// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"context"
	"errors"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/model"
	"github.com/authelia/authelia/v4/internal/oidc"
	plussessions "github.com/authelia/authelia/v4/internal/plus/sessions"
	"github.com/authelia/authelia/v4/internal/session"
)

// authelia-plus: listing and revoking the user's own sessions.

var errPlusSessionsUnavailable = errors.New("the user session records are not available")

// PlusSessionResponse is one session in the session list. Only these fields ever leave the server: the record's
// OpenID Connect 1.0 state stays inside.
type PlusSessionResponse struct {
	ID         uuid.UUID `json:"id"`
	CreatedAt  time.Time `json:"created_at"`
	LastActive time.Time `json:"last_active"`
	ExpiresAt  time.Time `json:"expires_at"`

	// ReportedIP is the client IP as Authelia saw it when the session was created; behind a proxy it's whatever the
	// proxy reported. It is for display only.
	ReportedIP string `json:"reported_ip"`
	UserAgent  string `json:"user_agent"`

	// Current is true for the session making the request.
	Current bool `json:"current"`
}

// PlusSessionsGET lists the active sessions of the logged in user.
func PlusSessionsGET(ctx *middlewares.AutheliaCtx) {
	userSession, ok := plusSessionsUserSession(ctx)
	if !ok {
		return
	}

	records, err := ctx.Providers.PlusSessions.List(ctx, userSession.Username)
	if err != nil {
		ctx.Logger.WithError(err).Errorf("Error occurred listing the sessions of user '%s'", userSession.Username)

		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetJSONError(messageOperationFailed)

		return
	}

	sessions := make([]PlusSessionResponse, 0, len(records))

	for _, record := range records {
		sessions = append(sessions, PlusSessionResponse{
			ID:         record.ID,
			CreatedAt:  record.CreatedAt.UTC(),
			LastActive: record.LastActive.UTC(),
			ExpiresAt:  record.ExpiresAt.UTC(),
			ReportedIP: record.IP,
			UserAgent:  record.UserAgent,
			Current:    record.ID == userSession.PlusID,
		})
	}

	if err = ctx.SetJSONBody(sessions); err != nil {
		ctx.Logger.WithError(err).Errorf("Error occurred encoding the sessions of user '%s'", userSession.Username)
	}
}

// PlusSessionDELETE revokes one of the logged in user's sessions. A session which doesn't exist and one which belongs
// to someone else get the same 404, so the endpoint can't be used to probe for IDs.
func PlusSessionDELETE(ctx *middlewares.AutheliaCtx) {
	userSession, ok := plusSessionsUserSession(ctx)
	if !ok {
		return
	}

	raw, _ := ctx.UserValue("sessionID").(string)

	id, err := uuid.Parse(raw)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusNotFound)
		ctx.SetJSONError(messageOperationFailed)

		return
	}

	if ok, err = ctx.Providers.PlusSessions.Revoke(ctx, id, userSession.Username); err != nil {
		ctx.Logger.WithError(err).Errorf("Error occurred revoking session '%s' of user '%s'", id, userSession.Username)

		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetJSONError(messageOperationFailed)

		return
	}

	if !ok {
		ctx.SetStatusCode(fasthttp.StatusNotFound)
		ctx.SetJSONError(messageOperationFailed)

		return
	}

	ctx.Logger.WithFields(map[string]any{"username": userSession.Username, "session": id.String(), "current": id == userSession.PlusID}).Info("User revoked a session")

	ctx.ReplyOK()
}

func plusSessionsUserSession(ctx *middlewares.AutheliaCtx) (userSession session.UserSession, ok bool) {
	var err error

	if ctx.Providers.PlusSessions == nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetJSONError(messageOperationFailed)

		return userSession, false
	}

	if userSession, err = ctx.GetSession(); err != nil || userSession.IsAnonymous() {
		ctx.SetStatusCode(fasthttp.StatusForbidden)
		ctx.SetJSONError(messageOperationFailed)

		return userSession, false
	}

	return userSession, true
}

// plusSessionsCreate records the session of an authentication which is about to succeed, and sets the record's ID on
// it. It must run before the session is marked authenticated, and the authentication must fail if it returns an error:
// a session without a record could never be revoked. A re-authentication replaces the session's previous record.
func plusSessionsCreate(ctx *middlewares.AutheliaCtx, config schema.SessionCookie, userSession *session.UserSession, username string, keepMeLoggedIn bool) (err error) {
	if ctx.Providers.PlusSessions == nil {
		return errPlusSessionsUnavailable
	}

	issuer := ""

	if userSession.OpenIDConnect != nil && len(userSession.OpenIDConnect.Clients) != 0 {
		var u *url.URL

		if u, err = ctx.IssuerURL(); err != nil {
			return err
		}

		issuer = u.String()
	}

	var id uuid.UUID

	if id, err = ctx.Providers.PlusSessions.Create(ctx, username, ctx.RemoteIP().String(), string(ctx.UserAgent()), keepMeLoggedIn, config, issuer, userSession.PlusID, userSession.OpenIDConnect); err != nil {
		return err
	}

	userSession.PlusID = id

	return nil
}

// plusSessionsRecordOpenIDConnect mirrors the session's OpenID Connect 1.0 logout state onto its record, so a revoke
// can revoke the grants without the session. The authorization must fail if it returns an error. Sessions from before
// the records existed have none to record onto.
func plusSessionsRecordOpenIDConnect(ctx *middlewares.AutheliaCtx, userSession *session.UserSession) (err error) {
	if userSession.PlusID == uuid.Nil || userSession.OpenIDConnect == nil {
		return nil
	}

	if ctx.Providers.PlusSessions == nil {
		return errPlusSessionsUnavailable
	}

	var issuer *url.URL

	if issuer, err = ctx.IssuerURL(); err != nil {
		return err
	}

	return ctx.Providers.PlusSessions.RecordOpenIDConnect(ctx, userSession.PlusID, issuer.String(), userSession.OpenIDConnect)
}

// NewPlusSessionsProcessor returns the side effects of a revoked session: its OpenID Connect 1.0 grants are revoked
// and its Back-Channel Logout clients are sent a Logout Token, as on logout.
func NewPlusSessionsProcessor(providers *middlewares.Providers, config *schema.Configuration, logger *logrus.Entry) plussessions.Processor {
	return func(ctx context.Context, record *model.PlusUserSession, state *plussessions.OpenIDConnectState) (err error) {
		if providers.OpenIDConnect == nil {
			return nil
		}

		if err = providers.StorageProvider.RevokeOAuth2SessionsByRequestIDs(ctx, state.RequestIDs); err != nil {
			return err
		}

		if len(state.Clients) == 0 {
			return nil
		}

		clients := make([]session.OpenIDConnectLogoutClient, 0, len(state.Clients))

		for _, c := range state.Clients {
			clients = append(clients, session.OpenIDConnectLogoutClient{ClientID: c.ClientID, Subject: c.Subject})
		}

		oauth2BackChannelLogout(ctx, providers.OpenIDConnect, logger, func() (oidc.Context, context.CancelFunc, error) {
			issuer, err := url.Parse(state.Issuer)
			if err != nil || state.Issuer == "" {
				return nil, nil, errors.New("the issuer is missing or invalid")
			}

			dctx, cancel := oidc.NewDetachedContextFromProviders(issuer, oidc.DetachedContextProviders{
				Clock:    providers.Clock,
				Random:   providers.Random,
				Config:   config,
				Storage:  providers.StorageProvider,
				Users:    providers.UserProvider,
				Resolver: providers.UserAttributeResolver,
			}, backChannelLogoutTimeout)

			return dctx, cancel, nil
		}, record.Username, state.SessionID, clients)

		return nil
	}
}
