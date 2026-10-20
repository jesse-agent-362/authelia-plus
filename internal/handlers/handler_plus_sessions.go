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
	"github.com/authelia/authelia/v4/internal/storage"
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

	var id uuid.UUID

	if id, err = ctx.Providers.PlusSessions.Create(ctx, username, ctx.RemoteIP().String(), string(ctx.UserAgent()), keepMeLoggedIn, config, userSession.PlusID, userSession.Username); err != nil {
		return err
	}

	userSession.PlusID = id

	return nil
}

// plusSessionsRecordGrant adds an authorization request made in the session to the session's record, so revoking the
// session revokes the request's tokens. The authorization must fail if it returns an error.
func plusSessionsRecordGrant(ctx *middlewares.AutheliaCtx, userSession *session.UserSession, grant model.PlusUserSessionGrant) (err error) {
	if ctx.Providers.PlusSessions == nil {
		return errPlusSessionsUnavailable
	}

	if userSession.PlusID == uuid.Nil {
		return plussessions.ErrRecordUnavailable
	}

	grant.SessionID = userSession.PlusID

	return ctx.Providers.PlusSessions.RecordGrant(ctx, grant)
}

// plusSessionsRevokeGrants revokes every token descended from the grants, and sends a Logout Token to each of their
// Back-Channel Logout clients. Each group of clients is sent the 'sid' and issuer its ID Tokens were issued with;
// newContext returns the Context the delivery runs in for an issuer.
func plusSessionsRevokeGrants(ctx context.Context, provider *oidc.OpenIDConnectProvider, store storage.Provider, logger *logrus.Entry, newContext func(issuer string) (oidc.Context, context.CancelFunc, error), username string, grants []model.PlusUserSessionGrant) (err error) {
	type group struct{ issuer, sid string }

	var (
		requestIDs = make([]string, 0, len(grants))
		groups     []group
		clients    = map[group][]session.OpenIDConnectLogoutClient{}
		seen       = map[session.OpenIDConnectLogoutClient]bool{}
	)

	for _, grant := range grants {
		if grant.RequestID != "" {
			requestIDs = append(requestIDs, grant.RequestID)
		}

		if grant.ClientID == "" {
			continue
		}

		c := session.OpenIDConnectLogoutClient{ClientID: grant.ClientID, Subject: grant.Subject}
		g := group{issuer: grant.Issuer, sid: grant.SID}

		if seen[c] {
			continue
		}

		seen[c] = true

		if _, ok := clients[g]; !ok {
			groups = append(groups, g)
		}

		clients[g] = append(clients[g], c)
	}

	// The Logout Tokens are sent even if revoking the tokens failed, so the clients end their sessions either way.
	err = store.RevokeOAuth2SessionsByRequestIDs(ctx, requestIDs)

	for _, g := range groups {
		oauth2BackChannelLogout(ctx, provider, logger, func() (oidc.Context, context.CancelFunc, error) {
			return newContext(g.issuer)
		}, username, g.sid, clients[g])
	}

	return err
}

// NewPlusSessionsProcessor returns the side effects of a revoked session: its OpenID Connect 1.0 grants are revoked
// and its Back-Channel Logout clients are sent a Logout Token, as on logout.
func NewPlusSessionsProcessor(providers *middlewares.Providers, config *schema.Configuration, logger *logrus.Entry) plussessions.Processor {
	return func(ctx context.Context, record *model.PlusUserSession, grants []model.PlusUserSessionGrant) (err error) {
		if providers.OpenIDConnect == nil {
			return nil
		}

		return plusSessionsRevokeGrants(ctx, providers.OpenIDConnect, providers.StorageProvider, logger, func(issuer string) (oidc.Context, context.CancelFunc, error) {
			u, err := url.Parse(issuer)
			if err != nil || issuer == "" {
				return nil, nil, errors.New("the issuer is missing or invalid")
			}

			dctx, cancel := oidc.NewDetachedContextFromProviders(u, oidc.DetachedContextProviders{
				Clock:    providers.Clock,
				Random:   providers.Random,
				Config:   config,
				Storage:  providers.StorageProvider,
				Users:    providers.UserProvider,
				Resolver: providers.UserAttributeResolver,
			}, backChannelLogoutTimeout)

			return dctx, cancel, nil
		}, record.Username, grants)
	}
}
