// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"time"

	oauthelia2 "authelia.com/provider/oauth2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/oidc"
	"github.com/authelia/authelia/v4/internal/random"
	"github.com/authelia/authelia/v4/internal/session"
)

// authelia-plus: OpenID Connect RP-Initiated Logout 1.0 and Back-Channel Logout 1.0.

// OAuth2EndSession handles the end session endpoint, as per OpenID Connect RP-Initiated Logout 1.0: a Relying Party
// sends the user agent here to log the user out of Authelia, and optionally to be sent back afterwards.
//
// The request is validated first; on failure nothing is logged out and no redirect happens, so an error can never
// bounce the user to an unregistered URI. When an 'id_token_hint' names a different user than the one logged in, the
// session is left alone: the hint is evidence the Relying Party wants that user's session ended, not this one. The
// End-User is not asked to confirm, matching the portal's /logout which doesn't either.
//
// https://openid.net/specs/openid-connect-rpinitiated-1_0.html
func OAuth2EndSession(ctx *middlewares.AutheliaCtx, rw http.ResponseWriter, r *http.Request) {
	requester, err := ctx.Providers.OpenIDConnect.NewRPInitiatedLogoutRequest(ctx, r)
	if err != nil {
		ctx.GetLogger().Errorf("End Session Request could not be processed: %s", oauthelia2.ErrorToDebugRFC6749Error(err))

		writeOAuth2EndSessionError(rw, err)

		return
	}

	clientID := ""

	if client := requester.GetClient(); client != nil {
		clientID = client.GetID()
	}

	if userSession, err := ctx.GetSession(); err != nil {
		ctx.GetLogger().WithError(err).Errorf("End Session Request from client with id '%s' could not load the user session", clientID)
	} else if !userSession.IsAnonymous() {
		if oauth2EndSessionHintMatches(ctx, requester, &userSession) {
			oauth2Logout(ctx, &userSession)

			if err = ctx.DestroySession(); err != nil {
				ctx.GetLogger().WithError(err).Errorf("End Session Request from client with id '%s' could not destroy the user session", clientID)
			}

			ctx.GetLogger().Debugf("End Session Request from client with id '%s' logged out user '%s'", clientID, userSession.Username)
		} else {
			ctx.GetLogger().Warnf("End Session Request from client with id '%s' has an 'id_token_hint' for a different user than '%s': the session was not ended", clientID, userSession.Username)
		}
	}

	var target *url.URL

	if target = requester.GetPostLogoutRedirectURI(); target != nil {
		if state := requester.GetState(); state != "" {
			query := target.Query()
			query.Set(oidc.FormParameterState, state)
			target.RawQuery = query.Encode()
		}
	} else if target, err = ctx.IssuerURL(); err != nil {
		ctx.GetLogger().WithError(err).Error("End Session Request could not determine the issuer to redirect to")

		writeOAuth2EndSessionError(rw, oidc.ErrEffectiveIssuer.WithWrap(err))

		return
	}

	http.Redirect(rw, r, target.String(), http.StatusFound)
}

// oauth2EndSessionHintMatches returns true when the request has no 'id_token_hint', or its subject belongs to the
// logged in user.
func oauth2EndSessionHintMatches(ctx *middlewares.AutheliaCtx, requester oauthelia2.RPInitiatedLogoutRequester, userSession *session.UserSession) bool {
	if requester.GetIDTokenHint() == "" {
		return true
	}

	subject, err := uuid.Parse(requester.GetSubject())
	if err != nil {
		return false
	}

	opaque, err := ctx.Providers.StorageProvider.LoadUserOpaqueIdentifier(ctx, subject)
	if err != nil || opaque == nil {
		return false
	}

	return opaque.Username == userSession.Username
}

func writeOAuth2EndSessionError(rw http.ResponseWriter, err error) {
	var rfc *oauthelia2.RFC6749Error

	if !errors.As(err, &rfc) {
		rfc = oauthelia2.ErrServerError
	}

	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	rw.WriteHeader(rfc.StatusCode())

	_ = json.NewEncoder(rw).Encode(map[string]string{"error": rfc.ErrorField, "error_description": rfc.GetDescription()})
}

// handleOAuth2AuthorizationBackChannelLogout gives the ID Token a 'sid' claim and records the client against the
// user session, so the client can be sent a Logout Token when the session ends. Clients without a
// 'backchannel_logout_uri' are left untouched: their ID Tokens carry no 'sid' and nothing is recorded.
func handleOAuth2AuthorizationBackChannelLogout(ctx *middlewares.AutheliaCtx, provider *session.Session, userSession *session.UserSession, client oidc.Client, s *oidc.Session) {
	if c, ok := client.(oauthelia2.BackChannelLogoutClient); !ok || c.GetBackChannelLogoutURI() == "" {
		return
	}

	changed := false

	if userSession.OpenIDConnect == nil {
		userSession.OpenIDConnect = &session.OpenIDConnectLogout{SessionID: ctx.Providers.Random.StringCustom(32, random.CharSetAlphaNumeric)}
		changed = true
	}

	s.Claims.SessionID = userSession.OpenIDConnect.SessionID

	if userSession.AddOpenIDConnectLogoutClient(client.GetID(), s.Subject) {
		changed = true
	}

	if !changed {
		return
	}

	// Not fatal: the user still gets their tokens, the client just won't hear about this session ending.
	if err := provider.SaveSession(ctx.RequestCtx, *userSession); err != nil {
		ctx.GetLogger().WithError(err).Errorf("Error occurred saving the OpenID Connect 1.0 logout state for client with id '%s' to the user session", client.GetID())
	}
}

// backChannelLogoutTimeout bounds how long Logout Token delivery may take in total. The library retries unreachable
// clients, and nothing else would stop a hung one.
const backChannelLogoutTimeout = 30 * time.Second

// goBackChannelLogout runs Logout Token delivery off the request goroutine. Replaced in tests.
var goBackChannelLogout = func(deliver func()) { go deliver() }

// oauth2Logout ends the user's OpenID Connect 1.0 sessions alongside their Authelia session: every token issued to
// the user is revoked, and each client given an ID Token in this session with a 'backchannel_logout_uri' is sent a
// Logout Token. It must run before the user session is destroyed. Failures are logged and never block the logout.
func oauth2Logout(ctx *middlewares.AutheliaCtx, userSession *session.UserSession) {
	if ctx.Providers.OpenIDConnect == nil || userSession.Username == "" {
		return
	}

	if err := ctx.Providers.StorageProvider.RevokeOAuth2SessionsByUsername(ctx, userSession.Username); err != nil {
		ctx.GetLogger().WithError(err).Errorf("Error occurred revoking the OpenID Connect 1.0 tokens of user '%s' during logout", userSession.Username)
	}

	if userSession.OpenIDConnect == nil || len(userSession.OpenIDConnect.Clients) == 0 {
		return
	}

	// A Logout Token carries one subject, and subjects differ between sectors, so clients are grouped by subject.
	var (
		subjects []string
		clients  = map[string][]oauthelia2.Client{}
	)

	for _, c := range userSession.OpenIDConnect.Clients {
		client, err := ctx.Providers.OpenIDConnect.GetClient(ctx, c.ClientID)
		if err != nil {
			ctx.GetLogger().WithError(err).Warnf("Back-Channel Logout skipped client with id '%s' as it could not be loaded", c.ClientID)
			continue
		}

		if _, ok := clients[c.Subject]; !ok {
			subjects = append(subjects, c.Subject)
		}

		clients[c.Subject] = append(clients[c.Subject], client)
	}

	if len(subjects) == 0 {
		return
	}

	dctx, cancel, err := oidc.NewDetachedContext(ctx, backChannelLogoutTimeout)
	if err != nil {
		ctx.GetLogger().WithError(err).Errorf("Back-Channel Logout for user '%s' could not be performed as the issuer could not be determined", userSession.Username)
		return
	}

	var (
		provider = ctx.Providers.OpenIDConnect
		logger   = ctx.GetLogger()
		sid      = userSession.OpenIDConnect.SessionID
		username = userSession.Username
	)

	goBackChannelLogout(func() {
		defer cancel()

		for _, subject := range subjects {
			results, err := provider.SendBackChannelLogout(dctx, oauthelia2.NewBackChannelLogoutRequest(subject, sid, clients[subject]))
			if err != nil {
				logger.WithError(err).Errorf("Back-Channel Logout for user '%s' could not be performed", username)
				continue
			}

			logBackChannelLogoutResults(logger, username, results)
		}
	})
}

func logBackChannelLogoutResults(logger *logrus.Entry, username string, results []oauthelia2.BackChannelLogoutResult) {
	for _, result := range results {
		switch {
		case result.Skipped:
			logger.Debugf("Back-Channel Logout for user '%s' skipped client with id '%s': %s", username, result.ClientID, result.Reason)
		case result.Err != nil:
			logger.WithError(result.Err).Warnf("Back-Channel Logout for user '%s' failed for client with id '%s' (status %d)", username, result.ClientID, result.Status)
		default:
			logger.Debugf("Back-Channel Logout for user '%s' was delivered to client with id '%s'", username, result.ClientID)
		}
	}
}
