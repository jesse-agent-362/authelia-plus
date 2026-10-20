// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	oauthelia2 "authelia.com/provider/oauth2"

	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/oidc"
	"github.com/authelia/authelia/v4/internal/random"
	"github.com/authelia/authelia/v4/internal/session"
)

// authelia-plus: OpenID Connect RP-Initiated Logout 1.0 and Back-Channel Logout 1.0.

// OAuth2EndSession handles the end session endpoint, as per OpenID Connect RP-Initiated Logout 1.0: a Relying Party
// sends the user agent here to log the user out of Authelia, and optionally to be sent back afterwards.
//
// The session is only ended when the request carries a valid 'id_token_hint' for the logged in user. The specification
// expects the End-User to be asked to confirm a logout without one, as anyone can link a user agent here; until there
// is a confirmation page such requests log nobody out. The user agent is sent to the requested
// 'post_logout_redirect_uri' only when it validates against the client's registered URIs and the user is known to be
// logged out, so the Relying Party never shows a logout that did not happen. Every other case goes to the portal,
// including invalid requests.
//
// https://openid.net/specs/openid-connect-rpinitiated-1_0.html
func OAuth2EndSession(ctx *middlewares.AutheliaCtx, rw http.ResponseWriter, r *http.Request) {
	requester, err := ctx.Providers.OpenIDConnect.NewRPInitiatedLogoutRequest(ctx, r)
	if err != nil {
		ctx.GetLogger().Errorf("End Session Request could not be processed: %s", oauthelia2.ErrorToDebugRFC6749Error(err))

		oauth2EndSessionRedirectPortal(ctx, rw, r)

		return
	}

	clientID := ""

	if client := requester.GetClient(); client != nil {
		clientID = client.GetID()
	}

	loggedIn := false

	if userSession, err := ctx.GetSession(); err != nil {
		ctx.GetLogger().WithError(err).Errorf("End Session Request from client with id '%s' could not load the user session", clientID)

		loggedIn = true
	} else if !userSession.IsAnonymous() {
		switch {
		case requester.GetIDTokenHint() == "":
			ctx.GetLogger().Infof("End Session Request from client with id '%s' has no 'id_token_hint': the session of user '%s' was not ended", clientID, userSession.Username)

			loggedIn = true
		case !oauth2EndSessionHintMatches(ctx, requester, &userSession):
			ctx.GetLogger().Warnf("End Session Request from client with id '%s' has an 'id_token_hint' for a different user than '%s': the session was not ended", clientID, userSession.Username)

			loggedIn = true
		default:
			oauth2Logout(ctx, &userSession)

			if err = ctx.DestroySession(); err != nil {
				ctx.GetLogger().WithError(err).Errorf("End Session Request from client with id '%s' could not destroy the user session", clientID)

				loggedIn = true
			}

			ctx.GetLogger().Debugf("End Session Request from client with id '%s' logged out user '%s'", clientID, userSession.Username)
		}
	}

	target := requester.GetPostLogoutRedirectURI()
	if target == nil || loggedIn {
		oauth2EndSessionRedirectPortal(ctx, rw, r)

		return
	}

	if state := requester.GetState(); state != "" {
		query := target.Query()
		query.Set(oidc.FormParameterState, state)
		target.RawQuery = query.Encode()
	}

	http.Redirect(rw, r, target.String(), http.StatusFound) //nolint:gosec // Matched exactly against the client's registered post logout redirect URIs.
}

// oauth2EndSessionHintMatches returns true when the subject of the request's validated 'id_token_hint' belongs to the
// logged in user.
func oauth2EndSessionHintMatches(ctx *middlewares.AutheliaCtx, requester oauthelia2.RPInitiatedLogoutRequester, userSession *session.UserSession) bool {
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

func oauth2EndSessionRedirectPortal(ctx *middlewares.AutheliaCtx, rw http.ResponseWriter, r *http.Request) {
	portal, err := ctx.IssuerURL()
	if err != nil {
		ctx.GetLogger().WithError(err).Error("End Session Request could not determine the portal to redirect to")

		http.Error(rw, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)

		return
	}

	http.Redirect(rw, r, portal.String(), http.StatusFound)
}

// handleOAuth2AuthorizationLogoutState records the authorization request against the user session, so its tokens can
// be revoked when the session ends. Clients with a 'backchannel_logout_uri' are also recorded so they can be sent a
// Logout Token, and their ID Tokens get a 'sid' claim. Other clients' ID Tokens are left untouched.
//
// The session is reloaded rather than taken from the caller: earlier steps of the request (consent) may have saved a
// newer copy, which saving the caller's copy would undo.
func handleOAuth2AuthorizationLogoutState(ctx *middlewares.AutheliaCtx, provider *session.Session, client oidc.Client, requester oauthelia2.AuthorizeRequester, s *oidc.Session) {
	userSession, err := provider.GetSession(ctx.RequestCtx)
	if err != nil {
		ctx.GetLogger().WithError(err).Errorf("Error occurred loading the user session to record the OpenID Connect 1.0 logout state for client with id '%s'", client.GetID())
		return
	}

	if userSession.OpenIDConnect == nil {
		userSession.OpenIDConnect = &session.OpenIDConnectLogout{}
	}

	userSession.OpenIDConnect.RequestIDs = append(userSession.OpenIDConnect.RequestIDs, requester.GetID())

	if c, ok := client.(oauthelia2.BackChannelLogoutClient); ok && c.GetBackChannelLogoutURI() != "" {
		if userSession.OpenIDConnect.SessionID == "" {
			userSession.OpenIDConnect.SessionID = ctx.Providers.Random.StringCustom(32, random.CharSetAlphaNumeric)
		}

		s.Claims.SessionID = userSession.OpenIDConnect.SessionID

		userSession.AddOpenIDConnectLogoutClient(client.GetID(), s.Subject)
	}

	// Not fatal: the user still gets their tokens, they just won't be revoked or announced when this session ends.
	if err = provider.SaveSession(ctx.RequestCtx, userSession); err != nil {
		ctx.GetLogger().WithError(err).Errorf("Error occurred saving the OpenID Connect 1.0 logout state for client with id '%s' to the user session", client.GetID())
	}
}

// backChannelLogoutTimeout bounds how long Logout Token delivery may take in total. The library retries unreachable
// clients, and nothing else would stop a hung one.
const backChannelLogoutTimeout = 30 * time.Second

// goBackChannelLogout runs Logout Token delivery off the request goroutine. Replaced in tests.
var goBackChannelLogout = func(deliver func()) { go deliver() }

// oauth2Logout ends the OpenID Connect 1.0 grants of this user session alongside the session itself: every token
// descended from an authorization made in this session is revoked, and each client given an ID Token in this session
// with a 'backchannel_logout_uri' is sent a Logout Token. Grants from the user's other sessions, including
// 'offline_access' ones, are left alone. It must run before the user session is destroyed. Failures are logged and
// never block the logout.
func oauth2Logout(ctx *middlewares.AutheliaCtx, userSession *session.UserSession) {
	if ctx.Providers.OpenIDConnect == nil || userSession.Username == "" || userSession.OpenIDConnect == nil {
		return
	}

	if err := ctx.Providers.StorageProvider.RevokeOAuth2SessionsByRequestIDs(ctx, userSession.OpenIDConnect.RequestIDs); err != nil {
		ctx.GetLogger().WithError(err).Errorf("Error occurred revoking the OpenID Connect 1.0 tokens of user '%s' during logout", userSession.Username)
	}

	if len(userSession.OpenIDConnect.Clients) == 0 {
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

		// Each subject is delivered concurrently so a hung client in one group can't spend the others' budget.
		var wg sync.WaitGroup

		for _, subject := range subjects {
			wg.Go(func() {
				results, err := provider.SendBackChannelLogout(dctx, oauthelia2.NewBackChannelLogoutRequest(subject, sid, clients[subject]))
				if err != nil {
					logger.WithError(err).Errorf("Back-Channel Logout for user '%s' could not be performed", username)
					return
				}

				logBackChannelLogoutResults(logger, username, results)
			})
		}

		wg.Wait()
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
