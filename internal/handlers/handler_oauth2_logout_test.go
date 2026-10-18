// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
	"go.uber.org/mock/gomock"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/mocks"
	"github.com/authelia/authelia/v4/internal/oidc"
)

// authelia-plus: tests for OpenID Connect RP-Initiated Logout 1.0 and Back-Channel Logout 1.0.

const (
	testOIDCEndSessionEndpoint     = "https://login.example.com:8080/api/oidc/end-session"
	testOIDCPostLogoutRedirectURI  = "https://app.example.com/logged-out"
	testOIDCBackChannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

	testOIDCFormParameterIDTokenHint           = "id_token_hint"
	testOIDCFormParameterPostLogoutRedirectURI = "post_logout_redirect_uri"
)

// testBackChannelLogoutReceiver is a Relying Party's back-channel logout endpoint which records the Logout Tokens it
// receives.
type testBackChannelLogoutReceiver struct {
	*httptest.Server

	mu     sync.Mutex
	tokens []string
}

func newTestBackChannelLogoutReceiver(t *testing.T) (receiver *testBackChannelLogoutReceiver) {
	t.Helper()

	receiver = &testBackChannelLogoutReceiver{}

	receiver.Server = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			rw.WriteHeader(http.StatusBadRequest)
			return
		}

		receiver.mu.Lock()
		receiver.tokens = append(receiver.tokens, r.PostForm.Get("logout_token"))
		receiver.mu.Unlock()

		rw.WriteHeader(http.StatusOK)
	}))

	t.Cleanup(receiver.Close)

	return receiver
}

func (r *testBackChannelLogoutReceiver) Tokens() []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]string(nil), r.tokens...)
}

// setupTestOIDCBackChannelLogoutInline makes Logout Token delivery synchronous so tests can assert on it.
func setupTestOIDCBackChannelLogoutInline(t *testing.T) {
	t.Helper()

	original := goBackChannelLogout
	goBackChannelLogout = func(deliver func()) { deliver() }

	t.Cleanup(func() { goBackChannelLogout = original })
}

func newTestOIDCBackChannelLogoutClient(t *testing.T, uri string) schema.IdentityProvidersOpenIDConnectClient {
	t.Helper()

	client := newTestOIDCAuthorizationCodeClient(t)
	client.ConsentMode = "implicit"
	client.BackChannelLogoutURI = uri
	client.PostLogoutRedirectURIs = []string{testOIDCPostLogoutRedirectURI}

	return client
}

// expectTestOIDCRevokeSession expects the grants recorded in the current user session, and only those, to be revoked.
func expectTestOIDCRevokeSession(t *testing.T, mock *mocks.MockAutheliaCtx) *gomock.Call {
	t.Helper()

	userSession, err := mock.Ctx.GetSession()

	require.NoError(t, err)
	require.NotNil(t, userSession.OpenIDConnect)
	require.NotEmpty(t, userSession.OpenIDConnect.RequestIDs)

	return mock.StorageMock.EXPECT().RevokeOAuth2SessionsByRequestIDs(gomock.Any(), userSession.OpenIDConnect.RequestIDs)
}

// mustGetTestOIDCIDToken runs the authorization code flow and returns the ID Token.
func mustGetTestOIDCIDToken(t *testing.T, mock *mocks.MockAutheliaCtx) (idToken string) {
	t.Helper()

	code := mustGetTestOIDCAuthorizationCode(t, mock, newTestOIDCAuthorizationValues())

	rw, r := newTestOAuth2Request(t, fasthttp.MethodPost, testOIDCTokenEndpoint, url.Values{
		testOIDCFormParameterGrantType:    []string{oidc.GrantTypeAuthorizationCode},
		oidc.FormParameterClientID:        []string{testOIDCAuthorizationCodeID},
		testOIDCFormParameterClientSecret: []string{testOIDCClientSecretValue},
		testOIDCFormParameterCode:         []string{code},
		oidc.FormParameterRedirectURI:     []string{testOIDCRedirectURI},
	})

	OAuth2TokenPOST(mock.Ctx, rw, r)

	require.Equal(t, http.StatusOK, rw.Code)

	idToken, ok := getTestOAuth2ErrorResponse(t, rw)["id_token"].(string)

	require.True(t, ok)

	return idToken
}

// mustDecodeTestJWT returns the unverified header and claims of a JWT.
func mustDecodeTestJWT(t *testing.T, token string) (header, claims map[string]any) {
	t.Helper()

	parts := strings.Split(token, ".")

	require.Len(t, parts, 3)

	for i, target := range []*map[string]any{&header, &claims} {
		raw, err := base64.RawURLEncoding.DecodeString(parts[i])

		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(raw, target))
	}

	return header, claims
}

func TestOAuth2AuthorizationBackChannelLogout(t *testing.T) {
	t.Run("ShouldNotIssueSessionIDToClientsWithoutBackChannelLogoutURI", func(t *testing.T) {
		mock := mocks.NewMockAutheliaCtxWithUserSession(t, newTestOIDCUserSession(1))
		defer mock.Close()

		client := newTestOIDCAuthorizationCodeClient(t)
		client.ConsentMode = "implicit"

		setupTestOIDCAuthorizationCodeFlow(t, mock, client)

		_, claims := mustDecodeTestJWT(t, mustGetTestOIDCIDToken(t, mock))

		assert.NotContains(t, claims, oidc.ClaimSessionID)

		userSession, err := mock.Ctx.GetSession()

		require.NoError(t, err)
		require.NotNil(t, userSession.OpenIDConnect)
		assert.Len(t, userSession.OpenIDConnect.RequestIDs, 1)
		assert.Empty(t, userSession.OpenIDConnect.SessionID)
		assert.Empty(t, userSession.OpenIDConnect.Clients)
	})

	t.Run("ShouldIssueSessionIDAndRecordClient", func(t *testing.T) {
		mock := mocks.NewMockAutheliaCtxWithUserSession(t, newTestOIDCUserSession(1))
		defer mock.Close()

		setupTestOIDCAuthorizationCodeFlow(t, mock, newTestOIDCBackChannelLogoutClient(t, "https://app.example.com/backchannel-logout"))

		_, claims := mustDecodeTestJWT(t, mustGetTestOIDCIDToken(t, mock))

		userSession, err := mock.Ctx.GetSession()

		require.NoError(t, err)
		require.NotNil(t, userSession.OpenIDConnect)
		assert.Len(t, userSession.OpenIDConnect.SessionID, 32)
		assert.Equal(t, userSession.OpenIDConnect.SessionID, claims[oidc.ClaimSessionID])

		subject := mustGetTestOIDCSubject(t, mock, testOIDCAuthorizationCodeID)

		require.Len(t, userSession.OpenIDConnect.Clients, 1)
		assert.Equal(t, testOIDCAuthorizationCodeID, userSession.OpenIDConnect.Clients[0].ClientID)
		assert.Equal(t, subject.String(), userSession.OpenIDConnect.Clients[0].Subject)
		assert.Equal(t, subject.String(), claims[oidc.ClaimSubject])
	})

	t.Run("ShouldReuseSessionIDAcrossAuthorizations", func(t *testing.T) {
		mock := mocks.NewMockAutheliaCtxWithUserSession(t, newTestOIDCUserSession(1))
		defer mock.Close()

		setupTestOIDCAuthorizationCodeFlow(t, mock, newTestOIDCBackChannelLogoutClient(t, "https://app.example.com/backchannel-logout"))

		_, first := mustDecodeTestJWT(t, mustGetTestOIDCIDToken(t, mock))
		_, second := mustDecodeTestJWT(t, mustGetTestOIDCIDToken(t, mock))

		assert.Equal(t, first[oidc.ClaimSessionID], second[oidc.ClaimSessionID])

		userSession, err := mock.Ctx.GetSession()

		require.NoError(t, err)
		require.NotNil(t, userSession.OpenIDConnect)
		assert.Len(t, userSession.OpenIDConnect.RequestIDs, 2)
		assert.Len(t, userSession.OpenIDConnect.Clients, 1)
	})
}

func TestOAuth2Logout(t *testing.T) {
	t.Run("ShouldRevokeTokensAndSendLogoutToken", func(t *testing.T) {
		setupTestOIDCBackChannelLogoutInline(t)

		receiver := newTestBackChannelLogoutReceiver(t)

		mock := mocks.NewMockAutheliaCtxWithUserSession(t, newTestOIDCUserSession(1))
		defer mock.Close()

		setupTestOIDCAuthorizationCodeFlow(t, mock, newTestOIDCBackChannelLogoutClient(t, receiver.URL))

		_, idClaims := mustDecodeTestJWT(t, mustGetTestOIDCIDToken(t, mock))

		expectTestOIDCRevokeSession(t, mock).Return(nil)

		userSession, err := mock.Ctx.GetSession()

		require.NoError(t, err)

		oauth2Logout(mock.Ctx, &userSession)

		tokens := receiver.Tokens()

		require.Len(t, tokens, 1)

		header, claims := mustDecodeTestJWT(t, tokens[0])

		assert.Equal(t, "logout+jwt", header["typ"])
		assert.Equal(t, idClaims[oidc.ClaimIssuer], claims[oidc.ClaimIssuer])
		assert.Equal(t, idClaims[oidc.ClaimSubject], claims[oidc.ClaimSubject])
		assert.Equal(t, idClaims[oidc.ClaimSessionID], claims[oidc.ClaimSessionID])
		assert.Contains(t, claims[oidc.ClaimAudience], testOIDCAuthorizationCodeID)
		assert.NotContains(t, claims, "nonce")
		assert.NotEmpty(t, claims["jti"])

		events, ok := claims["events"].(map[string]any)

		require.True(t, ok)
		assert.Contains(t, events, testOIDCBackChannelLogoutEvent)
	})

	t.Run("ShouldSendLogoutTokenWhenRevocationFails", func(t *testing.T) {
		setupTestOIDCBackChannelLogoutInline(t)

		receiver := newTestBackChannelLogoutReceiver(t)

		mock := mocks.NewMockAutheliaCtxWithUserSession(t, newTestOIDCUserSession(1))
		defer mock.Close()

		setupTestOIDCAuthorizationCodeFlow(t, mock, newTestOIDCBackChannelLogoutClient(t, receiver.URL))

		mustGetTestOIDCIDToken(t, mock)

		expectTestOIDCRevokeSession(t, mock).Return(errors.New("database is locked"))

		userSession, err := mock.Ctx.GetSession()

		require.NoError(t, err)

		oauth2Logout(mock.Ctx, &userSession)

		assert.Len(t, receiver.Tokens(), 1)
		assert.Contains(t, mock.Hook.AllEntries()[0].Message, "Error occurred revoking the OpenID Connect 1.0 tokens of user 'john'")
	})

	t.Run("ShouldOnlyRevokeTokensWithoutBackChannelClients", func(t *testing.T) {
		setupTestOIDCBackChannelLogoutInline(t)

		mock := mocks.NewMockAutheliaCtxWithUserSession(t, newTestOIDCUserSession(1))
		defer mock.Close()

		client := newTestOIDCAuthorizationCodeClient(t)
		client.ConsentMode = "implicit"

		setupTestOIDCAuthorizationCodeFlow(t, mock, client)

		mustGetTestOIDCIDToken(t, mock)

		expectTestOIDCRevokeSession(t, mock).Return(nil)

		userSession, err := mock.Ctx.GetSession()

		require.NoError(t, err)

		oauth2Logout(mock.Ctx, &userSession)
	})

	t.Run("ShouldDoNothingWithoutAuthorizations", func(t *testing.T) {
		mock := mocks.NewMockAutheliaCtxWithUserSession(t, newTestOIDCUserSession(1))
		defer mock.Close()

		client := newTestOIDCAuthorizationCodeClient(t)
		client.ConsentMode = "implicit"

		setupTestOIDCAuthorizationCodeFlow(t, mock, client)

		userSession, err := mock.Ctx.GetSession()

		require.NoError(t, err)

		// No storage expectation is set, so any call fails the test.
		oauth2Logout(mock.Ctx, &userSession)
	})

	t.Run("ShouldDoNothingWithoutProvider", func(t *testing.T) {
		mock := mocks.NewMockAutheliaCtxWithUserSession(t, newTestOIDCUserSession(1))
		defer mock.Close()

		userSession, err := mock.Ctx.GetSession()

		require.NoError(t, err)

		// No storage expectation is set, so any call fails the test.
		oauth2Logout(mock.Ctx, &userSession)
	})
}

func TestLogoutPOSTOpenIDConnect(t *testing.T) {
	setupTestOIDCBackChannelLogoutInline(t)

	receiver := newTestBackChannelLogoutReceiver(t)

	mock := mocks.NewMockAutheliaCtxWithUserSession(t, newTestOIDCUserSession(1))
	defer mock.Close()

	setupTestOIDCAuthorizationCodeFlow(t, mock, newTestOIDCBackChannelLogoutClient(t, receiver.URL))

	mustGetTestOIDCIDToken(t, mock)

	expectTestOIDCRevokeSession(t, mock).Return(nil)

	mock.Ctx.Request.SetBodyString("{}")

	LogoutPOST(mock.Ctx)

	assert.Equal(t, fasthttp.StatusOK, mock.Ctx.Response.StatusCode())
	assert.Len(t, receiver.Tokens(), 1)

	userSession, err := mock.Ctx.GetSession()

	require.NoError(t, err)
	assert.True(t, userSession.IsAnonymous())
}

func TestOAuth2EndSession(t *testing.T) {
	setup := func(t *testing.T) (mock *mocks.MockAutheliaCtx) {
		t.Helper()

		setupTestOIDCBackChannelLogoutInline(t)

		mock = mocks.NewMockAutheliaCtxWithUserSession(t, newTestOIDCUserSession(1))

		client := newTestOIDCAuthorizationCodeClient(t)
		client.ConsentMode = "implicit"
		client.PostLogoutRedirectURIs = []string{testOIDCPostLogoutRedirectURI}

		setupTestOIDCAuthorizationCodeFlow(t, mock, client)

		return mock
	}

	assertLoggedIn := func(t *testing.T, mock *mocks.MockAutheliaCtx, expected bool) {
		t.Helper()

		userSession, err := mock.Ctx.GetSession()

		require.NoError(t, err)
		assert.Equal(t, expected, !userSession.IsAnonymous())
	}

	const testOIDCPortalURL = "https://login.example.com:8080"

	endSession := func(t *testing.T, mock *mocks.MockAutheliaCtx, method string, values url.Values) (code int, location string) {
		t.Helper()

		rw, r := newTestOAuth2Request(t, method, testOIDCEndSessionEndpoint, values)

		OAuth2EndSession(mock.Ctx, rw, r)

		return rw.Code, rw.Header().Get(fasthttp.HeaderLocation)
	}

	t.Run("ShouldLogoutWithMatchingIDTokenHint", func(t *testing.T) {
		mock := setup(t)
		defer mock.Close()

		hint := mustGetTestOIDCIDToken(t, mock)

		expectTestOIDCRevokeSession(t, mock).Return(nil)

		code, location := endSession(t, mock, fasthttp.MethodPost, url.Values{
			testOIDCFormParameterIDTokenHint:           []string{hint},
			testOIDCFormParameterPostLogoutRedirectURI: []string{testOIDCPostLogoutRedirectURI},
			oidc.FormParameterState:                    []string{"abc123"},
		})

		assert.Equal(t, http.StatusFound, code)
		assert.Equal(t, testOIDCPostLogoutRedirectURI+"?state=abc123", location)
		assertLoggedIn(t, mock, false)
	})

	t.Run("ShouldLogoutWithMatchingIDTokenHintAndNotifyBackChannel", func(t *testing.T) {
		setupTestOIDCBackChannelLogoutInline(t)

		receiver := newTestBackChannelLogoutReceiver(t)

		mock := mocks.NewMockAutheliaCtxWithUserSession(t, newTestOIDCUserSession(1))
		defer mock.Close()

		setupTestOIDCAuthorizationCodeFlow(t, mock, newTestOIDCBackChannelLogoutClient(t, receiver.URL))

		hint := mustGetTestOIDCIDToken(t, mock)

		expectTestOIDCRevokeSession(t, mock).Return(nil)

		code, location := endSession(t, mock, fasthttp.MethodGet, url.Values{testOIDCFormParameterIDTokenHint: []string{hint}})

		assert.Equal(t, http.StatusFound, code)
		assert.Equal(t, testOIDCPortalURL, location)
		assert.Len(t, receiver.Tokens(), 1)
		assertLoggedIn(t, mock, false)
	})

	t.Run("ShouldNotLogoutCrossSiteLinkWithoutParameters", func(t *testing.T) {
		mock := setup(t)
		defer mock.Close()

		// No revocation expectation is set, so revoking fails the test.
		code, location := endSession(t, mock, fasthttp.MethodGet, nil)

		assert.Equal(t, http.StatusFound, code)
		assert.Equal(t, testOIDCPortalURL, location)
		assertLoggedIn(t, mock, true)
	})

	t.Run("ShouldNotLogoutWithoutIDTokenHintButRedirectWithState", func(t *testing.T) {
		mock := setup(t)
		defer mock.Close()

		code, location := endSession(t, mock, fasthttp.MethodGet, url.Values{
			oidc.FormParameterClientID:                 []string{testOIDCAuthorizationCodeID},
			testOIDCFormParameterPostLogoutRedirectURI: []string{testOIDCPostLogoutRedirectURI},
			oidc.FormParameterState:                    []string{"abc123"},
		})

		assert.Equal(t, http.StatusFound, code)
		assert.Equal(t, testOIDCPostLogoutRedirectURI+"?state=abc123", location)
		assertLoggedIn(t, mock, true)
	})

	t.Run("ShouldNotLogoutWithIDTokenHintForAnotherUser", func(t *testing.T) {
		mock := setup(t)
		defer mock.Close()

		hint := mustGetTestOIDCIDToken(t, mock)

		other := newTestOIDCUserSession(1)
		other.Username = "harry"

		require.NoError(t, mock.Ctx.SaveSession(other))

		code, location := endSession(t, mock, fasthttp.MethodGet, url.Values{
			testOIDCFormParameterIDTokenHint:           []string{hint},
			testOIDCFormParameterPostLogoutRedirectURI: []string{testOIDCPostLogoutRedirectURI},
		})

		assert.Equal(t, http.StatusFound, code)
		assert.Equal(t, testOIDCPostLogoutRedirectURI, location)
		assertLoggedIn(t, mock, true)
	})

	t.Run("ShouldNotLogoutWithForgedIDTokenHint", func(t *testing.T) {
		mock := setup(t)
		defer mock.Close()

		hint := mustGetTestOIDCIDToken(t, mock)
		parts := strings.Split(hint, ".")
		parts[2] = base64.RawURLEncoding.EncodeToString([]byte("not a signature"))

		code, location := endSession(t, mock, fasthttp.MethodGet, url.Values{
			testOIDCFormParameterIDTokenHint:           []string{strings.Join(parts, ".")},
			testOIDCFormParameterPostLogoutRedirectURI: []string{testOIDCPostLogoutRedirectURI},
		})

		assert.Equal(t, http.StatusFound, code)
		assert.Equal(t, testOIDCPortalURL, location)
		assertLoggedIn(t, mock, true)
	})

	t.Run("ShouldRedirectToPortalForInvalidRequests", func(t *testing.T) {
		testCases := []struct {
			name   string
			values url.Values
		}{
			{"UnregisteredPostLogoutRedirectURI", url.Values{
				oidc.FormParameterClientID:                 []string{testOIDCAuthorizationCodeID},
				testOIDCFormParameterPostLogoutRedirectURI: []string{"https://evil.example.com/"},
			}},
			{"PostLogoutRedirectURIWithoutClient", url.Values{
				testOIDCFormParameterPostLogoutRedirectURI: []string{testOIDCPostLogoutRedirectURI},
			}},
			{"UnknownClient", url.Values{
				oidc.FormParameterClientID:                 []string{"unknown"},
				testOIDCFormParameterPostLogoutRedirectURI: []string{testOIDCPostLogoutRedirectURI},
			}},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				mock := setup(t)
				defer mock.Close()

				code, location := endSession(t, mock, fasthttp.MethodGet, tc.values)

				assert.Equal(t, http.StatusFound, code)
				assert.Equal(t, testOIDCPortalURL, location)
				assertLoggedIn(t, mock, true)
			})
		}
	})

	t.Run("ShouldRedirectAnonymousUser", func(t *testing.T) {
		mock := setup(t)
		defer mock.Close()

		require.NoError(t, mock.Ctx.DestroySession())

		code, location := endSession(t, mock, fasthttp.MethodGet, url.Values{
			oidc.FormParameterClientID:                 []string{testOIDCAuthorizationCodeID},
			testOIDCFormParameterPostLogoutRedirectURI: []string{testOIDCPostLogoutRedirectURI},
		})

		assert.Equal(t, http.StatusFound, code)
		assert.Equal(t, testOIDCPostLogoutRedirectURI, location)
	})
}
