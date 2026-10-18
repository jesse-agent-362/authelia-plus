// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
	"go.uber.org/mock/gomock"

	"github.com/authelia/authelia/v4/internal/mocks"
	"github.com/authelia/authelia/v4/internal/oidc"
)

// authelia-plus: tests for OpenID Connect RP-Initiated Logout 1.0, and token revocation on logout.

const (
	testOIDCEndSessionEndpoint    = "https://login.example.com:8080/api/oidc/end-session"
	testOIDCPostLogoutRedirectURI = "https://app.example.com/logged-out"

	testOIDCFormParameterIDTokenHint           = "id_token_hint"
	testOIDCFormParameterPostLogoutRedirectURI = "post_logout_redirect_uri"
)

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

func TestOAuth2Logout(t *testing.T) {
	setup := func(t *testing.T) (mock *mocks.MockAutheliaCtx) {
		t.Helper()

		mock = mocks.NewMockAutheliaCtxWithUserSession(t, newTestOIDCUserSession(1))

		client := newTestOIDCAuthorizationCodeClient(t)
		client.ConsentMode = "implicit"

		setupTestOIDCAuthorizationCodeFlow(t, mock, client)

		mustGetTestOIDCIDToken(t, mock)

		return mock
	}

	t.Run("ShouldRevokeTokens", func(t *testing.T) {
		mock := setup(t)
		defer mock.Close()

		mock.StorageMock.EXPECT().RevokeOAuth2SessionsByUsername(gomock.Any(), testUsername).Return(nil)

		userSession, err := mock.Ctx.GetSession()

		require.NoError(t, err)

		oauth2Logout(mock.Ctx, &userSession)
	})

	t.Run("ShouldLogRevocationFailure", func(t *testing.T) {
		mock := setup(t)
		defer mock.Close()

		mock.StorageMock.EXPECT().RevokeOAuth2SessionsByUsername(gomock.Any(), testUsername).Return(errors.New("database is locked"))

		userSession, err := mock.Ctx.GetSession()

		require.NoError(t, err)

		oauth2Logout(mock.Ctx, &userSession)

		assert.Contains(t, mock.Hook.AllEntries()[0].Message, "Error occurred revoking the OpenID Connect 1.0 tokens of user 'john'")
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
	mock := mocks.NewMockAutheliaCtxWithUserSession(t, newTestOIDCUserSession(1))
	defer mock.Close()

	client := newTestOIDCAuthorizationCodeClient(t)
	client.ConsentMode = "implicit"

	setupTestOIDCAuthorizationCodeFlow(t, mock, client)

	mustGetTestOIDCIDToken(t, mock)

	mock.StorageMock.EXPECT().RevokeOAuth2SessionsByUsername(gomock.Any(), testUsername).Return(nil)

	mock.Ctx.Request.SetBodyString("{}")

	LogoutPOST(mock.Ctx)

	assert.Equal(t, fasthttp.StatusOK, mock.Ctx.Response.StatusCode())

	userSession, err := mock.Ctx.GetSession()

	require.NoError(t, err)
	assert.True(t, userSession.IsAnonymous())
}

func TestOAuth2EndSession(t *testing.T) {
	setup := func(t *testing.T) (mock *mocks.MockAutheliaCtx) {
		t.Helper()

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

	t.Run("ShouldLogoutAndRedirectWithState", func(t *testing.T) {
		mock := setup(t)
		defer mock.Close()

		mock.StorageMock.EXPECT().RevokeOAuth2SessionsByUsername(gomock.Any(), testUsername).Return(nil)

		rw, r := newTestOAuth2Request(t, fasthttp.MethodGet, testOIDCEndSessionEndpoint, url.Values{
			oidc.FormParameterClientID:                 []string{testOIDCAuthorizationCodeID},
			testOIDCFormParameterPostLogoutRedirectURI: []string{testOIDCPostLogoutRedirectURI},
			oidc.FormParameterState:                    []string{"abc123"},
		})

		OAuth2EndSession(mock.Ctx, rw, r)

		assert.Equal(t, http.StatusFound, rw.Code)
		assert.Equal(t, testOIDCPostLogoutRedirectURI+"?state=abc123", rw.Header().Get(fasthttp.HeaderLocation))
		assertLoggedIn(t, mock, false)
	})

	t.Run("ShouldLogoutWithMatchingIDTokenHint", func(t *testing.T) {
		mock := setup(t)
		defer mock.Close()

		hint := mustGetTestOIDCIDToken(t, mock)

		mock.StorageMock.EXPECT().RevokeOAuth2SessionsByUsername(gomock.Any(), testUsername).Return(nil)

		rw, r := newTestOAuth2Request(t, fasthttp.MethodPost, testOIDCEndSessionEndpoint, url.Values{
			testOIDCFormParameterIDTokenHint:           []string{hint},
			testOIDCFormParameterPostLogoutRedirectURI: []string{testOIDCPostLogoutRedirectURI},
		})

		OAuth2EndSession(mock.Ctx, rw, r)

		assert.Equal(t, http.StatusFound, rw.Code)
		assert.Equal(t, testOIDCPostLogoutRedirectURI, rw.Header().Get(fasthttp.HeaderLocation))
		assertLoggedIn(t, mock, false)
	})

	t.Run("ShouldNotLogoutWithIDTokenHintForAnotherUser", func(t *testing.T) {
		mock := setup(t)
		defer mock.Close()

		hint := mustGetTestOIDCIDToken(t, mock)

		other := newTestOIDCUserSession(1)
		other.Username = "harry"

		require.NoError(t, mock.Ctx.SaveSession(other))

		rw, r := newTestOAuth2Request(t, fasthttp.MethodGet, testOIDCEndSessionEndpoint, url.Values{
			testOIDCFormParameterIDTokenHint:           []string{hint},
			testOIDCFormParameterPostLogoutRedirectURI: []string{testOIDCPostLogoutRedirectURI},
		})

		OAuth2EndSession(mock.Ctx, rw, r)

		assert.Equal(t, http.StatusFound, rw.Code)
		assert.Equal(t, testOIDCPostLogoutRedirectURI, rw.Header().Get(fasthttp.HeaderLocation))
		assertLoggedIn(t, mock, true)
	})

	t.Run("ShouldRejectUnregisteredPostLogoutRedirectURI", func(t *testing.T) {
		mock := setup(t)
		defer mock.Close()

		rw, r := newTestOAuth2Request(t, fasthttp.MethodGet, testOIDCEndSessionEndpoint, url.Values{
			oidc.FormParameterClientID:                 []string{testOIDCAuthorizationCodeID},
			testOIDCFormParameterPostLogoutRedirectURI: []string{"https://evil.example.com/"},
		})

		OAuth2EndSession(mock.Ctx, rw, r)

		assert.Equal(t, http.StatusBadRequest, rw.Code)
		assert.Empty(t, rw.Header().Get(fasthttp.HeaderLocation))
		assert.Equal(t, "invalid_request", getTestOAuth2ErrorResponse(t, rw)["error"])
		assertLoggedIn(t, mock, true)
	})

	t.Run("ShouldRejectPostLogoutRedirectURIWithoutClient", func(t *testing.T) {
		mock := setup(t)
		defer mock.Close()

		rw, r := newTestOAuth2Request(t, fasthttp.MethodGet, testOIDCEndSessionEndpoint, url.Values{
			testOIDCFormParameterPostLogoutRedirectURI: []string{testOIDCPostLogoutRedirectURI},
		})

		OAuth2EndSession(mock.Ctx, rw, r)

		assert.Equal(t, http.StatusBadRequest, rw.Code)
		assert.Equal(t, "invalid_request", getTestOAuth2ErrorResponse(t, rw)["error"])
		assertLoggedIn(t, mock, true)
	})

	t.Run("ShouldRejectUnknownClient", func(t *testing.T) {
		mock := setup(t)
		defer mock.Close()

		rw, r := newTestOAuth2Request(t, fasthttp.MethodGet, testOIDCEndSessionEndpoint, url.Values{
			oidc.FormParameterClientID: []string{"unknown"},
		})

		OAuth2EndSession(mock.Ctx, rw, r)

		assert.NotEqual(t, http.StatusFound, rw.Code)
		assert.Equal(t, "invalid_client", getTestOAuth2ErrorResponse(t, rw)["error"])
		assertLoggedIn(t, mock, true)
	})

	t.Run("ShouldRejectForgedIDTokenHint", func(t *testing.T) {
		mock := setup(t)
		defer mock.Close()

		hint := mustGetTestOIDCIDToken(t, mock)
		parts := strings.Split(hint, ".")
		parts[2] = base64.RawURLEncoding.EncodeToString([]byte("not a signature"))

		rw, r := newTestOAuth2Request(t, fasthttp.MethodGet, testOIDCEndSessionEndpoint, url.Values{
			testOIDCFormParameterIDTokenHint: []string{strings.Join(parts, ".")},
		})

		OAuth2EndSession(mock.Ctx, rw, r)

		assert.Equal(t, http.StatusBadRequest, rw.Code)
		assert.Equal(t, "invalid_request", getTestOAuth2ErrorResponse(t, rw)["error"])
		assertLoggedIn(t, mock, true)
	})

	t.Run("ShouldLogoutAndRedirectToIssuerWithoutParameters", func(t *testing.T) {
		mock := setup(t)
		defer mock.Close()

		mock.StorageMock.EXPECT().RevokeOAuth2SessionsByUsername(gomock.Any(), testUsername).Return(nil)

		rw, r := newTestOAuth2Request(t, fasthttp.MethodGet, testOIDCEndSessionEndpoint, nil)

		OAuth2EndSession(mock.Ctx, rw, r)

		assert.Equal(t, http.StatusFound, rw.Code)
		assert.Equal(t, "https://login.example.com:8080", rw.Header().Get(fasthttp.HeaderLocation))
		assertLoggedIn(t, mock, false)
	})

	t.Run("ShouldRedirectAnonymousUserWithoutRevoking", func(t *testing.T) {
		mock := setup(t)
		defer mock.Close()

		require.NoError(t, mock.Ctx.DestroySession())

		rw, r := newTestOAuth2Request(t, fasthttp.MethodGet, testOIDCEndSessionEndpoint, url.Values{
			oidc.FormParameterClientID:                 []string{testOIDCAuthorizationCodeID},
			testOIDCFormParameterPostLogoutRedirectURI: []string{testOIDCPostLogoutRedirectURI},
		})

		OAuth2EndSession(mock.Ctx, rw, r)

		assert.Equal(t, http.StatusFound, rw.Code)
		assert.Equal(t, testOIDCPostLogoutRedirectURI, rw.Header().Get(fasthttp.HeaderLocation))
	})
}
