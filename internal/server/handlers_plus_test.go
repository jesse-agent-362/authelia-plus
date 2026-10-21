// SPDX-FileCopyrightText: 2026 authelia-plus contributors
//
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
	"go.uber.org/mock/gomock"

	"github.com/authelia/authelia/v4/internal/authorization"
	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/mocks"
	"github.com/authelia/authelia/v4/internal/model"
	plussessions "github.com/authelia/authelia/v4/internal/plus/sessions"
	"github.com/authelia/authelia/v4/internal/random"
	"github.com/authelia/authelia/v4/internal/session"
	"github.com/authelia/authelia/v4/internal/templates"
)

// authelia-plus: the routes of the session list and revoke, through the real router and middlewares.

type testPlusRouter struct {
	handler   fasthttp.RequestHandler
	providers middlewares.Providers
	storage   *mocks.MockStorage
	records   *mocks.PlusSessionsStore
}

func newTestPlusRouter(t *testing.T) *testPlusRouter {
	t.Helper()

	tmpl, err := templates.New(templates.Config{})
	require.NoError(t, err)
	require.NoError(t, tmpl.LoadTemplatedAssets(assets))

	config := &schema.Configuration{
		Server: schema.Server{
			Address:   schema.DefaultServerConfiguration.Address,
			Endpoints: schema.DefaultServerConfiguration.Endpoints,
		},
	}

	config.AccessControl.DefaultPolicy = "one_factor"
	config.AuthenticationBackend.RefreshInterval = schema.NewRefreshIntervalDurationNever()

	config.Session.Cookies = []schema.SessionCookie{
		{
			SessionCookieCommon: schema.SessionCookieCommon{Name: "authelia_session", Expiration: time.Hour, Inactivity: time.Hour, SameSite: "lax"},
			Domain:              "example.com",
			AutheliaURL:         &url.URL{Scheme: "https", Host: "auth.example.com", Path: "/"},
		},
	}

	r := &testPlusRouter{storage: mocks.NewMockStorage(gomock.NewController(t)), records: mocks.NewPlusSessionsStore()}

	r.providers = middlewares.NewProvidersBasic()
	r.providers.Random = random.NewMathematical()
	r.providers.Templates = tmpl
	r.providers.StorageProvider = r.storage
	r.providers.Authorizer = authorization.NewAuthorizer(config)
	r.providers.SessionProvider = session.NewProvider(config.Session, nil)
	r.providers.PlusSessions = plussessions.New(config, r.records, r.providers.Clock)
	r.providers.SessionProvider.SetPlusSessions(r.providers.PlusSessions)

	r.handler, err = handlerMain(config, r.providers)
	require.NoError(t, err)

	return r
}

// login stores a session at the given level with a record, and returns the cookie for it.
func (r *testPlusRouter) login(t *testing.T, username string, secondFactor bool) (id uuid.UUID, cookie *fasthttp.Cookie) {
	t.Helper()

	return r.loginElevated(t, username, secondFactor, false)
}

// loginElevated is login, with the session elevated if elevated is true.
func (r *testPlusRouter) loginElevated(t *testing.T, username string, secondFactor, elevated bool) (id uuid.UUID, cookie *fasthttp.Cookie) {
	t.Helper()

	s, err := r.providers.SessionProvider.Get("example.com")
	require.NoError(t, err)

	id, err = r.providers.PlusSessions.Create(context.Background(), username, "192.0.2.1", "ua", false, s.Config, uuid.Nil, "")
	require.NoError(t, err)

	return id, r.saveElevated(t, username, secondFactor, elevated, id)
}

// save stores a session at the given level with the given record ID, and returns the cookie for it.
func (r *testPlusRouter) save(t *testing.T, username string, secondFactor bool, id uuid.UUID) (cookie *fasthttp.Cookie) {
	t.Helper()

	return r.saveElevated(t, username, secondFactor, false, id)
}

// saveElevated is save, with the session elevated if elevated is true.
func (r *testPlusRouter) saveElevated(t *testing.T, username string, secondFactor, elevated bool, id uuid.UUID) (cookie *fasthttp.Cookie) {
	t.Helper()

	s, err := r.providers.SessionProvider.Get("example.com")
	require.NoError(t, err)

	ctx := &fasthttp.RequestCtx{}

	userSession := s.NewDefaultUserSession()
	userSession.Username = username
	userSession.AuthenticationMethodRefs.UsernameAndPassword = true
	userSession.AuthenticationMethodRefs.TOTP = secondFactor
	userSession.LastActivity = time.Now().Unix()
	userSession.PlusID = id

	if elevated {
		userSession.Elevations.User = &session.Elevation{RemoteIP: middlewares.RequestCtxRemoteIP(&fasthttp.RequestCtx{}), Expires: time.Now().Add(time.Hour)}
	}

	require.NoError(t, s.SaveSession(ctx, userSession))

	cookie = fasthttp.AcquireCookie()
	require.NoError(t, cookie.ParseBytes(ctx.Response.Header.PeekCookie("authelia_session")))

	return cookie
}

// authz asks the forward-auth endpoint whether the session may reach a one_factor resource.
func (r *testPlusRouter) authz(cookie *fasthttp.Cookie) int {
	ctx := &fasthttp.RequestCtx{}

	ctx.Request.Header.SetMethod(fasthttp.MethodGet)
	ctx.Request.SetRequestURI("/api/authz/forward-auth")
	ctx.Request.Header.SetHost("auth.example.com")
	ctx.Request.Header.Set(fasthttp.HeaderXForwardedProto, "https")
	ctx.Request.Header.Set(fasthttp.HeaderXForwardedHost, "app.example.com")
	ctx.Request.Header.Set("X-Forwarded-URI", "/")
	ctx.Request.Header.Set("X-Forwarded-Method", fasthttp.MethodGet)

	if cookie != nil {
		ctx.Request.Header.SetCookieBytesKV(cookie.Key(), cookie.Value())
	}

	r.handler(ctx)

	return ctx.Response.StatusCode()
}

func (r *testPlusRouter) do(method, path string, cookie *fasthttp.Cookie) *fasthttp.RequestCtx {
	ctx := &fasthttp.RequestCtx{}

	ctx.Request.Header.SetMethod(method)
	ctx.Request.SetRequestURI(path)
	ctx.Request.Header.SetHost("auth.example.com")
	ctx.Request.Header.Set(fasthttp.HeaderXForwardedProto, "https")
	ctx.Request.Header.Set(fasthttp.HeaderOrigin, "https://evil.example.net")

	if cookie != nil {
		ctx.Request.Header.SetCookieBytesKV(cookie.Key(), cookie.Value())
	}

	r.handler(ctx)

	return ctx
}

func TestHandlerMainPlusSessions(t *testing.T) {
	r := newTestPlusRouter(t)

	id, cookie := r.loginElevated(t, "john", true, true)
	other, _ := r.login(t, "harry", true)

	assert.Equal(t, fasthttp.StatusOK, r.authz(cookie))

	ctx := r.do(fasthttp.MethodGet, "/api/plus/sessions", cookie)
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	assert.Contains(t, string(ctx.Response.Body()), id.String())
	assert.NotContains(t, string(ctx.Response.Body()), other.String())

	// Requirement 6: no CORS on the endpoints, for the preflight or the request.
	ctx = r.do(fasthttp.MethodOptions, "/api/plus/sessions/"+id.String(), cookie)
	assert.Empty(t, ctx.Response.Header.Peek(fasthttp.HeaderAccessControlAllowOrigin))
	assert.Empty(t, ctx.Response.Header.Peek(fasthttp.HeaderAccessControlAllowMethods))

	ctx = r.do(fasthttp.MethodGet, "/api/plus/sessions", cookie)
	assert.Empty(t, ctx.Response.Header.Peek(fasthttp.HeaderAccessControlAllowOrigin))

	// Requirement 6: the revoke has no GET form.
	ctx = r.do(fasthttp.MethodGet, "/api/plus/sessions/"+id.String(), cookie)
	assert.Equal(t, fasthttp.StatusMethodNotAllowed, ctx.Response.StatusCode())
	assert.False(t, r.records.Get(id).RevokedAt.Valid)

	// Requirement 6: someone else's session and a missing one look the same.
	ctx = r.do(fasthttp.MethodDelete, "/api/plus/sessions/"+other.String(), cookie)
	assert.Equal(t, fasthttp.StatusNotFound, ctx.Response.StatusCode())
	assert.False(t, r.records.Get(other).RevokedAt.Valid)

	notFound := string(ctx.Response.Body())

	ctx = r.do(fasthttp.MethodDelete, "/api/plus/sessions/"+uuid.New().String(), cookie)
	assert.Equal(t, fasthttp.StatusNotFound, ctx.Response.StatusCode())
	assert.Equal(t, notFound, string(ctx.Response.Body()))

	ctx = r.do(fasthttp.MethodDelete, "/api/plus/sessions/"+id.String(), cookie)
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	assert.True(t, r.records.Get(id).RevokedAt.Valid)

	// Requirement 1: the revoked session is gone for every endpoint at once.
	ctx = r.do(fasthttp.MethodGet, "/api/plus/sessions", cookie)
	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())

	ctx = r.do(fasthttp.MethodGet, "/api/user/info", cookie)
	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())

	// The same goes for the authz endpoint.
	assert.Equal(t, fasthttp.StatusUnauthorized, r.authz(cookie))
}

func TestHandlerMainPlusSessionsRevokeOthers(t *testing.T) {
	r := newTestPlusRouter(t)

	current, cookie := r.loginElevated(t, "john", true, true)
	other, otherCookie := r.login(t, "john", true)
	hidden, hiddenCookie := r.login(t, "john", true)
	harry, harryCookie := r.login(t, "harry", true)

	// Live, but left looking expired by a lagging activity write, so the list hides it.
	r.records.Records[hidden].ExpiresAt = time.Now().Add(-time.Hour)

	ctx := r.do(fasthttp.MethodGet, "/api/plus/sessions", cookie)
	require.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	require.NotContains(t, string(ctx.Response.Body()), hidden.String())

	ctx = r.do(fasthttp.MethodDelete, "/api/plus/sessions", cookie)
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	assert.JSONEq(t, `{"status":"OK","data":{"count":2}}`, string(ctx.Response.Body()))
	assert.Empty(t, ctx.Response.Header.Peek(fasthttp.HeaderAccessControlAllowOrigin))

	assert.Equal(t, fasthttp.StatusOK, r.authz(cookie), "the current session survives")
	assert.Equal(t, fasthttp.StatusUnauthorized, r.authz(otherCookie))
	assert.Equal(t, fasthttp.StatusUnauthorized, r.authz(hiddenCookie), "a session hidden from the list is revoked too")
	assert.Equal(t, fasthttp.StatusOK, r.authz(harryCookie), "another user's sessions are untouched")

	assert.False(t, r.records.Get(current).RevokedAt.Valid)
	assert.True(t, r.records.Get(other).RevokedAt.Valid)
	assert.False(t, r.records.Get(harry).RevokedAt.Valid)

	ctx = r.do(fasthttp.MethodDelete, "/api/plus/sessions", cookie)
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	assert.JSONEq(t, `{"status":"OK","data":{"count":0}}`, string(ctx.Response.Body()))
}

// Revoking another session needs an elevated session on top of the full authentication, so a stolen session can't keep
// revoking the one its user logs in with. Revoking the current one is a logout and doesn't. The 403 tells the UI to
// elevate rather than to complete the second factor.
func TestHandlerMainPlusSessionsRequireElevation(t *testing.T) {
	r := newTestPlusRouter(t)

	current, cookie := r.login(t, "john", true)
	other, _ := r.login(t, "john", true)

	const elevation = `{"status":"KO","data":{"elevation":true,"first_factor":false,"second_factor":false}}`

	ctx := r.do(fasthttp.MethodDelete, "/api/plus/sessions", cookie)
	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
	assert.JSONEq(t, elevation, string(ctx.Response.Body()))

	ctx = r.do(fasthttp.MethodDelete, "/api/plus/sessions/"+other.String(), cookie)
	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
	assert.JSONEq(t, elevation, string(ctx.Response.Body()))

	assert.False(t, r.records.Get(other).RevokedAt.Valid)

	ctx = r.do(fasthttp.MethodDelete, "/api/plus/sessions/"+current.String(), cookie)
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	assert.True(t, r.records.Get(current).RevokedAt.Valid)
}

// Item 3: an authenticated session saved before the records existed has no record to revoke, so it's anonymous.
func TestHandlerMainPlusSessionsAuthzWithoutRecord(t *testing.T) {
	r := newTestPlusRouter(t)

	cookie := r.save(t, "john", true, uuid.Nil)

	assert.Equal(t, fasthttp.StatusUnauthorized, r.authz(cookie))

	ctx := r.do(fasthttp.MethodGet, "/api/user/info", cookie)
	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
}

// Requirement 5: one factor is not enough for a user with a second factor enrolled, on both endpoints.
func TestHandlerMainPlusSessionsRequireFullAuth(t *testing.T) {
	r := newTestPlusRouter(t)

	id, cookie := r.login(t, "john", false)

	other, _ := r.login(t, "john", true)

	r.storage.EXPECT().LoadUserInfo(gomock.Any(), "john").Return(model.UserInfo{HasTOTP: true}, nil).Times(3)

	ctx := r.do(fasthttp.MethodGet, "/api/plus/sessions", cookie)
	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
	assert.NotContains(t, string(ctx.Response.Body()), id.String())

	ctx = r.do(fasthttp.MethodDelete, "/api/plus/sessions/"+id.String(), cookie)
	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
	assert.False(t, r.records.Get(id).RevokedAt.Valid)

	secondFactor := string(ctx.Response.Body())

	ctx = r.do(fasthttp.MethodDelete, "/api/plus/sessions", cookie)
	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
	assert.Equal(t, secondFactor, string(ctx.Response.Body()), "the same 403 envelope as the single revoke")
	assert.False(t, r.records.Get(other).RevokedAt.Valid)

	ctx = r.do(fasthttp.MethodGet, "/api/plus/sessions", nil)
	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
}
