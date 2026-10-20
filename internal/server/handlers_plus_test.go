// SPDX-FileCopyrightText: 2026 Authelia
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

	s, err := r.providers.SessionProvider.Get("example.com")
	require.NoError(t, err)

	id, err = r.providers.PlusSessions.Create(context.Background(), username, "192.0.2.1", "ua", false, s.Config, "", uuid.Nil, nil)
	require.NoError(t, err)

	ctx := &fasthttp.RequestCtx{}

	userSession := s.NewDefaultUserSession()
	userSession.Username = username
	userSession.AuthenticationMethodRefs.UsernameAndPassword = true
	userSession.AuthenticationMethodRefs.TOTP = secondFactor
	userSession.LastActivity = time.Now().Unix()
	userSession.PlusID = id

	require.NoError(t, s.SaveSession(ctx, userSession))

	cookie = fasthttp.AcquireCookie()
	require.NoError(t, cookie.ParseBytes(ctx.Response.Header.PeekCookie("authelia_session")))

	return id, cookie
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

	id, cookie := r.login(t, "john", true)
	other, _ := r.login(t, "harry", true)

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
}

// Requirement 5: one factor is not enough for a user with a second factor enrolled, on both endpoints.
func TestHandlerMainPlusSessionsRequireFullAuth(t *testing.T) {
	r := newTestPlusRouter(t)

	id, cookie := r.login(t, "john", false)

	r.storage.EXPECT().LoadUserInfo(gomock.Any(), "john").Return(model.UserInfo{HasTOTP: true}, nil).Times(2)

	ctx := r.do(fasthttp.MethodGet, "/api/plus/sessions", cookie)
	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
	assert.NotContains(t, string(ctx.Response.Body()), id.String())

	ctx = r.do(fasthttp.MethodDelete, "/api/plus/sessions/"+id.String(), cookie)
	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
	assert.False(t, r.records.Get(id).RevokedAt.Valid)

	ctx = r.do(fasthttp.MethodGet, "/api/plus/sessions", nil)
	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
}
