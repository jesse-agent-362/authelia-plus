// SPDX-FileCopyrightText: 2026 Authelia
// SPDX-FileCopyrightText: 2026 authelia-plus contributors
//
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"errors"
	"testing"

	"github.com/fasthttp/session/v2"
	"github.com/fasthttp/session/v2/providers/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"

	"github.com/authelia/authelia/v4/internal/authentication"
	"github.com/authelia/authelia/v4/internal/configuration/schema"
)

type testPlusSessions struct {
	revoked map[uuid.UUID]bool
	touched []uuid.UUID
}

func (p *testPlusSessions) Revoked(id uuid.UUID) bool {
	return p.revoked[id]
}

func (p *testPlusSessions) Touch(userSession *UserSession, _ schema.SessionCookie) {
	p.touched = append(p.touched, userSession.PlusID)
}

// testFailingDestroyProvider is a memory provider which can't destroy sessions.
type testFailingDestroyProvider struct {
	*memory.Provider
}

func (p *testFailingDestroyProvider) Destroy(_ []byte) error {
	return errors.New("destroy failed")
}

func newTestPlusSession(t *testing.T, failDestroy bool) (*Session, *testPlusSessions) {
	t.Helper()

	config := schema.SessionCookie{
		SessionCookieCommon: schema.SessionCookieCommon{Name: testName, Expiration: testExpiration},
		Domain:              testDomain,
	}

	m, err := memory.New(memory.Config{})
	require.NoError(t, err)

	var provider session.Provider = m

	if failDestroy {
		provider = &testFailingDestroyProvider{Provider: m}
	}

	_, holder, err := NewProviderConfigAndSession(config, "memory", nil, provider)
	require.NoError(t, err)

	plus := &testPlusSessions{revoked: map[uuid.UUID]bool{}}

	return &Session{Config: config, sessionHolder: holder, plus: plus}, plus
}

// testPlusSessionRequest saves an authenticated session in one request and returns a second request carrying its
// cookie, so the next load reads the session back from the store.
func testPlusSessionRequest(t *testing.T, s *Session, id uuid.UUID) *fasthttp.RequestCtx {
	t.Helper()

	ctx := &fasthttp.RequestCtx{}

	userSession, err := s.GetSession(ctx)
	require.NoError(t, err)

	userSession.Username = "john"
	userSession.AuthenticationMethodRefs.UsernameAndPassword = true
	userSession.PlusID = id

	require.NoError(t, s.SaveSession(ctx, userSession))

	cookie := ctx.Response.Header.PeekCookie(testName)
	require.NotEmpty(t, cookie)

	c := fasthttp.AcquireCookie()
	defer fasthttp.ReleaseCookie(c)

	require.NoError(t, c.ParseBytes(cookie))

	next := &fasthttp.RequestCtx{}
	next.Request.Header.SetCookieBytesKV(c.Key(), c.Value())

	return next
}

func TestPlusSessionShouldLoadUnrevokedSessionAndTouchIt(t *testing.T) {
	s, plus := newTestPlusSession(t, false)

	id := uuid.New()

	ctx := testPlusSessionRequest(t, s, id)

	userSession, err := s.GetSession(ctx)
	require.NoError(t, err)

	assert.Equal(t, "john", userSession.Username)
	assert.Equal(t, authentication.OneFactor, userSession.AuthenticationLevel(false))
	assert.Equal(t, []uuid.UUID{id}, plus.touched)
}

// Requirement 1: the revocation is checked where every session loads, not only by the forward-auth handler, so every
// caller of GetSession (portal APIs, OpenID Connect 1.0 authorization) sees an anonymous session.
func TestPlusSessionShouldRejectRevokedSessionOnLoad(t *testing.T) {
	s, plus := newTestPlusSession(t, false)

	id := uuid.New()

	ctx := testPlusSessionRequest(t, s, id)

	plus.revoked[id] = true

	userSession, err := s.GetSession(ctx)
	require.NoError(t, err)

	assert.True(t, userSession.IsAnonymous())
	assert.Equal(t, uuid.Nil, userSession.PlusID)
	assert.Empty(t, plus.touched)

	// The session was destroyed, so it stays gone even once the ID is forgotten.
	delete(plus.revoked, id)

	userSession, err = NewEncapsulatedSession(s, ctx).GetSession()
	require.NoError(t, err)

	assert.True(t, userSession.IsAnonymous())
}

// Requirement 1: the session is rejected even when destroying it fails.
func TestPlusSessionShouldRejectRevokedSessionWhenDestroyFails(t *testing.T) {
	s, plus := newTestPlusSession(t, true)

	id := uuid.New()

	ctx := testPlusSessionRequest(t, s, id)

	plus.revoked[id] = true

	for range 2 {
		userSession, err := s.GetSession(ctx)
		require.NoError(t, err)

		assert.True(t, userSession.IsAnonymous())
	}
}

// An authenticated session without a record predates the records, and could never be revoked: a stolen long-lived
// cookie would survive revoking every session of its user. It's rejected instead.
func TestPlusSessionShouldRejectAuthenticatedSessionsWithoutRecord(t *testing.T) {
	s, plus := newTestPlusSession(t, false)

	ctx := testPlusSessionRequest(t, s, uuid.Nil)

	userSession, err := s.GetSession(ctx)
	require.NoError(t, err)

	assert.True(t, userSession.IsAnonymous())
	assert.Empty(t, plus.touched)
}

func TestPlusSessionShouldKeepAnonymousSessionsWithoutRecord(t *testing.T) {
	s, plus := newTestPlusSession(t, false)

	ctx := &fasthttp.RequestCtx{}

	anonymous, err := s.GetSession(ctx)
	require.NoError(t, err)

	anonymous.LastActivity = 42

	require.NoError(t, s.SaveSession(ctx, anonymous))

	userSession, err := s.GetSession(ctx)
	require.NoError(t, err)

	assert.Equal(t, int64(42), userSession.LastActivity, "an anonymous session is left alone")
	assert.Empty(t, plus.touched)
}

func TestPlusSessionShouldBeSetOnEveryDomain(t *testing.T) {
	config := schema.Session{}
	config.Cookies = []schema.SessionCookie{
		{SessionCookieCommon: schema.SessionCookieCommon{Name: testName, Expiration: testExpiration}, Domain: testDomain},
		{SessionCookieCommon: schema.SessionCookieCommon{Name: testName, Expiration: testExpiration}, Domain: "example.net"},
	}

	provider := NewProvider(config, nil)

	plus := &testPlusSessions{}

	provider.SetPlusSessions(plus)

	for _, domain := range []string{testDomain, "example.net"} {
		s, err := provider.Get(domain)
		require.NoError(t, err)

		assert.Equal(t, plus, s.plus)
	}
}
