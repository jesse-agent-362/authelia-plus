// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package sessions_test

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/authelia/authelia/v4/internal/clock"
	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/mocks"
	"github.com/authelia/authelia/v4/internal/model"
	. "github.com/authelia/authelia/v4/internal/plus/sessions"
	"github.com/authelia/authelia/v4/internal/session"
)

var errTest = errors.New("test error")

func newTestConfig(redis bool) *schema.Configuration {
	config := &schema.Configuration{}
	config.Session.Cookies = []schema.SessionCookie{
		{SessionCookieCommon: schema.SessionCookieCommon{Expiration: time.Hour, RememberMe: 24 * time.Hour}, Domain: "example.com"},
	}

	if redis {
		config.Session.Redis = &schema.SessionRedis{}
	}

	return config
}

func newTestManager(t *testing.T, redis bool) (*Manager, *mocks.PlusSessionsStore, *clock.Fixed) {
	t.Helper()

	store := mocks.NewPlusSessionsStore()
	c := clock.NewFixed(time.Unix(1760000000, 0))

	return New(newTestConfig(redis), store, c), store, c
}

func testCookie() schema.SessionCookie {
	return schema.SessionCookie{SessionCookieCommon: schema.SessionCookieCommon{Expiration: time.Hour, RememberMe: 24 * time.Hour}, Domain: "example.com"}
}

func testCreate(t *testing.T, m *Manager) uuid.UUID {
	t.Helper()

	id, err := m.Create(context.Background(), "john", "192.0.2.1", "Mozilla/5.0", false, testCookie(), uuid.Nil, "")
	require.NoError(t, err)

	return id
}

func TestShouldCreateRecord(t *testing.T) {
	m, store, c := newTestManager(t, true)

	id, err := m.Create(context.Background(), "john", "192.0.2.1", "Mozilla/5.0", true, testCookie(), uuid.Nil, "")
	require.NoError(t, err)

	assert.Equal(t, uuid.Version(7), id.Version())

	record := store.Get(id)
	require.NotNil(t, record)

	assert.Equal(t, "john", record.Username)
	assert.Equal(t, "192.0.2.1", record.IP)
	assert.Equal(t, "Mozilla/5.0", record.UserAgent)
	assert.Equal(t, c.Now().UTC(), record.CreatedAt)
	assert.Equal(t, c.Now().UTC().Add(24*time.Hour), record.ExpiresAt)
	assert.False(t, record.RevokedAt.Valid)
}

// Requirement 3: the User-Agent and IP are capped, without splitting a UTF-8 sequence.
func TestShouldCapUserAgentAndIP(t *testing.T) {
	m, store, _ := newTestManager(t, true)

	ua := strings.Repeat("a", MaxUserAgent-1) + "é" + strings.Repeat("b", 100)
	ip := strings.Repeat("1", 100)

	id, err := m.Create(context.Background(), "john", ip, ua, false, testCookie(), uuid.Nil, "")
	require.NoError(t, err)

	record := store.Get(id)
	require.NotNil(t, record)

	assert.Equal(t, strings.Repeat("a", MaxUserAgent-1), record.UserAgent)
	assert.Len(t, record.IP, MaxIP)
}

// Requirement 3: a failed insert is an error, which the caller turns into a failed authentication.
func TestShouldFailCreateWhenInsertFails(t *testing.T) {
	m, store, _ := newTestManager(t, true)

	store.SetError("SavePlusUserSession", errTest)

	id, err := m.Create(context.Background(), "john", "192.0.2.1", "ua", false, testCookie(), uuid.Nil, "")

	assert.ErrorIs(t, err, errTest)
	assert.Equal(t, uuid.Nil, id)
	assert.Empty(t, store.Records)
}

func TestShouldReplacePreviousRecord(t *testing.T) {
	m, store, _ := newTestManager(t, true)

	previous := testCreate(t, m)

	require.NoError(t, m.RecordGrant(context.Background(), model.PlusUserSessionGrant{SessionID: previous, RequestID: "req1"}))

	id, err := m.Create(context.Background(), "john", "192.0.2.1", "ua", false, testCookie(), previous, "john")
	require.NoError(t, err)

	assert.NotEqual(t, previous, id)

	old := store.Get(previous)
	assert.True(t, old.RevokedAt.Valid)
	assert.True(t, old.ProcessedAt.Valid, "the replaced record must not be processed: its grants moved to the new one")
	assert.Equal(t, RevokedByReplace, old.RevokedBy)
	assert.True(t, m.Revoked(previous))

	require.Len(t, store.Grants, 1)
	assert.Equal(t, id, store.Grants[0].SessionID)
}

// A re-authentication racing a revoke of the record it replaces must fail, or the revoked session would carry on under
// a fresh record.
func TestShouldFailReplaceWhenPreviousRevoked(t *testing.T) {
	m, store, _ := newTestManager(t, true)

	previous := testCreate(t, m)

	// Revoked by the CLI, which this instance hasn't polled yet.
	_, err := RevokeUser(context.Background(), store, "john", time.Unix(1760000000, 0))
	require.NoError(t, err)
	require.False(t, m.Revoked(previous))

	id, err := m.Create(context.Background(), "john", "192.0.2.1", "ua", false, testCookie(), previous, "john")

	assert.ErrorIs(t, err, ErrRecordUnavailable)
	assert.Equal(t, uuid.Nil, id)
	assert.Len(t, store.Records, 1, "no replacement is recorded")
	assert.False(t, store.Get(previous).ProcessedAt.Valid, "the revoke is still processed")
}

// Logging in as another user over an authenticated session ends the other user's session, grants and all.
func TestShouldRevokePreviousRecordOnUserSwitch(t *testing.T) {
	m, store, _ := newTestManager(t, true)

	previous := testCreate(t, m)

	id, err := m.Create(context.Background(), "harry", "192.0.2.1", "ua", false, testCookie(), previous, "john")
	require.NoError(t, err)

	old := store.Get(previous)
	assert.True(t, old.RevokedAt.Valid)
	assert.False(t, old.ProcessedAt.Valid, "the other user's grants are revoked in the background")
	assert.Equal(t, RevokedBySwitch, old.RevokedBy)
	assert.Equal(t, "harry", store.Get(id).Username)
}

// Item 1: the logout's own revoke of the grants is best effort; the poller processes the revocation afterwards anyway,
// so a revoke that failed, or ran before a racing authorization stored its code, is made good.
func TestShouldEndRecordOnLogout(t *testing.T) {
	m, store, c := newTestManager(t, true)

	var got [][]model.PlusUserSessionGrant

	m.SetProcessor(func(_ context.Context, _ *model.PlusUserSession, grants []model.PlusUserSessionGrant) error {
		got = append(got, grants)

		return nil
	})

	id := testCreate(t, m)

	require.NoError(t, m.RecordGrant(context.Background(), model.PlusUserSessionGrant{SessionID: id, RequestID: "req1"}))

	grants, ok, err := m.End(context.Background(), id, "john")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, []model.PlusUserSessionGrant{{SessionID: id, RequestID: "req1"}}, grants)

	record := store.Get(id)
	assert.Equal(t, RevokedByLogout, record.RevokedBy)
	assert.False(t, record.ProcessedAt.Valid, "the poller still processes it")
	assert.True(t, m.Revoked(id))

	assert.ErrorIs(t, m.RecordGrant(context.Background(), model.PlusUserSessionGrant{SessionID: id, RequestID: "req2"}), ErrRecordUnavailable)

	c.Set(c.Now().Add(ProcessDelay + time.Second))

	m.Poll(context.Background())

	assert.Equal(t, [][]model.PlusUserSessionGrant{{{SessionID: id, RequestID: "req1"}}}, got)
	assert.True(t, store.Get(id).ProcessedAt.Valid)

	_, ok, err = m.End(context.Background(), id, "john")
	require.NoError(t, err)
	assert.False(t, ok, "a processed record has nothing left for a logout")
}

// A logout which can't load the grants leaves the revocation to be processed in the background.
func TestShouldLeaveRecordToPollerWhenEndCannotLoadGrants(t *testing.T) {
	m, store, _ := newTestManager(t, true)

	id := testCreate(t, m)

	store.SetError("LoadPlusUserSessionGrants", errTest)

	_, ok, err := m.End(context.Background(), id, "john")
	assert.ErrorIs(t, err, errTest)
	assert.False(t, ok)

	record := store.Get(id)
	assert.True(t, record.RevokedAt.Valid)
	assert.False(t, record.ProcessedAt.Valid)
}

// Requirement 4: the revoked set is loaded by the startup check, before anything is served, not by the first poll.
func TestShouldLoadRevokedSetAtStartup(t *testing.T) {
	store := mocks.NewPlusSessionsStore()
	c := clock.NewFixed(time.Unix(1760000000, 0))

	id := uuid.New()

	require.NoError(t, store.SavePlusUserSession(context.Background(), model.PlusUserSession{ID: id, Username: "john", ExpiresAt: c.Now().Add(time.Hour)}))

	_, err := store.RevokePlusUserSession(context.Background(), id, "john", RevokedBySelf, c.Now().Add(-time.Minute))
	require.NoError(t, err)

	m := New(newTestConfig(true), store, c)

	assert.False(t, m.Revoked(id))

	require.NoError(t, m.StartupCheck())

	assert.True(t, m.Revoked(id))
}

// Requirement 4: if the set can't be loaded, the startup fails rather than serving without it.
func TestShouldFailStartupWhenRevokedSetFails(t *testing.T) {
	m, store, _ := newTestManager(t, true)

	store.SetError("LoadPlusUserSessionRevocations", errTest)

	assert.ErrorIs(t, m.StartupCheck(), errTest)
}

// Requirement 4: a failed refresh keeps the last good set.
func TestShouldKeepRevokedSetWhenRefreshFails(t *testing.T) {
	m, store, c := newTestManager(t, true)

	id := testCreate(t, m)

	_, err := store.RevokePlusUserSession(context.Background(), id, "john", RevokedByCLI, c.Now())
	require.NoError(t, err)

	require.NoError(t, m.StartupCheck())
	require.True(t, m.Revoked(id))

	store.SetError("LoadPlusUserSessionRevocations", errTest)

	c.Set(c.Now().Add(time.Minute))

	m.Poll(context.Background())

	assert.True(t, m.Revoked(id))
}

// The revoked ID is kept for the longest session lifetime after the revoke, however stale the record's expiry.
func TestShouldKeepRevokedIDForRetention(t *testing.T) {
	m, store, c := newTestManager(t, true)

	assert.Equal(t, 24*time.Hour+time.Hour+5*time.Minute, m.Retention())

	id := testCreate(t, m)

	store.Records[id].ExpiresAt = c.Now().Add(-48 * time.Hour)

	require.NoError(t, m.StartupCheck())

	ok, err := m.Revoke(context.Background(), id, "john")
	require.NoError(t, err)
	require.True(t, ok)

	c.Set(c.Now().Add(m.Retention() - time.Minute))
	m.Poll(context.Background())

	assert.True(t, m.Revoked(id))

	// Forgotten on the next reload of the whole retention.
	c.Set(c.Now().Add(PurgeInterval))
	m.Poll(context.Background())

	assert.False(t, m.Revoked(id))
}

func TestShouldPickUpRevokesFromOtherInstances(t *testing.T) {
	m, store, c := newTestManager(t, true)

	id := testCreate(t, m)

	require.NoError(t, m.StartupCheck())

	count, err := RevokeUser(context.Background(), store, "JOHN", c.Now())
	require.NoError(t, err)
	assert.Equal(t, int64(0), count, "the username is matched exactly, as on every other path")

	count, err = RevokeUser(context.Background(), store, "john", c.Now())
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	assert.False(t, m.Revoked(id))

	m.Poll(context.Background())

	assert.True(t, m.Revoked(id))
}

func TestShouldRevokeOnlyOwnRecord(t *testing.T) {
	m, _, _ := newTestManager(t, true)

	id := testCreate(t, m)

	ok, err := m.Revoke(context.Background(), id, "harry")
	require.NoError(t, err)
	assert.False(t, ok)
	assert.False(t, m.Revoked(id))

	ok, err = m.Revoke(context.Background(), uuid.New(), "john")
	require.NoError(t, err)
	assert.False(t, ok)

	ok, err = m.Revoke(context.Background(), id, "john")
	require.NoError(t, err)
	assert.True(t, ok)
	assert.True(t, m.Revoked(id))

	ok, err = m.Revoke(context.Background(), id, "john")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestShouldCloseRecordsOnRestartWithMemoryProvider(t *testing.T) {
	m, store, c := newTestManager(t, false)

	id := testCreate(t, m)

	require.NoError(t, m.StartupCheck())

	record := store.Get(id)
	assert.True(t, record.RevokedAt.Valid)
	assert.Equal(t, RevokedByRestart, record.RevokedBy)
	assert.True(t, record.ProcessedAt.Valid)

	var calls atomic.Int32

	m.SetProcessor(func(_ context.Context, _ *model.PlusUserSession, _ []model.PlusUserSessionGrant) error {
		calls.Add(1)
		return nil
	})

	c.Set(c.Now().Add(ProcessDelay + time.Second))
	m.Poll(context.Background())

	assert.Equal(t, int32(0), calls.Load(), "a restart must not revoke the OpenID Connect 1.0 grants")
}

func TestShouldNotCloseRecordsOnRestartWithRedisProvider(t *testing.T) {
	m, store, _ := newTestManager(t, true)

	id := testCreate(t, m)

	require.NoError(t, m.StartupCheck())

	assert.False(t, store.Get(id).RevokedAt.Valid)
}

func TestShouldProcessRevocationOnceAfterDelay(t *testing.T) {
	store := mocks.NewPlusSessionsStore()
	c := clock.NewFixed(time.Unix(1760000000, 0))

	a, b := New(newTestConfig(true), store, c), New(newTestConfig(true), store, c)

	var (
		calls atomic.Int32
		got   []model.PlusUserSessionGrant
	)

	processor := func(_ context.Context, record *model.PlusUserSession, grants []model.PlusUserSessionGrant) error {
		calls.Add(1)

		got = grants

		return nil
	}

	a.SetProcessor(processor)
	b.SetProcessor(processor)

	id := testCreate(t, a)

	require.NoError(t, a.RecordGrant(context.Background(), model.PlusUserSessionGrant{SessionID: id, RequestID: "req1"}))
	require.NoError(t, b.RecordGrant(context.Background(), model.PlusUserSessionGrant{SessionID: id, RequestID: "req2", ClientID: "app", Subject: "sub", SID: "sid", Issuer: "https://auth.example.com"}))

	ok, err := a.Revoke(context.Background(), id, "john")
	require.NoError(t, err)
	require.True(t, ok)

	a.Poll(context.Background())
	b.Poll(context.Background())

	assert.Equal(t, int32(0), calls.Load(), "the revocation must wait until every instance rejects the session")

	c.Set(c.Now().Add(ProcessDelay + time.Second))

	a.Poll(context.Background())
	b.Poll(context.Background())
	a.Poll(context.Background())

	assert.Equal(t, int32(1), calls.Load())
	assert.Equal(t, []model.PlusUserSessionGrant{
		{SessionID: id, RequestID: "req1"},
		{SessionID: id, RequestID: "req2", ClientID: "app", Subject: "sub", SID: "sid", Issuer: "https://auth.example.com"},
	}, got)

	// Once revoked, no further grant can be recorded onto the record on any instance.
	assert.ErrorIs(t, b.RecordGrant(context.Background(), model.PlusUserSessionGrant{SessionID: id, RequestID: "req3"}), ErrRecordUnavailable)
}

// Each claim is stamped when it's taken: a record claimed after a slow one must not carry the poll's start time, or
// another instance would take it over while it's still being processed.
func TestShouldStampEachClaimWhenTaken(t *testing.T) {
	m, store, c := newTestManager(t, true)

	first, second := testCreate(t, m), testCreate(t, m)

	_, err := m.Revoke(context.Background(), first, "john")
	require.NoError(t, err)

	c.Set(c.Now().Add(time.Second))

	_, err = m.Revoke(context.Background(), second, "john")
	require.NoError(t, err)

	c.Set(c.Now().Add(ProcessDelay + time.Second))

	claimed := map[uuid.UUID]time.Time{}

	m.SetProcessor(func(_ context.Context, record *model.PlusUserSession, _ []model.PlusUserSessionGrant) error {
		claimed[record.ID] = store.Get(record.ID).ClaimedAt.Time

		c.Set(c.Now().Add(ClaimLease + time.Minute))

		return nil
	})

	start := c.Now().UTC()

	m.Poll(context.Background())

	require.Len(t, claimed, 2)
	assert.Equal(t, start, claimed[first])
	assert.Equal(t, start.Add(ClaimLease+time.Minute), claimed[second])
}

// A record whose grants can't be loaded is released for a retry rather than left claimed with its grants unrevoked.
func TestShouldRetryRevocationWhenGrantsFailToLoad(t *testing.T) {
	m, store, c := newTestManager(t, true)

	var calls atomic.Int32

	m.SetProcessor(func(_ context.Context, _ *model.PlusUserSession, _ []model.PlusUserSessionGrant) error {
		calls.Add(1)

		return nil
	})

	id := testCreate(t, m)

	_, err := m.Revoke(context.Background(), id, "john")
	require.NoError(t, err)

	c.Set(c.Now().Add(ProcessDelay + time.Second))

	store.SetError("LoadPlusUserSessionGrants", errTest)

	m.Poll(context.Background())

	assert.Equal(t, int32(0), calls.Load())
	assert.False(t, store.Get(id).ProcessedAt.Valid)
	assert.False(t, store.Get(id).ClaimedAt.Valid, "the claim is released")

	store.SetError("LoadPlusUserSessionGrants", nil)

	c.Set(c.Now().Add(RetryBase))
	m.Poll(context.Background())

	assert.Equal(t, int32(1), calls.Load())
	assert.True(t, store.Get(id).ProcessedAt.Valid)
}

func TestShouldRetryRevocationWhenProcessingFails(t *testing.T) {
	m, _, c := newTestManager(t, true)

	var calls atomic.Int32

	m.SetProcessor(func(_ context.Context, _ *model.PlusUserSession, _ []model.PlusUserSessionGrant) error {
		if calls.Add(1) == 1 {
			return errTest
		}

		return nil
	})

	id := testCreate(t, m)

	_, err := m.Revoke(context.Background(), id, "john")
	require.NoError(t, err)

	c.Set(c.Now().Add(ProcessDelay + time.Second))

	m.Poll(context.Background())
	m.Poll(context.Background())

	assert.Equal(t, int32(1), calls.Load(), "a failed revocation waits for its backoff")

	c.Set(c.Now().Add(RetryBase))
	m.Poll(context.Background())
	m.Poll(context.Background())

	assert.Equal(t, int32(2), calls.Load())
}

func TestShouldBackOffFailingRevocations(t *testing.T) {
	m, store, c := newTestManager(t, true)

	m.SetProcessor(func(_ context.Context, _ *model.PlusUserSession, _ []model.PlusUserSessionGrant) error {
		return errTest
	})

	id := testCreate(t, m)

	_, err := m.Revoke(context.Background(), id, "john")
	require.NoError(t, err)

	c.Set(c.Now().Add(ProcessDelay + time.Second))

	for attempt, wait := range []time.Duration{RetryBase, 2 * RetryBase, 4 * RetryBase} {
		m.Poll(context.Background())

		record := store.Get(id)

		assert.Equal(t, attempt+1, record.Attempts)
		assert.Equal(t, c.Now().UTC().Add(wait), record.RetryAt.Time.UTC(), "attempt %d", attempt+1)

		c.Set(record.RetryAt.Time)
	}

	assert.Equal(t, time.Hour, Backoff(20), "the backoff is capped")
}

func TestShouldBoundProcessingOfOneRevocation(t *testing.T) {
	m, _, c := newTestManager(t, true)

	var remaining time.Duration

	m.SetProcessor(func(pctx context.Context, _ *model.PlusUserSession, _ []model.PlusUserSessionGrant) error {
		deadline, ok := pctx.Deadline()
		require.True(t, ok, "the processor runs with a deadline")

		remaining = time.Until(deadline)

		return nil
	})

	id := testCreate(t, m)

	_, err := m.Revoke(context.Background(), id, "john")
	require.NoError(t, err)

	c.Set(c.Now().Add(ProcessDelay + time.Second))

	m.Poll(context.Background())

	assert.Positive(t, remaining)
	assert.LessOrEqual(t, remaining, ProcessTimeout)
	assert.Less(t, ProcessTimeout, ClaimLease, "a revocation is done or abandoned before another instance takes it over")
}

func TestShouldRefreshIncrementally(t *testing.T) {
	m, store, c := newTestManager(t, true)

	start := c.Now().UTC()

	require.NoError(t, m.StartupCheck())

	other := testCreate(t, m)

	// Revoked by another instance.
	revokedAt := start.Add(time.Minute)

	_, err := store.RevokePlusUserSession(context.Background(), other, "john", RevokedByCLI, revokedAt)
	require.NoError(t, err)

	c.Set(start.Add(2 * time.Minute))
	m.Poll(context.Background())

	assert.True(t, m.Revoked(other))

	c.Set(start.Add(3 * time.Minute))
	m.Poll(context.Background())

	c.Set(start.Add(PurgeInterval))
	m.Poll(context.Background())

	assert.Equal(t, []time.Time{
		start.Add(-m.Retention()),
		start.Add(-m.Retention()).Add(2 * time.Minute),
		revokedAt.Add(-RefreshOverlap),
		start.Add(PurgeInterval).Add(-m.Retention()),
	}, store.RevocationsSince, "the whole retention at startup and every PurgeInterval, else from the latest revocation seen")
}

func TestShouldRevokeOtherSessions(t *testing.T) {
	m, store, _ := newTestManager(t, true)

	current, other := testCreate(t, m), testCreate(t, m)

	harry, err := m.Create(context.Background(), "harry", "192.0.2.1", "Mozilla/5.0", false, testCookie(), uuid.Nil, "")
	require.NoError(t, err)

	count, err := m.RevokeOthers(context.Background(), "john", current)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	assert.True(t, m.Revoked(other), "rejected here at once")
	assert.False(t, m.Revoked(current))
	assert.False(t, m.Revoked(harry))
	assert.Equal(t, RevokedBySelf, store.Get(other).RevokedBy)
	assert.False(t, store.Get(other).ProcessedAt.Valid, "processed by the poller")
}

// Item 2: an instance shutting down mid-processing cancels the context the processor runs in; the claim is still
// released, with a context of its own, so the next poll anywhere retries it.
func TestShouldReleaseClaimWhenShutDownMidProcessing(t *testing.T) {
	m, store, c := newTestManager(t, true)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var calls atomic.Int32

	m.SetProcessor(func(pctx context.Context, _ *model.PlusUserSession, _ []model.PlusUserSessionGrant) error {
		if calls.Add(1) == 1 {
			cancel()

			return pctx.Err()
		}

		return nil
	})

	id := testCreate(t, m)

	_, err := m.Revoke(context.Background(), id, "john")
	require.NoError(t, err)

	c.Set(c.Now().Add(ProcessDelay + time.Second))

	m.Poll(ctx)

	assert.Equal(t, int32(1), calls.Load())
	assert.False(t, store.Get(id).ProcessedAt.Valid)
	assert.False(t, store.Get(id).ClaimedAt.Valid, "the claim is released despite the shutdown")

	c.Set(c.Now().Add(RetryBase))
	m.Poll(context.Background())

	assert.Equal(t, int32(2), calls.Load())
	assert.True(t, store.Get(id).ProcessedAt.Valid)
}

// Item 2: an instance killed mid-processing never completes or releases its claim. The revocation is processed
// once the claim is older than the lease, and not before.
func TestShouldReclaimRevocationAfterLease(t *testing.T) {
	m, store, c := newTestManager(t, true)

	var calls atomic.Int32

	m.SetProcessor(func(_ context.Context, _ *model.PlusUserSession, _ []model.PlusUserSessionGrant) error {
		calls.Add(1)

		return nil
	})

	id := testCreate(t, m)

	_, err := m.Revoke(context.Background(), id, "john")
	require.NoError(t, err)

	c.Set(c.Now().Add(ProcessDelay + time.Second))

	// The instance that dies.
	ok, err := store.ClaimPlusUserSession(context.Background(), id, c.Now(), c.Now().Add(-ClaimLease))
	require.NoError(t, err)
	require.True(t, ok)

	c.Set(c.Now().Add(ClaimLease - time.Second))

	m.Poll(context.Background())

	assert.Equal(t, int32(0), calls.Load(), "the claim still holds")

	c.Set(c.Now().Add(2 * time.Second))

	m.Poll(context.Background())

	assert.Equal(t, int32(1), calls.Load())
	assert.True(t, store.Get(id).ProcessedAt.Valid)
}

func TestShouldRejectGrantForRevokedRecord(t *testing.T) {
	m, _, _ := newTestManager(t, true)

	id := testCreate(t, m)

	_, err := m.Revoke(context.Background(), id, "john")
	require.NoError(t, err)

	assert.ErrorIs(t, m.RecordGrant(context.Background(), model.PlusUserSessionGrant{SessionID: id, RequestID: "req1"}), ErrRecordUnavailable)
	assert.ErrorIs(t, m.RecordGrant(context.Background(), model.PlusUserSessionGrant{SessionID: uuid.New(), RequestID: "req1"}), ErrRecordUnavailable)
}

// A record holding the most grants refuses more, and the refusal is logged with the user so an administrator can see
// why their authorizations fail.
func TestShouldWarnWhenGrantCapIsHit(t *testing.T) {
	m, store, _ := newTestManager(t, true)

	logger, hook := test.NewNullLogger()
	m.SetLogger(logger)

	id := testCreate(t, m)

	store.Records[id].Grants = model.PlusUserSessionMaxGrants - 1

	require.NoError(t, m.RecordGrant(context.Background(), model.PlusUserSessionGrant{SessionID: id, RequestID: "req1"}))
	assert.Empty(t, hook.AllEntries())

	assert.ErrorIs(t, m.RecordGrant(context.Background(), model.PlusUserSessionGrant{SessionID: id, RequestID: "req2"}), ErrRecordUnavailable)

	entry := hook.LastEntry()

	require.NotNil(t, entry)
	assert.Equal(t, logrus.WarnLevel, entry.Level)
	assert.Contains(t, entry.Message, "'john'")

	hook.Reset()

	// Revoked by another instance, so this one's revoked set doesn't hold it yet.
	_, err := store.RevokePlusUserSession(context.Background(), id, "john", RevokedBySelf, time.Now())
	require.NoError(t, err)

	assert.ErrorIs(t, m.RecordGrant(context.Background(), model.PlusUserSessionGrant{SessionID: id, RequestID: "req3"}), ErrRecordUnavailable)
	assert.Empty(t, hook.AllEntries(), "a revoked record isn't full")
}

func TestShouldThrottleAndBoundActivityWrites(t *testing.T) {
	m, _, c := newTestManager(t, true)

	userSession := &session.UserSession{Username: "john", PlusID: uuid.New()}

	m.Touch(userSession, testCookie())
	m.Touch(userSession, testCookie())

	assert.Equal(t, 1, m.QueuedWrites())

	c.Set(c.Now().Add(TouchInterval))

	m.Touch(userSession, testCookie())

	assert.Equal(t, 2, m.QueuedWrites())

	for range WriteQueue * 2 {
		m.Touch(&session.UserSession{Username: "john", PlusID: uuid.New()}, testCookie())
	}

	assert.Equal(t, WriteQueue, m.QueuedWrites())
}

func TestShouldWriteActivityInRun(t *testing.T) {
	m, store, c := newTestManager(t, true)

	id := testCreate(t, m)

	c.Set(c.Now().Add(TouchInterval))

	m.Touch(&session.UserSession{Username: "john", PlusID: id, KeepMeLoggedIn: true}, testCookie())

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})

	go func() {
		m.Run(ctx)
		close(done)
	}()

	require.Eventually(t, func() bool {
		return store.Get(id).LastActive.Equal(c.Now().UTC())
	}, 5*time.Second, 10*time.Millisecond)

	assert.Equal(t, c.Now().UTC().Add(24*time.Hour), store.Get(id).ExpiresAt)

	cancel()
	<-done
}

func TestShouldRefreshWhileProcessingIsStuck(t *testing.T) {
	m, store, c := newTestManager(t, true)

	m.SetPollInterval(10 * time.Millisecond)

	stuck, release := make(chan struct{}), make(chan struct{})

	m.SetProcessor(func(_ context.Context, _ *model.PlusUserSession, _ []model.PlusUserSessionGrant) error {
		close(stuck)
		<-release

		return nil
	})

	slow, other := testCreate(t, m), testCreate(t, m)

	require.NoError(t, m.StartupCheck())

	_, err := m.Revoke(context.Background(), slow, "john")
	require.NoError(t, err)

	c.Set(c.Now().Add(ProcessDelay + time.Second))

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})

	go func() {
		m.Run(ctx)
		close(done)
	}()

	<-stuck

	// Revoked by another instance while this one's processing hangs.
	_, err = store.RevokePlusUserSession(context.Background(), other, "john", RevokedByCLI, c.Now().UTC())
	require.NoError(t, err)

	assert.Eventually(t, func() bool { return m.Revoked(other) }, 5*time.Second, 10*time.Millisecond, "the refresh doesn't wait for the processing")

	close(release)
	cancel()
	<-done
}

func TestShouldPurgeOldRecords(t *testing.T) {
	m, store, c := newTestManager(t, true)

	revoked, unprocessed, live, expired := testCreate(t, m), testCreate(t, m), testCreate(t, m), testCreate(t, m)

	for _, id := range []uuid.UUID{revoked, unprocessed} {
		_, err := m.Revoke(context.Background(), id, "john")
		require.NoError(t, err)
	}

	require.NoError(t, store.CompletePlusUserSession(context.Background(), revoked, c.Now()))

	store.Records[expired].ExpiresAt = c.Now().Add(-m.Retention() - time.Minute)
	store.Records[live].ExpiresAt = c.Now().Add(m.Retention() + time.Hour)

	c.Set(c.Now().Add(m.Retention() + time.Minute))

	m.Purge(context.Background())

	assert.Nil(t, store.Get(revoked))
	assert.Nil(t, store.Get(expired))
	assert.NotNil(t, store.Get(live))
	assert.NotNil(t, store.Get(unprocessed), "item 3: a revocation is never purged before it's processed")
}
