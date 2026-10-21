// SPDX-FileCopyrightText: 2026 Authelia
// SPDX-FileCopyrightText: 2026 authelia-plus contributors
//
// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/authelia/authelia/v4/internal/clock"
	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/logging"
	"github.com/authelia/authelia/v4/internal/model"
	"github.com/authelia/authelia/v4/internal/session"
)

// ErrRecordUnavailable is returned when a user session record can no longer take a grant or be replaced, because it is
// missing, revoked or its revocation is being processed, or it holds model.PlusUserSessionMaxGrants grants.
var ErrRecordUnavailable = errors.New("the user session record is missing or revoked")

// New returns a Manager for the user session records in store.
func New(config *schema.Configuration, store Store, clock clock.Provider) *Manager {
	return &Manager{
		store:     store,
		clock:     clock,
		log:       logging.Logger().WithField("provider", "plus sessions"),
		memory:    config.Session.Redis == nil,
		retention: retention(config.Session) + retentionMargin,
		interval:  pollInterval,
		revoked:   map[uuid.UUID]time.Time{},
		touched:   map[uuid.UUID]time.Time{},
		writes:    make(chan activity, writeQueue),
	}
}

// Manager keeps the user session records and the set of revoked IDs.
type Manager struct {
	store     Store
	clock     clock.Provider
	log       *logrus.Entry
	memory    bool
	retention time.Duration
	processor Processor
	interval  time.Duration

	mu      sync.RWMutex
	revoked map[uuid.UUID]time.Time

	// latest is the latest revocation time seen by a refresh, and reloaded when the whole retention was last loaded.
	latest   time.Time
	reloaded time.Time

	muTouched sync.Mutex
	touched   map[uuid.UUID]time.Time
	writes    chan activity
}

type activity struct {
	id         uuid.UUID
	lastActive time.Time
	expiresAt  time.Time
}

// SetProcessor sets the side effects performed for each revoked record.
func (m *Manager) SetProcessor(processor Processor) {
	m.processor = processor
}

// StartupCheck creates the table and loads the revoked set before anything is served, so no revoked session is ever
// accepted after a restart. With the memory session provider every session died with the last process, so their
// records are closed without side effects: their OpenID Connect 1.0 grants are left alone.
func (m *Manager) StartupCheck() (err error) {
	ctx := context.Background()

	if err = m.store.PlusUserSessionsSchemaEnsure(ctx); err != nil {
		return err
	}

	if m.memory {
		var count int64

		if count, err = m.store.ClosePlusUserSessions(ctx, RevokedByRestart, m.clock.Now().UTC()); err != nil {
			return err
		}

		if count > 0 {
			m.log.Infof("Closed %d user session records as the memory session provider does not keep sessions across restarts", count)
		}
	}

	return m.refresh(ctx)
}

// Revoked reports whether the record with this ID was revoked.
func (m *Manager) Revoked(id uuid.UUID) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	_, ok := m.revoked[id]

	return ok
}

// Touch queues an activity write for the session, at most once per touchInterval. A full queue drops the write.
func (m *Manager) Touch(userSession *session.UserSession, config schema.SessionCookie) {
	now := m.clock.Now().UTC()

	m.muTouched.Lock()

	if last, ok := m.touched[userSession.PlusID]; ok && now.Sub(last) < touchInterval {
		m.muTouched.Unlock()

		return
	}

	m.touched[userSession.PlusID] = now

	m.muTouched.Unlock()

	select {
	case m.writes <- activity{id: userSession.PlusID, lastActive: now, expiresAt: now.Add(lifetime(config, userSession.KeepMeLoggedIn))}:
	default:
		m.log.Debug("Dropped a user session activity write as the queue is full")
	}
}

// Create records a new user session and returns its ID. The caller must not authenticate the session if this fails.
//
// A session already authenticated as the same user is a re-authentication: its record is replaced atomically, and its
// grants move to the new record. That fails with ErrRecordUnavailable if the record was revoked meanwhile,
// so a revoke landing at the same moment can't be escaped. A session authenticated as another user is a switch: the
// other user's record is revoked as on a logout, grants and all.
func (m *Manager) Create(ctx context.Context, username, ip, userAgent string, keepMeLoggedIn bool, config schema.SessionCookie, previous uuid.UUID, previousUsername string) (id uuid.UUID, err error) {
	if id, err = uuid.NewV7(); err != nil {
		return uuid.Nil, fmt.Errorf("error generating user session record id: %w", err)
	}

	now := m.clock.Now().UTC()

	record := model.PlusUserSession{
		ID:         id,
		Username:   username,
		CreatedAt:  now,
		LastActive: now,
		ExpiresAt:  now.Add(lifetime(config, keepMeLoggedIn)),
		IP:         truncate(ip, MaxIP),
		UserAgent:  truncate(userAgent, MaxUserAgent),
	}

	switch {
	case previous == uuid.Nil:
		err = m.store.SavePlusUserSession(ctx, record)
	case previousUsername == username:
		var ok bool

		if ok, err = m.store.ReplacePlusUserSession(ctx, previous, record, RevokedByReplace); err == nil && !ok {
			err = ErrRecordUnavailable
		}

		if err == nil {
			m.markRevoked(previous, now)
		}
	default:
		if _, err = m.revoke(ctx, previous, previousUsername, RevokedBySwitch); err == nil {
			err = m.store.SavePlusUserSession(ctx, record)
		}
	}

	if err != nil {
		return uuid.Nil, err
	}

	m.muTouched.Lock()
	m.touched[id] = now
	m.muTouched.Unlock()

	return id, nil
}

// List returns the active user session records of a user.
func (m *Manager) List(ctx context.Context, username string) (records []model.PlusUserSession, err error) {
	return m.store.LoadPlusUserSessionsActive(ctx, username, m.clock.Now().UTC())
}

// Revoke revokes the record with this ID if it is an unrevoked record of username, and reports whether it did. The
// session is rejected by this instance immediately.
func (m *Manager) Revoke(ctx context.Context, id uuid.UUID, username string) (ok bool, err error) {
	return m.revoke(ctx, id, username, RevokedBySelf)
}

// RevokeOthers revokes every session record of username but the one with the ID current, and returns how many it
// revoked and the IDs of that user's other records whose revocation is not yet processed. The sessions are rejected by
// this instance immediately.
func (m *Manager) RevokeOthers(ctx context.Context, username string, current uuid.UUID) (count int64, ids []uuid.UUID, err error) {
	now := m.clock.Now().UTC()

	if count, ids, err = m.store.RevokeOtherPlusUserSessions(ctx, username, current, RevokedBySelf, now); err != nil {
		return 0, nil, err
	}

	for _, id := range ids {
		m.markRevoked(id, now)
	}

	return count, ids, nil
}

// Grants returns the grants of the records with these IDs, for the caller of a revoke to revoke right away. That's best
// effort, as for a logout: the revocations are processed in the background as well.
func (m *Manager) Grants(ctx context.Context, ids ...uuid.UUID) (grants []model.PlusUserSessionGrant, err error) {
	for _, id := range ids {
		var g []model.PlusUserSessionGrant

		if g, err = m.store.LoadPlusUserSessionGrants(ctx, id); err != nil {
			return nil, err
		}

		grants = append(grants, g...)
	}

	return grants, nil
}

// RequestRevoked reports whether the session record holding the grant of an authorization request is revoked, read
// from the store so a revoke on any instance counts at once. A request no record holds is not revoked. A token refresh
// must be refused for a revoked one: a refresh that started before the revoke was processed could otherwise mint
// tokens the processing doesn't see.
func (m *Manager) RequestRevoked(ctx context.Context, requestID string) (revoked bool, err error) {
	var record *model.PlusUserSession

	if record, err = m.store.LoadPlusUserSessionByRequestID(ctx, requestID); err != nil || record == nil {
		return false, err
	}

	return record.RevokedAt.Valid || m.Revoked(record.ID), nil
}

// RecordGrant adds an OAuth 2.0 authorization request to the record of the session it was made in, so revoking the
// session can revoke its tokens. It returns ErrRecordUnavailable when the record is revoked or missing, in
// which case the caller must not issue the grant.
func (m *Manager) RecordGrant(ctx context.Context, grant model.PlusUserSessionGrant) (err error) {
	if m.Revoked(grant.SessionID) {
		return ErrRecordUnavailable
	}

	var ok bool

	if ok, err = m.store.SavePlusUserSessionGrant(ctx, grant); err != nil {
		return err
	}

	if !ok {
		m.warnIfFull(ctx, grant.SessionID)

		return ErrRecordUnavailable
	}

	return nil
}

// warnIfFull logs a refused grant whose record is open but holds the most grants, as that fails every authorization of
// the session until the user logs out.
func (m *Manager) warnIfFull(ctx context.Context, id uuid.UUID) {
	record, err := m.store.LoadPlusUserSession(ctx, id)
	if err != nil || record == nil || record.RevokedAt.Valid || record.Grants < model.PlusUserSessionMaxGrants {
		return
	}

	m.log.Warnf("The session of user '%s' holds the most OpenID Connect 1.0 grants a session can, %d, so its authorizations fail until the user logs out", record.Username, model.PlusUserSessionMaxGrants)
}

// End revokes the record of a session being logged out, and returns its grants for the caller to revoke right away.
// That's best effort: the revocation is processed in the background as for any other, so grants a failed or early
// revoke missed are revoked anyway. It reports false when the record is missing or its revocation was processed
// already. The session is rejected by this instance immediately.
func (m *Manager) End(ctx context.Context, id uuid.UUID, username string) (grants []model.PlusUserSessionGrant, ok bool, err error) {
	now := m.clock.Now().UTC()

	if ok, err = m.store.EndPlusUserSession(ctx, id, username, RevokedByLogout, now); err != nil || !ok {
		return nil, ok, err
	}

	m.markRevoked(id, now)

	if grants, err = m.store.LoadPlusUserSessionGrants(ctx, id); err != nil {
		return nil, false, err
	}

	return grants, true, nil
}

func (m *Manager) revoke(ctx context.Context, id uuid.UUID, username, revokedBy string) (ok bool, err error) {
	now := m.clock.Now().UTC()

	if ok, err = m.store.RevokePlusUserSession(ctx, id, username, revokedBy, now); err != nil || !ok {
		return ok, err
	}

	m.markRevoked(id, now)

	return true, nil
}

func (m *Manager) markRevoked(id uuid.UUID, now time.Time) {
	m.mu.Lock()
	m.revoked[id] = now
	m.mu.Unlock()
}

// RevokeUser revokes every session record of a user, matching the username exactly, and returns how many it revoked. It only writes the store: the
// running instances reject the sessions and process the revocations on their next poll.
func RevokeUser(ctx context.Context, store Store, username string, now time.Time) (count int64, err error) {
	if err = store.PlusUserSessionsSchemaEnsure(ctx); err != nil {
		return 0, err
	}

	return store.RevokePlusUserSessionsByUsername(ctx, username, RevokedByCLI, now.UTC())
}

// refresh adds the IDs revoked since the latest revocation it saw, less refreshOverlap, to the revoked set. Every
// purgeInterval it loads the IDs revoked within the whole retention instead, and forgets the IDs seen longer ago than
// that. A failed full reload falls back to the incremental refresh and is retried after reloadRetry, so it can never
// stop the set from learning of new revocations. On error the set is left as it was.
func (m *Manager) refresh(ctx context.Context) (err error) {
	now := m.clock.Now().UTC()

	m.mu.RLock()
	latest, full := m.latest, now.Sub(m.reloaded) >= purgeInterval
	m.mu.RUnlock()

	if full || latest.IsZero() {
		if err = m.load(ctx, now, now.Add(-m.retention), reloadTimeout, full); err == nil || latest.IsZero() {
			return err
		}

		m.log.WithError(err).Warn("Error occurred reloading every revoked user session, refreshing the recent revocations only")

		m.mu.Lock()
		m.reloaded = now.Add(reloadRetry - purgeInterval)
		m.mu.Unlock()
	}

	return m.load(ctx, now, latest.Add(-refreshOverlap), storeTimeout, false)
}

// load adds the IDs revoked since since to the revoked set. A full load, of the whole retention, also forgets the IDs
// seen longer ago than the retention.
func (m *Manager) load(ctx context.Context, now, since time.Time, timeout time.Duration, full bool) (err error) {
	lctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var revocations []model.PlusUserSessionRevocation

	if revocations, err = m.store.LoadPlusUserSessionRevocations(lctx, since); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, r := range revocations {
		if _, ok := m.revoked[r.ID]; !ok {
			m.revoked[r.ID] = now
		}

		if r.RevokedAt.After(m.latest) {
			m.latest = r.RevokedAt
		}
	}

	if full {
		m.reloaded = now

		for id, seen := range m.revoked {
			if now.Sub(seen) > m.retention {
				delete(m.revoked, id)
			}
		}
	}

	return nil
}

func lifetime(config schema.SessionCookie, keepMeLoggedIn bool) time.Duration {
	if keepMeLoggedIn && config.RememberMe > 0 {
		return config.RememberMe
	}

	return config.Expiration
}

// retention is the longest a session can live, so how long its ID must stay in the revoked set after a revoke.
func retention(config schema.Session) (longest time.Duration) {
	longest = max(config.Expiration, config.RememberMe)

	for _, c := range config.Cookies {
		longest = max(longest, c.Expiration, c.RememberMe)
	}

	return longest
}

// truncate cuts s to at most n bytes without splitting a UTF-8 sequence.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}

	return strings.ToValidUTF8(s[:n], "")
}
