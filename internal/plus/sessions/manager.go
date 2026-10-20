// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"context"
	"encoding/json"
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

// ErrRecordUnavailable is returned when a user session record can no longer take OpenID Connect 1.0 state, because it
// is missing or its revocation is being processed.
var ErrRecordUnavailable = errors.New("the user session record is missing or revoked")

// New returns a Manager for the user session records in store.
func New(config *schema.Configuration, store Store, clock clock.Provider) *Manager {
	return &Manager{
		store:     store,
		clock:     clock,
		log:       logging.Logger().WithField("provider", "plus sessions"),
		memory:    config.Session.Redis == nil,
		retention: retention(config.Session) + retentionMargin,
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

	mu      sync.RWMutex
	revoked map[uuid.UUID]time.Time

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
// The OpenID Connect 1.0 state of the session, if any, moves to the new record, and the previous record, if any, is
// closed without side effects: its session is the one being replaced.
func (m *Manager) Create(ctx context.Context, username, ip, userAgent string, keepMeLoggedIn bool, config schema.SessionCookie, issuer string, previous uuid.UUID, logout *session.OpenIDConnectLogout) (id uuid.UUID, err error) {
	if id, err = uuid.NewV7(); err != nil {
		return uuid.Nil, fmt.Errorf("error generating user session record id: %w", err)
	}

	now := m.clock.Now().UTC()

	if err = m.store.SavePlusUserSession(ctx, model.PlusUserSession{
		ID:          id,
		Username:    username,
		CreatedAt:   now,
		LastActive:  now,
		ExpiresAt:   now.Add(lifetime(config, keepMeLoggedIn)),
		IP:          truncate(ip, MaxIP),
		UserAgent:   truncate(userAgent, MaxUserAgent),
		RequestIDs:  "[]",
		BackChannel: "{}",
	}); err != nil {
		return uuid.Nil, err
	}

	m.muTouched.Lock()
	m.touched[id] = now
	m.muTouched.Unlock()

	if logout != nil {
		if err = m.RecordOpenIDConnect(ctx, id, issuer, logout); err != nil {
			return uuid.Nil, err
		}
	}

	if previous != uuid.Nil {
		if err = m.store.ClosePlusUserSession(ctx, previous, RevokedByReplace, now); err != nil {
			return uuid.Nil, err
		}
	}

	return id, nil
}

// List returns the active user session records of a user.
func (m *Manager) List(ctx context.Context, username string) (records []model.PlusUserSession, err error) {
	return m.store.LoadPlusUserSessionsActive(ctx, username, m.clock.Now().UTC())
}

// Revoke revokes the record with this ID if it is an unrevoked record of username, and reports whether it did. The
// session is rejected by this instance immediately.
func (m *Manager) Revoke(ctx context.Context, id uuid.UUID, username string) (ok bool, err error) {
	now := m.clock.Now().UTC()

	if ok, err = m.store.RevokePlusUserSession(ctx, id, username, RevokedBySelf, now); err != nil || !ok {
		return ok, err
	}

	m.mu.Lock()
	m.revoked[id] = now
	m.mu.Unlock()

	return true, nil
}

// RecordOpenIDConnect mirrors the OpenID Connect 1.0 logout state of the session onto its record, so its grants can be
// revoked without the session. It returns ErrRecordUnavailable when the record is revoked or missing, in which case
// the caller must not issue the grant.
func (m *Manager) RecordOpenIDConnect(ctx context.Context, id uuid.UUID, issuer string, logout *session.OpenIDConnectLogout) (err error) {
	if m.Revoked(id) {
		return ErrRecordUnavailable
	}

	state := OpenIDConnectState{RequestIDs: logout.RequestIDs, SessionID: logout.SessionID}

	if state.RequestIDs == nil {
		state.RequestIDs = []string{}
	}

	if len(logout.Clients) != 0 {
		state.Issuer = issuer

		for _, c := range logout.Clients {
			state.Clients = append(state.Clients, OpenIDConnectClient{ClientID: c.ClientID, Subject: c.Subject})
		}
	}

	var requestIDs, backChannel []byte

	if requestIDs, err = json.Marshal(state.RequestIDs); err != nil {
		return err
	}

	state.RequestIDs = nil

	if backChannel, err = json.Marshal(state); err != nil {
		return err
	}

	var ok bool

	if ok, err = m.store.UpdatePlusUserSessionOpenIDConnect(ctx, id, string(requestIDs), string(backChannel)); err != nil {
		return err
	}

	if !ok {
		return ErrRecordUnavailable
	}

	return nil
}

// RevokeUser revokes every session record of a user, and returns how many it revoked. It only writes the store: the
// running instances reject the sessions and process the revocations on their next poll.
func RevokeUser(ctx context.Context, store Store, username string, now time.Time) (count int64, err error) {
	if err = store.PlusUserSessionsSchemaEnsure(ctx); err != nil {
		return 0, err
	}

	return store.RevokePlusUserSessionsByUsername(ctx, username, RevokedByCLI, now.UTC())
}

// refresh adds the IDs revoked within the retention to the revoked set, and forgets the IDs seen longer ago than
// that. On error the set is left as it was.
func (m *Manager) refresh(ctx context.Context) (err error) {
	now := m.clock.Now().UTC()

	var ids []uuid.UUID

	if ids, err = m.store.LoadPlusUserSessionRevokedIDs(ctx, now.Add(-m.retention)); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, id := range ids {
		if _, ok := m.revoked[id]; !ok {
			m.revoked[id] = now
		}
	}

	for id, seen := range m.revoked {
		if now.Sub(seen) > m.retention {
			delete(m.revoked, id)
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
