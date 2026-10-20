// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// storeTimeout bounds each store operation of the background work.
const storeTimeout = 10 * time.Second

// Run writes the queued activity and polls the store until ctx is done: it refreshes the revoked set, processes new
// revocations and purges old records.
func (m *Manager) Run(ctx context.Context) {
	done := make(chan struct{})

	go func() {
		defer close(done)

		m.write(ctx)
	}()

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	var purged time.Time

	for {
		select {
		case <-ctx.Done():
			<-done
			return
		case <-ticker.C:
		}

		m.poll(ctx)

		if now := m.clock.Now(); now.Sub(purged) >= purgeInterval {
			m.purge(ctx)

			purged = now
		}
	}
}

func (m *Manager) write(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case a := <-m.writes:
			wctx, cancel := context.WithTimeout(ctx, storeTimeout)

			if err := m.store.UpdatePlusUserSessionActivity(wctx, a.id, a.lastActive, a.expiresAt); err != nil {
				m.log.WithError(err).Warn("Error occurred recording user session activity")
			}

			cancel()
		}
	}
}

func (m *Manager) poll(ctx context.Context) {
	pctx, cancel := context.WithTimeout(ctx, storeTimeout)
	defer cancel()

	if err := m.refresh(pctx); err != nil {
		m.log.WithError(err).Error("Error occurred refreshing the revoked user sessions, keeping the last known set")
	}

	now := m.clock.Now().UTC()

	m.muTouched.Lock()

	for id, last := range m.touched {
		if now.Sub(last) >= touchInterval {
			delete(m.touched, id)
		}
	}

	m.muTouched.Unlock()

	m.process(ctx, now)
}

// process performs the side effects of the revocations older than processDelay. Each record is claimed first, so with
// several instances one processes it at a time; a failed one is released again to be retried on the next poll, and
// one whose instance stopped mid-processing is taken over once its claim is older than claimLease.
func (m *Manager) process(ctx context.Context, now time.Time) {
	pctx, cancel := context.WithTimeout(ctx, storeTimeout)
	defer cancel()

	ids, err := m.store.LoadPlusUserSessionUnprocessedIDs(pctx, now.Add(-processDelay), now.Add(-claimLease), processBatch)
	if err != nil {
		m.log.WithError(err).Error("Error occurred loading the revoked user sessions to process")

		return
	}

	for _, id := range ids {
		m.processOne(ctx, id, now)
	}
}

func (m *Manager) processOne(ctx context.Context, id uuid.UUID, now time.Time) {
	pctx, cancel := context.WithTimeout(ctx, storeTimeout)
	defer cancel()

	if ok, err := m.store.ClaimPlusUserSession(pctx, id, now, now.Add(-claimLease)); err != nil || !ok {
		if err != nil {
			m.log.WithError(err).Errorf("Error occurred claiming the revoked user session '%s'", id)
		}

		return
	}

	// Loaded after the claim: the claim stops any further grant being added, so this is every grant of the session.
	record, err := m.store.LoadPlusUserSession(pctx, id)
	if err != nil || record == nil {
		m.log.WithError(err).Errorf("Error occurred loading the revoked user session '%s', it will be retried", id)

		m.unclaim(id)

		return
	}

	grants, err := m.store.LoadPlusUserSessionGrants(pctx, id)
	if err != nil {
		m.log.WithError(err).Errorf("Error occurred loading the grants of the revoked user session '%s', it will be retried", id)

		m.unclaim(id)

		return
	}

	if m.processor != nil {
		if err = m.processor(ctx, record, grants); err != nil {
			m.log.WithError(err).Errorf("Error occurred revoking the OpenID Connect 1.0 grants of the revoked user session '%s', it will be retried", id)

			m.unclaim(id)

			return
		}
	}

	// Detached from ctx, which is done at shutdown: a revocation processed then is still marked so. Should this fail,
	// the claim lapses and the revocation is processed again, which is harmless.
	cctx, ccancel := context.WithTimeout(context.Background(), storeTimeout)
	defer ccancel()

	if err = m.store.CompletePlusUserSession(cctx, id, m.clock.Now().UTC()); err != nil {
		m.log.WithError(err).Errorf("Error occurred marking the revoked user session '%s' as processed, it will be processed again", id)

		return
	}

	m.log.Debugf("Processed the revocation of the user session '%s' of user '%s'", id, record.Username)
}

// unclaim releases a claim for the next poll to retry. It's detached from ctx, which is done at shutdown; should it
// fail anyway, the claim lapses after claimLease.
func (m *Manager) unclaim(id uuid.UUID) {
	uctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
	defer cancel()

	if err := m.store.UnclaimPlusUserSession(uctx, id); err != nil {
		m.log.WithError(err).Errorf("Error occurred releasing the revoked user session '%s' for a retry", id)
	}
}

// purge deletes the records nothing needs any more: revoked ones past the retention, and unrevoked ones past the
// retention after their expiry, which a lagging activity write can't have hidden a live session behind.
func (m *Manager) purge(ctx context.Context) {
	pctx, cancel := context.WithTimeout(ctx, storeTimeout)
	defer cancel()

	cutoff := m.clock.Now().UTC().Add(-m.retention)

	if err := m.store.PurgePlusUserSessions(pctx, cutoff, cutoff); err != nil {
		m.log.WithError(err).Warn("Error occurred purging old user session records")
	}
}
