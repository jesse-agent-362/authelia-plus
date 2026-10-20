// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
)

// storeTimeout bounds each store operation of the background work.
const storeTimeout = 10 * time.Second

// Run writes the queued activity and polls the store until ctx is done: it refreshes the revoked set, processes new
// revocations and purges old records. The refresh runs apart from the rest, so slow processing can't delay it.
func (m *Manager) Run(ctx context.Context) {
	var wg sync.WaitGroup

	wg.Go(func() { m.write(ctx) })
	wg.Go(func() { m.every(ctx, m.refreshPoll) })

	var purged time.Time

	m.every(ctx, func(ctx context.Context) {
		m.process(ctx, m.clock.Now().UTC())

		if now := m.clock.Now(); now.Sub(purged) >= purgeInterval {
			m.purge(ctx)

			purged = now
		}
	})

	wg.Wait()
}

// every runs fn each poll interval until ctx is done.
func (m *Manager) every(ctx context.Context, fn func(ctx context.Context)) {
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fn(ctx)
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

// refreshPoll refreshes the revoked set and forgets the activity writes older than touchInterval.
func (m *Manager) refreshPoll(ctx context.Context) {
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
}

// process performs the side effects of the revocations older than processDelay. Each record is claimed first, so with
// several instances one processes it at a time; a failed one is released again to be retried after a backoff, and
// one whose instance stopped mid-processing is taken over once its claim is older than claimLease.
func (m *Manager) process(ctx context.Context, now time.Time) {
	pctx, cancel := context.WithTimeout(ctx, storeTimeout)
	defer cancel()

	ids, err := m.store.LoadPlusUserSessionUnprocessedIDs(pctx, now.Add(-processDelay), now.Add(-claimLease), now, processBatch)
	if err != nil {
		m.log.WithError(err).Error("Error occurred loading the revoked user sessions to process")

		return
	}

	for _, id := range ids {
		m.processOne(ctx, id)
	}
}

// processOne claims and processes one revocation. The claim is stamped when it's taken, not when the poll started:
// a batch can run for longer than claimLease, and a claim stamped that late would be taken over while it's processed.
func (m *Manager) processOne(ctx context.Context, id uuid.UUID) {
	pctx, cancel := context.WithTimeout(ctx, storeTimeout)
	defer cancel()

	now := m.clock.Now().UTC()

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

		m.unclaim(id, 1)

		return
	}

	grants, err := m.store.LoadPlusUserSessionGrants(pctx, id)
	if err != nil {
		m.log.WithError(err).Errorf("Error occurred loading the grants of the revoked user session '%s', it will be retried", id)

		m.unclaim(id, record.Attempts)

		return
	}

	if m.processor != nil {
		xctx, xcancel := context.WithTimeout(ctx, processTimeout)

		err = m.processor(xctx, record, grants)

		xcancel()

		if err != nil {
			m.log.WithError(err).Errorf("Error occurred revoking the OpenID Connect 1.0 grants of the revoked user session '%s', it will be retried", id)

			m.unclaim(id, record.Attempts)

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

// unclaim releases a claim to be retried after the backoff for the attempts made. It's detached from ctx, which is
// done at shutdown; should it fail anyway, the claim lapses after claimLease.
func (m *Manager) unclaim(id uuid.UUID, attempts int) {
	uctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
	defer cancel()

	if err := m.store.UnclaimPlusUserSession(uctx, id, m.clock.Now().UTC().Add(backoff(attempts))); err != nil {
		m.log.WithError(err).Errorf("Error occurred releasing the revoked user session '%s' for a retry", id)
	}
}

// backoff is the wait before retrying a revocation after attempts failed attempts.
func backoff(attempts int) time.Duration {
	wait := retryBase

	for i := 1; i < attempts && wait < retryMax; i++ {
		wait *= 2
	}

	return min(wait, retryMax)
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
