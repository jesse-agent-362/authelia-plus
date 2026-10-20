// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"context"
	"time"
)

// Poll runs one refresh, then one processing, of the background work.
func (m *Manager) Poll(ctx context.Context) {
	m.refreshPoll(ctx)
	m.process(ctx, m.clock.Now().UTC())
}

// Purge runs the purge of the background work.
func (m *Manager) Purge(ctx context.Context) {
	m.purge(ctx)
}

// Backoff is the wait before retrying a revocation after attempts failed attempts.
func Backoff(attempts int) time.Duration {
	return backoff(attempts)
}

// SetPollInterval sets how often Run polls.
func (m *Manager) SetPollInterval(interval time.Duration) {
	m.interval = interval
}

// QueuedWrites is how many activity writes are waiting.
func (m *Manager) QueuedWrites() int {
	return len(m.writes)
}

// Retention is how long a revoked ID is remembered.
func (m *Manager) Retention() time.Duration {
	return m.retention
}

const (
	ClaimLease     = claimLease
	PurgeInterval  = purgeInterval
	RefreshOverlap = refreshOverlap
	ProcessTimeout = processTimeout
	RetryBase      = retryBase
	ProcessDelay   = processDelay
	TouchInterval  = touchInterval
	WriteQueue     = writeQueue
)
