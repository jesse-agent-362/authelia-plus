// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"context"
	"time"
)

// Poll runs one poll of the background work.
func (m *Manager) Poll(ctx context.Context) {
	m.poll(ctx)
}

// Purge runs the purge of the background work.
func (m *Manager) Purge(ctx context.Context) {
	m.purge(ctx)
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
	ProcessDelay  = processDelay
	TouchInterval = touchInterval
	WriteQueue    = writeQueue
)
