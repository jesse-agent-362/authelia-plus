// SPDX-FileCopyrightText: 2026 authelia-plus contributors
//
// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/authelia/authelia/v4/internal/model"
)

// Store is the storage of the user session records. The SQL storage providers implement it.
type Store interface {
	PlusUserSessionsSchemaEnsure(ctx context.Context) (err error)
	SavePlusUserSession(ctx context.Context, s model.PlusUserSession) (err error)
	ReplacePlusUserSession(ctx context.Context, previous uuid.UUID, s model.PlusUserSession, revokedBy string) (ok bool, err error)
	LoadPlusUserSession(ctx context.Context, id uuid.UUID) (s *model.PlusUserSession, err error)
	LoadPlusUserSessionsActive(ctx context.Context, username string, now time.Time) (sessions []model.PlusUserSession, err error)
	UpdatePlusUserSessionActivity(ctx context.Context, id uuid.UUID, lastActive, expiresAt time.Time) (ok bool, err error)
	LoadPlusUserSessionByRequestID(ctx context.Context, requestID string) (s *model.PlusUserSession, err error)
	SavePlusUserSessionGrant(ctx context.Context, grant model.PlusUserSessionGrant) (ok bool, err error)
	LoadPlusUserSessionGrants(ctx context.Context, id uuid.UUID) (grants []model.PlusUserSessionGrant, err error)
	RevokePlusUserSession(ctx context.Context, id uuid.UUID, username, revokedBy string, now time.Time) (ok bool, err error)
	RevokePlusUserSessionsByUsername(ctx context.Context, username, revokedBy string, now time.Time) (count int64, err error)
	ClosePlusUserSessions(ctx context.Context, revokedBy string, now time.Time) (count int64, err error)
	EndPlusUserSession(ctx context.Context, id uuid.UUID, username, revokedBy string, now time.Time) (ok bool, err error)
	RevokeOtherPlusUserSessions(ctx context.Context, username string, except uuid.UUID, revokedBy string, now time.Time) (count int64, ids []uuid.UUID, err error)
	LoadPlusUserSessionRevocations(ctx context.Context, since time.Time) (revocations []model.PlusUserSessionRevocation, err error)
	LoadPlusUserSessionUnprocessedIDs(ctx context.Context, before, leaseBefore, now time.Time, limit int) (ids []uuid.UUID, err error)
	ClaimPlusUserSession(ctx context.Context, id uuid.UUID, now, leaseBefore time.Time) (ok bool, err error)
	CompletePlusUserSession(ctx context.Context, id uuid.UUID, now time.Time) (err error)
	UnclaimPlusUserSession(ctx context.Context, id uuid.UUID, retryAt time.Time) (err error)
	PurgePlusUserSessions(ctx context.Context, revokedBefore, expiredBefore time.Time) (err error)
}

// Processor performs the side effects of a revoked user session record: revoking its OpenID Connect 1.0 grants and
// sending its Back-Channel Logout tokens. An error means the grants may not have been revoked, and the record is
// retried.
type Processor func(ctx context.Context, record *model.PlusUserSession, grants []model.PlusUserSessionGrant) (err error)

// Who revoked a user session record.
const (
	RevokedBySelf    = "self"
	RevokedByCLI     = "cli"
	RevokedByRestart = "restart"
	RevokedByReplace = "replaced"
	RevokedByLogout  = "logout"
	RevokedBySwitch  = "switched"
)

const (
	// pollInterval is how often the revoked set is refreshed from the store, and how often revocations are processed.
	// Each runs on its own, so a slow processing never delays a refresh.
	pollInterval = 10 * time.Second

	// refreshOverlap is how far before the latest revocation seen a refresh starts. It covers a revocation committed
	// late or stamped by a clock behind this one; every purgeInterval the whole retention is reloaded anyway. Instances
	// sharing a store need their clocks synchronized, with NTP or the like, to well within this.
	refreshOverlap = 5 * time.Minute

	// reloadTimeout bounds the full reload of the revoked set, which loads the whole retention.
	reloadTimeout = time.Minute

	// reloadRetry is how long after a failed full reload it's tried again; the incremental refresh runs meanwhile.
	reloadRetry = 5 * time.Minute

	// processDelay is how long a revocation waits before it's processed. Every instance has stopped accepting the
	// session by then, so no authorization in flight can still add a grant after the grants were revoked.
	processDelay = 3 * pollInterval

	// claimLease is how long a claim on a revocation holds. A claim older than this is taken over by the next poll,
	// so a revocation whose instance died or shut down mid-processing is still processed.
	claimLease = 5 * time.Minute

	// processBatch bounds the revocations processed per poll.
	processBatch = 100

	// processTimeout bounds the side effects of one revocation, well within claimLease, so a stuck one can't hold up the
	// others nor be taken over while it still runs.
	processTimeout = time.Minute

	// retryBase is the wait before the first retry of a failed revocation; it doubles with each attempt up to retryMax.
	retryBase = processDelay
	retryMax  = time.Hour

	// purgeInterval is how often old records are deleted.
	purgeInterval = time.Hour

	// touchInterval is the least time between two activity writes for a session.
	touchInterval = 5 * time.Minute

	// retentionMargin is added to the longest session lifetime to get how long a revoked ID must be remembered.
	retentionMargin = touchInterval + time.Hour

	// writeQueue bounds the activity writes waiting for the store; writes beyond it are dropped.
	writeQueue = 256

	// MaxUserAgent is the most bytes of the User-Agent that are recorded.
	MaxUserAgent = 512

	// MaxIP is the most bytes of the remote IP that are recorded.
	MaxIP = 64
)
