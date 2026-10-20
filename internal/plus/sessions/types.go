// SPDX-FileCopyrightText: 2026 Authelia
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
	LoadPlusUserSession(ctx context.Context, id uuid.UUID) (s *model.PlusUserSession, err error)
	LoadPlusUserSessionsActive(ctx context.Context, username string, now time.Time) (sessions []model.PlusUserSession, err error)
	UpdatePlusUserSessionActivity(ctx context.Context, id uuid.UUID, lastActive, expiresAt time.Time) (err error)
	UpdatePlusUserSessionOpenIDConnect(ctx context.Context, id uuid.UUID, requestIDs, backChannel string) (ok bool, err error)
	RevokePlusUserSession(ctx context.Context, id uuid.UUID, username, revokedBy string, now time.Time) (ok bool, err error)
	RevokePlusUserSessionsByUsername(ctx context.Context, username, revokedBy string, now time.Time) (count int64, err error)
	ClosePlusUserSessions(ctx context.Context, revokedBy string, now time.Time) (count int64, err error)
	ClosePlusUserSession(ctx context.Context, id uuid.UUID, revokedBy string, now time.Time) (err error)
	LoadPlusUserSessionRevokedIDs(ctx context.Context, since time.Time) (ids []uuid.UUID, err error)
	LoadPlusUserSessionUnprocessedIDs(ctx context.Context, before time.Time, limit int) (ids []uuid.UUID, err error)
	ClaimPlusUserSession(ctx context.Context, id uuid.UUID, now time.Time) (ok bool, err error)
	UnclaimPlusUserSession(ctx context.Context, id uuid.UUID) (err error)
	PurgePlusUserSessions(ctx context.Context, revokedBefore, expiredBefore time.Time) (err error)
}

// Processor performs the side effects of a revoked user session record: revoking its OpenID Connect 1.0 grants and
// sending its Back-Channel Logout tokens. An error means the grants may not have been revoked, and the record is
// retried.
type Processor func(ctx context.Context, record *model.PlusUserSession, state *OpenIDConnectState) (err error)

// OpenIDConnectState is the OpenID Connect 1.0 state of a user session record.
type OpenIDConnectState struct {
	// RequestIDs are the authorization requests made in the session.
	RequestIDs []string

	// Issuer is the issuer the Back-Channel Logout clients were issued ID Tokens by.
	Issuer string `json:",omitempty"`

	// SessionID is the 'sid' claim issued to the Back-Channel Logout clients.
	SessionID string `json:",omitempty"`

	// Clients are the Back-Channel Logout clients.
	Clients []OpenIDConnectClient `json:",omitempty"`
}

// OpenIDConnectClient is a Back-Channel Logout client and the subject its ID Tokens were issued for.
type OpenIDConnectClient struct {
	ClientID string
	Subject  string
}

// Who revoked a user session record.
const (
	RevokedBySelf    = "self"
	RevokedByCLI     = "cli"
	RevokedByRestart = "restart"
	RevokedByReplace = "replaced"
)

const (
	// pollInterval is how often the revoked set is refreshed from the store and revocations are processed.
	pollInterval = 10 * time.Second

	// processDelay is how long a revocation waits before it's processed. Every instance has stopped accepting the
	// session by then, so no authorization in flight can still add a grant after the grants were revoked.
	processDelay = 3 * pollInterval

	// processBatch bounds the revocations processed per poll.
	processBatch = 100

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
