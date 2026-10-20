// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
)

// authelia-plus: the record of a user session, which the user can list and revoke.

// PlusUserSession is a row of the plus_user_session table. It is found from the user session data by ID, the raw
// session ID is never stored.
type PlusUserSession struct {
	ID         uuid.UUID `db:"id"`
	Username   string    `db:"username"`
	CreatedAt  time.Time `db:"created_at"`
	LastActive time.Time `db:"last_active"`
	ExpiresAt  time.Time `db:"expires_at"`
	IP         string    `db:"ip"`
	UserAgent  string    `db:"user_agent"`

	// RequestIDs is the JSON array of the OAuth 2.0 authorization requests made in the session.
	RequestIDs string `db:"request_ids"`

	// BackChannel is the JSON of the Back-Channel Logout state of the session: issuer, sid and clients.
	BackChannel string `db:"bcl_clients"`

	RevokedAt   sql.NullTime `db:"revoked_at"`
	RevokedBy   string       `db:"revoked_by"`
	ProcessedAt sql.NullTime `db:"processed_at"`
}
