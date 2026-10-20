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

	// Grants counts the rows of plus_user_session_grant ever added for the session. Adding one updates it, which locks
	// the record against a concurrent claim.
	Grants int `db:"grants"`

	RevokedAt   sql.NullTime `db:"revoked_at"`
	RevokedBy   string       `db:"revoked_by"`
	ProcessedAt sql.NullTime `db:"processed_at"`
}

// PlusUserSessionGrant is a row of the plus_user_session_grant table: an OAuth 2.0 authorization request made in a user
// session. Rows are only ever inserted, so concurrent authorizations can't lose each other's grants.
type PlusUserSessionGrant struct {
	SessionID uuid.UUID `db:"session_id"`
	RequestID string    `db:"request_id"`

	// ClientID, Subject, SID and Issuer are set when the client has a Back-Channel Logout URI: they're what its
	// Logout Token is built from.
	ClientID string `db:"client_id"`
	Subject  string `db:"subject"`
	SID      string `db:"sid"`
	Issuer   string `db:"issuer"`
}
