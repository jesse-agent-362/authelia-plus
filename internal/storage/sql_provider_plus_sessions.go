// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/authelia/authelia/v4/internal/model"
)

// authelia-plus: the plus_user_session table behind the session list and revoke.
//
// The table is created at startup rather than by a numbered migration, so it can't collide with upstream's migration
// numbers. These methods are deliberately not part of the Provider interface; the plus code reaches them by type
// assertion.

const tablePlusUserSession = "plus_user_session"

const (
	queryPlusUserSessionCreateSQLite = `
CREATE TABLE IF NOT EXISTS plus_user_session (
    id CHAR(36) NOT NULL PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    created_at DATETIME NOT NULL,
    last_active DATETIME NOT NULL,
    expires_at DATETIME NOT NULL,
    ip VARCHAR(64) NOT NULL,
    user_agent VARCHAR(512) NOT NULL,
    request_ids TEXT NOT NULL,
    bcl_clients TEXT NOT NULL,
    revoked_at DATETIME NULL DEFAULT NULL,
    revoked_by VARCHAR(100) NOT NULL DEFAULT '',
    processed_at DATETIME NULL DEFAULT NULL
);`

	queryPlusUserSessionCreatePostgreSQL = `
CREATE TABLE IF NOT EXISTS plus_user_session (
    id CHAR(36) NOT NULL CONSTRAINT plus_user_session_pkey PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_active TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    ip VARCHAR(64) NOT NULL,
    user_agent VARCHAR(512) NOT NULL,
    request_ids TEXT NOT NULL,
    bcl_clients TEXT NOT NULL,
    revoked_at TIMESTAMP WITH TIME ZONE NULL DEFAULT NULL,
    revoked_by VARCHAR(100) NOT NULL DEFAULT '',
    processed_at TIMESTAMP WITH TIME ZONE NULL DEFAULT NULL
);`

	queryPlusUserSessionCreateMySQL = `
CREATE TABLE IF NOT EXISTS plus_user_session (
    id CHAR(36) NOT NULL PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    created_at TIMESTAMP NOT NULL,
    last_active TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    ip VARCHAR(64) NOT NULL,
    user_agent VARCHAR(512) NOT NULL,
    request_ids TEXT NOT NULL,
    bcl_clients TEXT NOT NULL,
    revoked_at TIMESTAMP NULL DEFAULT NULL,
    revoked_by VARCHAR(100) NOT NULL DEFAULT '',
    processed_at TIMESTAMP NULL DEFAULT NULL,
    INDEX plus_user_session_username (username),
    INDEX plus_user_session_revoked_at (revoked_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;`

	queryPlusUserSessionCreateIndexUsername  = `CREATE INDEX IF NOT EXISTS plus_user_session_username ON plus_user_session (username);`
	queryPlusUserSessionCreateIndexRevokedAt = `CREATE INDEX IF NOT EXISTS plus_user_session_revoked_at ON plus_user_session (revoked_at);`

	queryPlusUserSessionColumns = `id, username, created_at, last_active, expires_at, ip, user_agent, request_ids, bcl_clients, revoked_at, revoked_by, processed_at`

	queryPlusUserSessionInsert = `
INSERT INTO plus_user_session (id, username, created_at, last_active, expires_at, ip, user_agent, request_ids, bcl_clients)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);`

	queryPlusUserSessionSelectByID = `SELECT ` + queryPlusUserSessionColumns + ` FROM plus_user_session WHERE id = ?;`

	queryPlusUserSessionSelectActiveByUsername = `
SELECT ` + queryPlusUserSessionColumns + `
FROM plus_user_session
WHERE username = ? AND revoked_at IS NULL AND expires_at > ?
ORDER BY last_active DESC;`

	queryPlusUserSessionUpdateActivity = `
UPDATE plus_user_session
SET last_active = ?, expires_at = ?
WHERE id = ? AND revoked_at IS NULL;`

	queryPlusUserSessionUpdateOpenIDConnect = `
UPDATE plus_user_session
SET request_ids = ?, bcl_clients = ?
WHERE id = ? AND processed_at IS NULL;`

	queryPlusUserSessionRevoke = `
UPDATE plus_user_session
SET revoked_at = ?, revoked_by = ?
WHERE id = ? AND username = ? AND revoked_at IS NULL;`

	queryPlusUserSessionRevokeByUsername = `
UPDATE plus_user_session
SET revoked_at = ?, revoked_by = ?
WHERE LOWER(username) = LOWER(?) AND revoked_at IS NULL;`

	queryPlusUserSessionClose = `
UPDATE plus_user_session
SET revoked_at = ?, revoked_by = ?, processed_at = ?
WHERE revoked_at IS NULL;`

	queryPlusUserSessionCloseByID = `
UPDATE plus_user_session
SET revoked_at = ?, revoked_by = ?, processed_at = ?
WHERE id = ? AND revoked_at IS NULL;`

	queryPlusUserSessionSelectRevokedIDs = `SELECT id FROM plus_user_session WHERE revoked_at IS NOT NULL AND revoked_at > ?;`

	queryPlusUserSessionSelectUnprocessedIDs = `
SELECT id
FROM plus_user_session
WHERE revoked_at IS NOT NULL AND revoked_at <= ? AND processed_at IS NULL
ORDER BY revoked_at
LIMIT ?;`

	queryPlusUserSessionClaim = `UPDATE plus_user_session SET processed_at = ? WHERE id = ? AND processed_at IS NULL;`

	queryPlusUserSessionUnclaim = `UPDATE plus_user_session SET processed_at = NULL WHERE id = ?;`

	queryPlusUserSessionPurge = `
DELETE FROM plus_user_session
WHERE (revoked_at IS NOT NULL AND revoked_at < ?) OR (revoked_at IS NULL AND expires_at < ?);`
)

// PlusUserSessionsSchemaEnsure creates the plus_user_session table and its indexes if they don't exist.
func (p *SQLProvider) PlusUserSessionsSchemaEnsure(ctx context.Context) (err error) {
	var queries []string

	switch p.name {
	case providerMySQL:
		queries = []string{queryPlusUserSessionCreateMySQL}
	case providerPostgres:
		queries = []string{queryPlusUserSessionCreatePostgreSQL, queryPlusUserSessionCreateIndexUsername, queryPlusUserSessionCreateIndexRevokedAt}
	default:
		queries = []string{queryPlusUserSessionCreateSQLite, queryPlusUserSessionCreateIndexUsername, queryPlusUserSessionCreateIndexRevokedAt}
	}

	for _, query := range queries {
		if _, err = p.db.ExecContext(ctx, query); err != nil {
			return fmt.Errorf("error creating the %s table: %w", tablePlusUserSession, err)
		}
	}

	return nil
}

// SavePlusUserSession inserts a user session record.
func (p *SQLProvider) SavePlusUserSession(ctx context.Context, s model.PlusUserSession) (err error) {
	if _, err = p.db.ExecContext(ctx, p.db.Rebind(queryPlusUserSessionInsert),
		s.ID, s.Username, s.CreatedAt, s.LastActive, s.ExpiresAt, s.IP, s.UserAgent, s.RequestIDs, s.BackChannel); err != nil {
		return fmt.Errorf("error inserting user session record for user '%s': %w", s.Username, err)
	}

	return nil
}

// LoadPlusUserSession loads a user session record by ID. It returns nil when there is none.
func (p *SQLProvider) LoadPlusUserSession(ctx context.Context, id uuid.UUID) (s *model.PlusUserSession, err error) {
	s = &model.PlusUserSession{}

	if err = p.db.GetContext(ctx, s, p.db.Rebind(queryPlusUserSessionSelectByID), id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}

		return nil, fmt.Errorf("error selecting user session record '%s': %w", id, err)
	}

	return s, nil
}

// LoadPlusUserSessionsActive loads the unrevoked, unexpired user session records of a user, most recently active first.
func (p *SQLProvider) LoadPlusUserSessionsActive(ctx context.Context, username string, now time.Time) (sessions []model.PlusUserSession, err error) {
	if err = p.db.SelectContext(ctx, &sessions, p.db.Rebind(queryPlusUserSessionSelectActiveByUsername), username, now); err != nil {
		return nil, fmt.Errorf("error selecting user session records for user '%s': %w", username, err)
	}

	return sessions, nil
}

// UpdatePlusUserSessionActivity records the last activity and expiration of an unrevoked user session record.
func (p *SQLProvider) UpdatePlusUserSessionActivity(ctx context.Context, id uuid.UUID, lastActive, expiresAt time.Time) (err error) {
	if _, err = p.db.ExecContext(ctx, p.db.Rebind(queryPlusUserSessionUpdateActivity), lastActive, expiresAt, id); err != nil {
		return fmt.Errorf("error updating activity of user session record '%s': %w", id, err)
	}

	return nil
}

// UpdatePlusUserSessionOpenIDConnect records the OpenID Connect 1.0 state of a user session record. It reports false
// when the record is missing or its revocation is already being processed, as the state would then never be acted on.
func (p *SQLProvider) UpdatePlusUserSessionOpenIDConnect(ctx context.Context, id uuid.UUID, requestIDs, backChannel string) (ok bool, err error) {
	var result sql.Result

	if result, err = p.db.ExecContext(ctx, p.db.Rebind(queryPlusUserSessionUpdateOpenIDConnect), requestIDs, backChannel, id); err != nil {
		return false, fmt.Errorf("error updating openid connect state of user session record '%s': %w", id, err)
	}

	return plusRowsAffected(result)
}

// RevokePlusUserSession revokes a user session record if it belongs to username and is not already revoked. It reports
// false otherwise, without telling those cases apart.
func (p *SQLProvider) RevokePlusUserSession(ctx context.Context, id uuid.UUID, username, revokedBy string, now time.Time) (ok bool, err error) {
	var result sql.Result

	if result, err = p.db.ExecContext(ctx, p.db.Rebind(queryPlusUserSessionRevoke), now, revokedBy, id, username); err != nil {
		return false, fmt.Errorf("error revoking user session record '%s': %w", id, err)
	}

	return plusRowsAffected(result)
}

// RevokePlusUserSessionsByUsername revokes every unrevoked user session record of a user, matching the username case
// insensitively, and returns how many were revoked.
func (p *SQLProvider) RevokePlusUserSessionsByUsername(ctx context.Context, username, revokedBy string, now time.Time) (count int64, err error) {
	var result sql.Result

	if result, err = p.db.ExecContext(ctx, p.db.Rebind(queryPlusUserSessionRevokeByUsername), now, revokedBy, username); err != nil {
		return 0, fmt.Errorf("error revoking user session records of user '%s': %w", username, err)
	}

	return result.RowsAffected()
}

// ClosePlusUserSessions revokes every unrevoked user session record and marks it processed, so the revocation has no
// side effects. It returns how many were closed.
func (p *SQLProvider) ClosePlusUserSessions(ctx context.Context, revokedBy string, now time.Time) (count int64, err error) {
	var result sql.Result

	if result, err = p.db.ExecContext(ctx, p.db.Rebind(queryPlusUserSessionClose), now, revokedBy, now); err != nil {
		return 0, fmt.Errorf("error closing user session records: %w", err)
	}

	return result.RowsAffected()
}

// ClosePlusUserSession revokes a user session record and marks it processed, so the revocation has no side effects.
func (p *SQLProvider) ClosePlusUserSession(ctx context.Context, id uuid.UUID, revokedBy string, now time.Time) (err error) {
	if _, err = p.db.ExecContext(ctx, p.db.Rebind(queryPlusUserSessionCloseByID), now, revokedBy, now, id); err != nil {
		return fmt.Errorf("error closing user session record '%s': %w", id, err)
	}

	return nil
}

// LoadPlusUserSessionRevokedIDs loads the IDs of the user session records revoked after since.
func (p *SQLProvider) LoadPlusUserSessionRevokedIDs(ctx context.Context, since time.Time) (ids []uuid.UUID, err error) {
	if err = p.db.SelectContext(ctx, &ids, p.db.Rebind(queryPlusUserSessionSelectRevokedIDs), since); err != nil {
		return nil, fmt.Errorf("error selecting revoked user session records: %w", err)
	}

	return ids, nil
}

// LoadPlusUserSessionUnprocessedIDs loads up to limit IDs of the user session records revoked no later than before
// whose revocation has not been processed, oldest revocation first.
func (p *SQLProvider) LoadPlusUserSessionUnprocessedIDs(ctx context.Context, before time.Time, limit int) (ids []uuid.UUID, err error) {
	if err = p.db.SelectContext(ctx, &ids, p.db.Rebind(queryPlusUserSessionSelectUnprocessedIDs), before, limit); err != nil {
		return nil, fmt.Errorf("error selecting unprocessed user session records: %w", err)
	}

	return ids, nil
}

// ClaimPlusUserSession marks the revocation of a user session record as processed. It reports false when another
// instance already did, in which case the caller must not process it.
func (p *SQLProvider) ClaimPlusUserSession(ctx context.Context, id uuid.UUID, now time.Time) (ok bool, err error) {
	var result sql.Result

	if result, err = p.db.ExecContext(ctx, p.db.Rebind(queryPlusUserSessionClaim), now, id); err != nil {
		return false, fmt.Errorf("error claiming user session record '%s': %w", id, err)
	}

	return plusRowsAffected(result)
}

// UnclaimPlusUserSession marks the revocation of a user session record as unprocessed again, so it's retried.
func (p *SQLProvider) UnclaimPlusUserSession(ctx context.Context, id uuid.UUID) (err error) {
	if _, err = p.db.ExecContext(ctx, p.db.Rebind(queryPlusUserSessionUnclaim), id); err != nil {
		return fmt.Errorf("error unclaiming user session record '%s': %w", id, err)
	}

	return nil
}

// PurgePlusUserSessions deletes the user session records revoked before revokedBefore, and the unrevoked ones which
// expired before expiredBefore.
func (p *SQLProvider) PurgePlusUserSessions(ctx context.Context, revokedBefore, expiredBefore time.Time) (err error) {
	if _, err = p.db.ExecContext(ctx, p.db.Rebind(queryPlusUserSessionPurge), revokedBefore, expiredBefore); err != nil {
		return fmt.Errorf("error purging user session records: %w", err)
	}

	return nil
}

func plusRowsAffected(result sql.Result) (ok bool, err error) {
	var n int64

	if n, err = result.RowsAffected(); err != nil {
		return false, err
	}

	return n == 1, nil
}
