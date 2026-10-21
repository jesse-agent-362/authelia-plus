// SPDX-FileCopyrightText: 2026 authelia-plus contributors
//
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/rpadovani/sqlx-v2"

	"github.com/authelia/authelia/v4/internal/model"
)

// authelia-plus: the plus_user_session and plus_user_session_grant tables behind the session list and revoke.
//
// The table is created at startup rather than by a numbered migration, so it can't collide with upstream's migration
// numbers. These methods are deliberately not part of the Provider interface; the plus code reaches them by type
// assertion.

// plusPurgeBatch bounds the records purged per statement, well below every dialect's limit on parameters.
const plusPurgeBatch = 100

const (
	tablePlusUserSession      = "plus_user_session"
	tablePlusUserSessionGrant = "plus_user_session_grant"
)

const (
	queryPlusUserSessionCreateSQLite = `
CREATE TABLE IF NOT EXISTS plus_user_session (
    id CHAR(36) NOT NULL PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_active DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ip VARCHAR(64) NOT NULL,
    user_agent VARCHAR(512) NOT NULL,
    grants INTEGER NOT NULL DEFAULT 0,
    revoked_at DATETIME NULL DEFAULT NULL,
    revoked_by VARCHAR(100) NOT NULL DEFAULT '',
    claimed_at DATETIME NULL DEFAULT NULL,
    processed_at DATETIME NULL DEFAULT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    retry_at DATETIME NULL DEFAULT NULL
);`

	queryPlusUserSessionGrantCreateSQLite = `
CREATE TABLE IF NOT EXISTS plus_user_session_grant (
    session_id CHAR(36) NOT NULL,
    request_id VARCHAR(40) NOT NULL,
    client_id VARCHAR(255) NOT NULL DEFAULT '',
    subject VARCHAR(255) NOT NULL DEFAULT '',
    sid VARCHAR(64) NOT NULL DEFAULT '',
    issuer VARCHAR(512) NOT NULL DEFAULT '',
    PRIMARY KEY (session_id, request_id)
);`

	queryPlusUserSessionCreatePostgreSQL = `
CREATE TABLE IF NOT EXISTS plus_user_session (
    id CHAR(36) NOT NULL CONSTRAINT plus_user_session_pkey PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_active TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ip VARCHAR(64) NOT NULL,
    user_agent VARCHAR(512) NOT NULL,
    grants INTEGER NOT NULL DEFAULT 0,
    revoked_at TIMESTAMP WITH TIME ZONE NULL DEFAULT NULL,
    revoked_by VARCHAR(100) NOT NULL DEFAULT '',
    claimed_at TIMESTAMP WITH TIME ZONE NULL DEFAULT NULL,
    processed_at TIMESTAMP WITH TIME ZONE NULL DEFAULT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    retry_at TIMESTAMP WITH TIME ZONE NULL DEFAULT NULL
);`

	queryPlusUserSessionGrantCreatePostgreSQL = `
CREATE TABLE IF NOT EXISTS plus_user_session_grant (
    session_id CHAR(36) NOT NULL,
    request_id VARCHAR(40) NOT NULL,
    client_id VARCHAR(255) NOT NULL DEFAULT '',
    subject VARCHAR(255) NOT NULL DEFAULT '',
    sid VARCHAR(64) NOT NULL DEFAULT '',
    issuer VARCHAR(512) NOT NULL DEFAULT '',
    CONSTRAINT plus_user_session_grant_pkey PRIMARY KEY (session_id, request_id)
);`

	// The username is compared exactly on every dialect: the case insensitive collation MySQL would otherwise use
	// could let one user list and revoke the sessions of another whose username differs only in case. It's binary
	// rather than utf8mb4_bin, which pads, so 'john ' would equal 'john'; MariaDB has no collation without padding
	// that MySQL shares.
	queryPlusUserSessionCreateMySQL = `
CREATE TABLE IF NOT EXISTS plus_user_session (
    id CHAR(36) NOT NULL PRIMARY KEY,
    username VARBINARY(400) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_active TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ip VARCHAR(64) NOT NULL,
    user_agent VARCHAR(512) NOT NULL,
    grants INTEGER NOT NULL DEFAULT 0,
    revoked_at TIMESTAMP NULL DEFAULT NULL,
    revoked_by VARCHAR(100) NOT NULL DEFAULT '',
    claimed_at TIMESTAMP NULL DEFAULT NULL,
    processed_at TIMESTAMP NULL DEFAULT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    retry_at TIMESTAMP NULL DEFAULT NULL,
    INDEX plus_user_session_username (username),
    INDEX plus_user_session_revoked_at (revoked_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;`

	queryPlusUserSessionGrantCreateMySQL = `
CREATE TABLE IF NOT EXISTS plus_user_session_grant (
    session_id CHAR(36) NOT NULL,
    request_id VARCHAR(40) NOT NULL,
    client_id VARCHAR(255) NOT NULL DEFAULT '',
    subject VARCHAR(255) NOT NULL DEFAULT '',
    sid VARCHAR(64) NOT NULL DEFAULT '',
    issuer VARCHAR(512) NOT NULL DEFAULT '',
    PRIMARY KEY (session_id, request_id),
    INDEX plus_user_session_grant_request_id (request_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;`

	queryPlusUserSessionCreateIndexUsername  = `CREATE INDEX IF NOT EXISTS plus_user_session_username ON plus_user_session (username);`
	queryPlusUserSessionCreateIndexRevokedAt = `CREATE INDEX IF NOT EXISTS plus_user_session_revoked_at ON plus_user_session (revoked_at);`

	// queryPlusUserSessionGrantCreateIndexRequestID serves the token endpoint's lookup of a grant's record by request ID,
	// which the primary key, led by session_id, can't.
	queryPlusUserSessionGrantCreateIndexRequestID = `CREATE INDEX IF NOT EXISTS plus_user_session_grant_request_id ON plus_user_session_grant (request_id);`

	queryPlusUserSessionColumns = `id, username, created_at, last_active, expires_at, ip, user_agent, grants, revoked_at, revoked_by, claimed_at, processed_at, attempts, retry_at`

	queryPlusUserSessionInsert = `
INSERT INTO plus_user_session (id, username, created_at, last_active, expires_at, ip, user_agent, grants)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);`

	queryPlusUserSessionSelectByID = `SELECT ` + queryPlusUserSessionColumns + ` FROM plus_user_session WHERE id = ?;`

	queryPlusUserSessionSelectByRequestID = `
SELECT ` + queryPlusUserSessionColumns + `
FROM plus_user_session
WHERE id = (SELECT session_id FROM plus_user_session_grant WHERE request_id = ? LIMIT 1);`

	queryPlusUserSessionSelectActiveByUsername = `
SELECT ` + queryPlusUserSessionColumns + `
FROM plus_user_session
WHERE username = ? AND revoked_at IS NULL AND expires_at > ?
ORDER BY last_active DESC;`

	queryPlusUserSessionUpdateActivity = `
UPDATE plus_user_session
SET last_active = ?, expires_at = ?
WHERE id = ? AND revoked_at IS NULL;`

	// queryPlusUserSessionLockForGrant always changes the row when it matches, so every dialect reports it affected,
	// and it holds the row lock until the grant is inserted: a revoke either waits for the grant or the insert fails.
	// A record holding the most grants takes no more.
	queryPlusUserSessionLockForGrant = `
UPDATE plus_user_session
SET grants = grants + 1
WHERE id = ? AND revoked_at IS NULL AND processed_at IS NULL AND grants < ?;`

	queryPlusUserSessionSelectGrants = `SELECT grants FROM plus_user_session WHERE id = ?;`

	queryPlusUserSessionGrantInsert = `
INSERT INTO plus_user_session_grant (session_id, request_id, client_id, subject, sid, issuer)
VALUES (?, ?, ?, ?, ?, ?);`

	queryPlusUserSessionGrantSelect = `
SELECT session_id, request_id, client_id, subject, sid, issuer
FROM plus_user_session_grant
WHERE session_id = ?
ORDER BY request_id;`

	queryPlusUserSessionGrantMove = `UPDATE plus_user_session_grant SET session_id = ? WHERE session_id = ?;`

	queryPlusUserSessionRevoke = `
UPDATE plus_user_session
SET revoked_at = ?, revoked_by = ?
WHERE id = ? AND username = ? AND revoked_at IS NULL;`

	queryPlusUserSessionRevokeOthers = `
UPDATE plus_user_session
SET revoked_at = ?, revoked_by = ?
WHERE username = ? AND id <> ? AND revoked_at IS NULL;`

	queryPlusUserSessionSelectRevokedOthers = `
SELECT id
FROM plus_user_session
WHERE username = ? AND id <> ? AND revoked_at IS NOT NULL AND processed_at IS NULL;`

	queryPlusUserSessionRevokeByUsername = `
UPDATE plus_user_session
SET revoked_at = ?, revoked_by = ?
WHERE username = ? AND revoked_at IS NULL;`

	queryPlusUserSessionClose = `
UPDATE plus_user_session
SET revoked_at = ?, revoked_by = ?, processed_at = ?
WHERE revoked_at IS NULL;`

	// queryPlusUserSessionReplaceClose closes the record a re-authentication replaces. It only matches a record nobody
	// revoked, so a revoke racing the re-authentication can't be escaped.
	queryPlusUserSessionReplaceClose = `
UPDATE plus_user_session
SET revoked_at = ?, revoked_by = ?, processed_at = ?
WHERE id = ? AND username = ? AND revoked_at IS NULL AND processed_at IS NULL;`

	// queryPlusUserSessionEndCheck finds whether a logout has anything left to revoke: the record is ended with the
	// plain revoke, which leaves the processing to the poller.
	queryPlusUserSessionEndCheck = `
SELECT COUNT(id)
FROM plus_user_session
WHERE id = ? AND username = ? AND processed_at IS NULL;`

	queryPlusUserSessionSelectRevokedIDs = `SELECT id, revoked_at FROM plus_user_session WHERE revoked_at IS NOT NULL AND revoked_at > ?;`

	// queryPlusUserSessionSelectUnprocessedIDs takes the revocations by the user or an administrator first, so a backlog
	// of logouts, whose tokens the logout already revoked, can't hold them up.
	queryPlusUserSessionSelectUnprocessedIDs = `
SELECT id
FROM plus_user_session
WHERE revoked_at IS NOT NULL AND revoked_at <= ? AND processed_at IS NULL AND (claimed_at IS NULL OR claimed_at < ?)
    AND (retry_at IS NULL OR retry_at <= ?)
ORDER BY CASE WHEN revoked_by IN ('self', 'cli') THEN 0 ELSE 1 END, attempts, revoked_at
LIMIT ?;`

	// queryPlusUserSessionClaim leases a revoked record to one instance. A lease older than the cutoff is taken over,
	// so a record whose instance died or shut down mid-processing is processed anyway.
	queryPlusUserSessionClaim = `
UPDATE plus_user_session
SET claimed_at = ?, attempts = attempts + 1
WHERE id = ? AND revoked_at IS NOT NULL AND processed_at IS NULL AND (claimed_at IS NULL OR claimed_at < ?);`

	queryPlusUserSessionComplete = `UPDATE plus_user_session SET processed_at = ?, claimed_at = NULL WHERE id = ? AND processed_at IS NULL;`

	queryPlusUserSessionUnclaim = `UPDATE plus_user_session SET claimed_at = NULL, retry_at = ? WHERE id = ? AND processed_at IS NULL;`

	// queryPlusUserSessionSelectPurge never selects a revoked record before it is processed: its grants' tokens can
	// outlive the retention. The delete checks the same again.
	queryPlusUserSessionSelectPurge = `
SELECT id
FROM plus_user_session
WHERE (revoked_at IS NOT NULL AND revoked_at < ? AND processed_at IS NOT NULL) OR (revoked_at IS NULL AND expires_at < ?);`

	queryPlusUserSessionPurgeByIDs = `
DELETE FROM plus_user_session
WHERE id IN (?) AND ((revoked_at IS NOT NULL AND revoked_at < ? AND processed_at IS NOT NULL) OR (revoked_at IS NULL AND expires_at < ?));`

	// queryPlusUserSessionGrantPurgeByIDs deletes only the grants of records the purge deleted: a record whose
	// deletion the re-check refused keeps them, and grants a concurrent re-authentication moved to its new record no
	// longer match.
	queryPlusUserSessionGrantPurgeByIDs = `
DELETE FROM plus_user_session_grant
WHERE session_id IN (?) AND session_id NOT IN (SELECT id FROM plus_user_session WHERE id IN (?));`
)

// PlusUserSessionsSchemaEnsure creates the plus_user_session and plus_user_session_grant tables and their indexes if
// they don't exist.
func (p *SQLProvider) PlusUserSessionsSchemaEnsure(ctx context.Context) (err error) {
	var queries []string

	switch p.name {
	case providerMySQL:
		queries = []string{queryPlusUserSessionCreateMySQL, queryPlusUserSessionGrantCreateMySQL}
	case providerPostgres:
		queries = []string{queryPlusUserSessionCreatePostgreSQL, queryPlusUserSessionGrantCreatePostgreSQL, queryPlusUserSessionCreateIndexUsername, queryPlusUserSessionCreateIndexRevokedAt, queryPlusUserSessionGrantCreateIndexRequestID}
	default:
		queries = []string{queryPlusUserSessionCreateSQLite, queryPlusUserSessionGrantCreateSQLite, queryPlusUserSessionCreateIndexUsername, queryPlusUserSessionCreateIndexRevokedAt, queryPlusUserSessionGrantCreateIndexRequestID}
	}

	for _, query := range queries {
		if _, err = p.db.ExecContext(ctx, query); err != nil {
			return fmt.Errorf("error creating the %s and %s tables: %w", tablePlusUserSession, tablePlusUserSessionGrant, err)
		}
	}

	return nil
}

// SavePlusUserSession inserts a user session record.
func (p *SQLProvider) SavePlusUserSession(ctx context.Context, s model.PlusUserSession) (err error) {
	if _, err = p.db.ExecContext(ctx, p.db.Rebind(queryPlusUserSessionInsert),
		s.ID, s.Username, s.CreatedAt, s.LastActive, s.ExpiresAt, s.IP, s.UserAgent, 0); err != nil {
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

// UpdatePlusUserSessionActivity records the last activity and expiration of an unrevoked user session record. It
// reports whether a row was affected; MySQL doesn't count a row whose values didn't change, so false alone doesn't
// prove the record is missing or revoked.
func (p *SQLProvider) UpdatePlusUserSessionActivity(ctx context.Context, id uuid.UUID, lastActive, expiresAt time.Time) (ok bool, err error) {
	var result sql.Result

	if result, err = p.db.ExecContext(ctx, p.db.Rebind(queryPlusUserSessionUpdateActivity), lastActive, expiresAt, id); err != nil {
		return false, fmt.Errorf("error updating activity of user session record '%s': %w", id, err)
	}

	return plusRowsAffected(result)
}

// LoadPlusUserSessionByRequestID loads the user session record holding the grant of an authorization request. It
// returns nil when no record holds it.
func (p *SQLProvider) LoadPlusUserSessionByRequestID(ctx context.Context, requestID string) (s *model.PlusUserSession, err error) {
	s = &model.PlusUserSession{}

	if err = p.db.GetContext(ctx, s, p.db.Rebind(queryPlusUserSessionSelectByRequestID), requestID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}

		return nil, fmt.Errorf("error selecting the user session record of request '%s': %w", requestID, err)
	}

	return s, nil
}

// SavePlusUserSessionGrant adds a grant to a user session record. It reports false when the record is missing or
// revoked, as the grant could then be missed by the revocation, or holds model.PlusUserSessionMaxGrants grants; the
// caller must not issue it.
func (p *SQLProvider) SavePlusUserSessionGrant(ctx context.Context, grant model.PlusUserSessionGrant) (ok bool, err error) {
	err = p.plusTx(ctx, func(tx SQLXTx) (err error) {
		var result sql.Result

		if result, err = tx.ExecContext(ctx, p.db.Rebind(queryPlusUserSessionLockForGrant), grant.SessionID, model.PlusUserSessionMaxGrants); err != nil {
			return err
		}

		if ok, err = plusRowsAffected(result); err != nil || !ok {
			return err
		}

		_, err = tx.ExecContext(ctx, p.db.Rebind(queryPlusUserSessionGrantInsert),
			grant.SessionID, grant.RequestID, grant.ClientID, grant.Subject, grant.SID, grant.Issuer)

		return err
	})
	if err != nil {
		return false, fmt.Errorf("error saving grant '%s' of user session record '%s': %w", grant.RequestID, grant.SessionID, err)
	}

	return ok, nil
}

// LoadPlusUserSessionGrants loads the grants of a user session record.
func (p *SQLProvider) LoadPlusUserSessionGrants(ctx context.Context, id uuid.UUID) (grants []model.PlusUserSessionGrant, err error) {
	if err = p.db.SelectContext(ctx, &grants, p.db.Rebind(queryPlusUserSessionGrantSelect), id); err != nil {
		return nil, fmt.Errorf("error selecting grants of user session record '%s': %w", id, err)
	}

	return grants, nil
}

// ReplacePlusUserSession atomically closes the previous record of a session, without side effects, inserts its
// replacement and moves the previous record's grants to it. It reports false, changing nothing, unless the previous
// record belongs to the replacement's user and was not revoked.
func (p *SQLProvider) ReplacePlusUserSession(ctx context.Context, previous uuid.UUID, s model.PlusUserSession, revokedBy string) (ok bool, err error) {
	err = p.plusTx(ctx, func(tx SQLXTx) (err error) {
		var result sql.Result

		if result, err = tx.ExecContext(ctx, p.db.Rebind(queryPlusUserSessionReplaceClose), s.CreatedAt, revokedBy, s.CreatedAt, previous, s.Username); err != nil {
			return err
		}

		if ok, err = plusRowsAffected(result); err != nil || !ok {
			return err
		}

		// The grants move with their count, so the replacement can't take more than its share.
		var grants int

		if err = tx.GetContext(ctx, &grants, p.db.Rebind(queryPlusUserSessionSelectGrants), previous); err != nil {
			return err
		}

		if _, err = tx.ExecContext(ctx, p.db.Rebind(queryPlusUserSessionInsert),
			s.ID, s.Username, s.CreatedAt, s.LastActive, s.ExpiresAt, s.IP, s.UserAgent, grants); err != nil {
			return err
		}

		_, err = tx.ExecContext(ctx, p.db.Rebind(queryPlusUserSessionGrantMove), s.ID, previous)

		return err
	})
	if err != nil {
		return false, fmt.Errorf("error replacing user session record '%s' for user '%s': %w", previous, s.Username, err)
	}

	return ok, nil
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

// RevokeOtherPlusUserSessions revokes every unrevoked user session record of username except the one with the ID
// except, in a single statement, and returns how many it revoked and the IDs of that user's other records which are
// revoked and not yet processed: the ones it revoked, and possibly some revoked just before.
func (p *SQLProvider) RevokeOtherPlusUserSessions(ctx context.Context, username string, except uuid.UUID, revokedBy string, now time.Time) (count int64, ids []uuid.UUID, err error) {
	err = p.plusTx(ctx, func(tx SQLXTx) (err error) {
		var result sql.Result

		if result, err = tx.ExecContext(ctx, p.db.Rebind(queryPlusUserSessionRevokeOthers), now, revokedBy, username, except); err != nil {
			return err
		}

		if count, err = result.RowsAffected(); err != nil {
			return err
		}

		return tx.SelectContext(ctx, &ids, p.db.Rebind(queryPlusUserSessionSelectRevokedOthers), username, except)
	})
	if err != nil {
		return 0, nil, fmt.Errorf("error revoking the other user session records of user '%s': %w", username, err)
	}

	return count, ids, nil
}

// RevokePlusUserSessionsByUsername revokes every unrevoked user session record of a user, matching the username
// exactly, and returns how many were revoked.
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

// EndPlusUserSession revokes a user session record of username for its logout, if it wasn't already. It reports false
// when the record is missing or its revocation was processed already.
func (p *SQLProvider) EndPlusUserSession(ctx context.Context, id uuid.UUID, username, revokedBy string, now time.Time) (ok bool, err error) {
	err = p.plusTx(ctx, func(tx SQLXTx) (err error) {
		if _, err = tx.ExecContext(ctx, p.db.Rebind(queryPlusUserSessionRevoke), now, revokedBy, id, username); err != nil {
			return err
		}

		var count int

		if err = tx.GetContext(ctx, &count, p.db.Rebind(queryPlusUserSessionEndCheck), id, username); err != nil {
			return err
		}

		ok = count == 1

		return nil
	})
	if err != nil {
		return false, fmt.Errorf("error ending user session record '%s': %w", id, err)
	}

	return ok, nil
}

// LoadPlusUserSessionRevocations loads the IDs and revocation times of the user session records revoked after since.
func (p *SQLProvider) LoadPlusUserSessionRevocations(ctx context.Context, since time.Time) (revocations []model.PlusUserSessionRevocation, err error) {
	if err = p.db.SelectContext(ctx, &revocations, p.db.Rebind(queryPlusUserSessionSelectRevokedIDs), since); err != nil {
		return nil, fmt.Errorf("error selecting revoked user session records: %w", err)
	}

	return revocations, nil
}

// LoadPlusUserSessionUnprocessedIDs loads up to limit IDs of the user session records revoked no later than before
// whose revocation has not been processed, which are unclaimed or were claimed before leaseBefore, and which are due
// for a retry by now. The least attempted come first, then the oldest revocation, so failing records go last.
func (p *SQLProvider) LoadPlusUserSessionUnprocessedIDs(ctx context.Context, before, leaseBefore, now time.Time, limit int) (ids []uuid.UUID, err error) {
	if err = p.db.SelectContext(ctx, &ids, p.db.Rebind(queryPlusUserSessionSelectUnprocessedIDs), before, leaseBefore, now, limit); err != nil {
		return nil, fmt.Errorf("error selecting unprocessed user session records: %w", err)
	}

	return ids, nil
}

// ClaimPlusUserSession leases the revocation of a user session record for processing, counting an attempt. It reports false when it's
// processed, or another instance holds a lease taken at or after leaseBefore, in which case the caller must not
// process it.
func (p *SQLProvider) ClaimPlusUserSession(ctx context.Context, id uuid.UUID, now, leaseBefore time.Time) (ok bool, err error) {
	var result sql.Result

	if result, err = p.db.ExecContext(ctx, p.db.Rebind(queryPlusUserSessionClaim), now, id, leaseBefore); err != nil {
		return false, fmt.Errorf("error claiming user session record '%s': %w", id, err)
	}

	return plusRowsAffected(result)
}

// CompletePlusUserSession marks the revocation of a user session record as processed.
func (p *SQLProvider) CompletePlusUserSession(ctx context.Context, id uuid.UUID, now time.Time) (err error) {
	if _, err = p.db.ExecContext(ctx, p.db.Rebind(queryPlusUserSessionComplete), now, id); err != nil {
		return fmt.Errorf("error completing user session record '%s': %w", id, err)
	}

	return nil
}

// UnclaimPlusUserSession releases the lease on the revocation of a user session record, so it's retried from retryAt.
func (p *SQLProvider) UnclaimPlusUserSession(ctx context.Context, id uuid.UUID, retryAt time.Time) (err error) {
	if _, err = p.db.ExecContext(ctx, p.db.Rebind(queryPlusUserSessionUnclaim), retryAt, id); err != nil {
		return fmt.Errorf("error unclaiming user session record '%s': %w", id, err)
	}

	return nil
}

// PurgePlusUserSessions deletes the processed user session records revoked before revokedBefore, the unrevoked ones which
// expired before expiredBefore, and the grants of exactly those records, in one transaction.
func (p *SQLProvider) PurgePlusUserSessions(ctx context.Context, revokedBefore, expiredBefore time.Time) (err error) {
	err = p.plusTx(ctx, func(tx SQLXTx) (err error) {
		var ids []uuid.UUID

		if err = tx.SelectContext(ctx, &ids, p.db.Rebind(queryPlusUserSessionSelectPurge), revokedBefore, expiredBefore); err != nil {
			return err
		}

		for chunk := range slices.Chunk(ids, plusPurgeBatch) {
			var (
				query string
				args  []any
			)

			if query, args, err = sqlx.In(queryPlusUserSessionPurgeByIDs, chunk, revokedBefore, expiredBefore); err != nil {
				return err
			}

			if _, err = tx.ExecContext(ctx, p.db.Rebind(query), args...); err != nil {
				return err
			}

			if query, args, err = sqlx.In(queryPlusUserSessionGrantPurgeByIDs, chunk, chunk); err != nil {
				return err
			}

			if _, err = tx.ExecContext(ctx, p.db.Rebind(query), args...); err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("error purging user session records: %w", err)
	}

	return nil
}

func (p *SQLProvider) plusTx(ctx context.Context, fn func(tx SQLXTx) error) (err error) {
	var tx SQLXTx

	if tx, err = p.db.BeginTxx(ctx, nil); err != nil {
		return err
	}

	if err = fn(tx); err != nil {
		_ = tx.Rollback()

		return err
	}

	return tx.Commit()
}

func plusRowsAffected(result sql.Result) (ok bool, err error) {
	var n int64

	if n, err = result.RowsAffected(); err != nil {
		return false, err
	}

	return n == 1, nil
}
