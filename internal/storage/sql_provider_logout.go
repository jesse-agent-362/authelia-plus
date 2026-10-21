// SPDX-FileCopyrightText: 2026 Authelia
// SPDX-FileCopyrightText: 2026 authelia-plus contributors
//
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"fmt"
	"slices"

	"github.com/rpadovani/sqlx-v2"
)

// authelia-plus: revoking the OAuth 2.0 sessions of a logged out user session.

// revokeRequestIDsBatch bounds the request IDs revoked per statement, well below every dialect's limit on parameters.
const revokeRequestIDsBatch = 100

const queryFmtRevokeOAuth2SessionsByRequestIDs = `
UPDATE %s
SET revoked = TRUE
WHERE request_id IN (?) AND revoked = FALSE;`

// RevokeOAuth2SessionsByRequestIDs marks every access token, refresh token, authorization code, device code and OpenID
// Connect 1.0 session belonging to the given authorization requests as revoked, in a single transaction. The request
// ID is kept through the code exchange and every refresh, so this reaches all tokens descended from those
// authorizations. A revoked access token fails introspection, a revoked refresh token can no longer be exchanged and a
// revoked device code can no longer be polled for tokens.
func (p *SQLProvider) RevokeOAuth2SessionsByRequestIDs(ctx context.Context, requestIDs []string) (err error) {
	if len(requestIDs) == 0 {
		return nil
	}

	var tx SQLXTx

	if tx, err = p.db.BeginTxx(ctx, nil); err != nil {
		return fmt.Errorf("error beginning transaction to revoke oauth2 sessions: %w", err)
	}

	for _, table := range []string{
		tableOAuth2AccessTokenSession,
		tableOAuth2RefreshTokenSession,
		tableOAuth2AuthorizeCodeSession,
		tableOAuth2OpenIDConnectSession,
		tableOAuth2DeviceCodeSession,
	} {
		for chunk := range slices.Chunk(requestIDs, revokeRequestIDsBatch) {
			var (
				query string
				args  []any
			)

			if query, args, err = sqlx.In(fmt.Sprintf(queryFmtRevokeOAuth2SessionsByRequestIDs, table), chunk); err != nil {
				_ = tx.Rollback()

				return fmt.Errorf("error building the query to revoke oauth2 sessions in table '%s': %w", table, err)
			}

			if _, err = tx.ExecContext(ctx, p.db.Rebind(query), args...); err != nil {
				_ = tx.Rollback()

				return fmt.Errorf("error revoking oauth2 sessions in table '%s': %w", table, err)
			}
		}
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("error committing transaction to revoke oauth2 sessions: %w", err)
	}

	return nil
}
