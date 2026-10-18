// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"fmt"
)

// authelia-plus: revoking the OAuth 2.0 sessions of a logged out user session.

// RevokeOAuth2SessionsByRequestIDs marks every access token, refresh token, authorization code and OpenID Connect 1.0
// session belonging to the given authorization requests as revoked, in a single transaction. The request ID is kept
// through the code exchange and every refresh, so this reaches all tokens descended from those authorizations. A
// revoked access token fails introspection and a revoked refresh token can no longer be exchanged.
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
	} {
		query := p.db.Rebind(fmt.Sprintf(queryFmtRevokeOAuth2SessionByRequestID, table))

		for _, requestID := range requestIDs {
			if _, err = tx.ExecContext(ctx, query, requestID); err != nil {
				_ = tx.Rollback()

				return fmt.Errorf("error revoking oauth2 sessions in table '%s' with request id '%s': %w", table, requestID, err)
			}
		}
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("error committing transaction to revoke oauth2 sessions: %w", err)
	}

	return nil
}
