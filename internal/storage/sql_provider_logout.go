// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"fmt"
)

// authelia-plus: revoking a user's OAuth 2.0 sessions at logout.

const queryFmtRevokeOAuth2SessionsByUsername = `
		UPDATE %s
		SET revoked = TRUE
		WHERE revoked = FALSE AND subject IN (
			SELECT identifier
			FROM %s
			WHERE username = ?
		);`

// RevokeOAuth2SessionsByUsername marks every access token, refresh token, authorization code and OpenID Connect 1.0
// session issued to the user as revoked, across all clients. A revoked access token fails introspection and a revoked
// refresh token can no longer be exchanged, so clients lose access the next time they check either.
func (p *SQLProvider) RevokeOAuth2SessionsByUsername(ctx context.Context, username string) (err error) {
	for _, table := range []string{
		tableOAuth2AccessTokenSession,
		tableOAuth2RefreshTokenSession,
		tableOAuth2AuthorizeCodeSession,
		tableOAuth2OpenIDConnectSession,
	} {
		query := p.db.Rebind(fmt.Sprintf(queryFmtRevokeOAuth2SessionsByUsername, table, tableUserOpaqueIdentifier))

		if _, err = p.conn(ctx).ExecContext(ctx, query, username); err != nil {
			return fmt.Errorf("error revoking oauth2 sessions in table '%s' for user '%s': %w", table, username, err)
		}
	}

	return nil
}
