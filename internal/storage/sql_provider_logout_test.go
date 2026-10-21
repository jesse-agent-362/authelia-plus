// SPDX-FileCopyrightText: 2026 Authelia
// SPDX-FileCopyrightText: 2026 authelia-plus contributors
//
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/authelia/authelia/v4/internal/model"
)

// authelia-plus: tests for revoking the OAuth 2.0 sessions of a logged out user session.

func TestSQLProviderRevokeOAuth2SessionsByRequestIDs(t *testing.T) {
	provider := newTestSQLiteProviderWithEncryption(t)
	require.NoError(t, provider.StartupCheck())

	ctx := context.Background()

	types := []OAuth2SessionType{
		OAuth2SessionTypeAccessToken,
		OAuth2SessionTypeRefreshToken,
		OAuth2SessionTypeAuthorizeCode,
		OAuth2SessionTypeOpenIDConnect,
	}

	// Two rows per request and type, as refreshing leaves several tokens sharing one request ID.
	for _, sessionType := range types {
		for _, requestID := range []string{"req-a", "req-b", "req-other"} {
			for i := range 2 {
				require.NoError(t, provider.SaveOAuth2Session(ctx, sessionType, model.OAuth2Session{
					ChallengeID:     model.MustNullUUID(model.NewRandomNullUUID()),
					RequestID:       requestID,
					ClientID:        "test-client",
					Signature:       fmt.Sprintf("sig-%s-%d", requestID, i),
					Subject:         sql.NullString{Valid: true, String: "c1b8b3a2-3f6e-4b51-9d0c-0d4f2b9a7e11"},
					Active:          true,
					RequestedScopes: model.StringSlicePipeDelimited{"openid"},
					GrantedScopes:   model.StringSlicePipeDelimited{"openid"},
					Session:         []byte("{}"),
				}))
			}
		}
	}

	// More request IDs than one statement takes, with the two that exist in different statements.
	requestIDs := make([]string, 0, 2*revokeRequestIDsBatch+2)
	requestIDs = append(requestIDs, "req-a")

	for i := range 2 * revokeRequestIDsBatch {
		requestIDs = append(requestIDs, fmt.Sprintf("req-unknown-%d", i))
	}

	requestIDs = append(requestIDs, "req-b")

	require.NoError(t, provider.RevokeOAuth2SessionsByRequestIDs(ctx, requestIDs))

	for _, sessionType := range types {
		t.Run(sessionType.String(), func(t *testing.T) {
			for i := range 2 {
				for _, requestID := range []string{"req-a", "req-b"} {
					_, err := provider.LoadOAuth2Session(ctx, sessionType, fmt.Sprintf("sig-%s-%d", requestID, i))

					assert.ErrorIs(t, err, sql.ErrNoRows)
				}

				loaded, err := provider.LoadOAuth2Session(ctx, sessionType, fmt.Sprintf("sig-req-other-%d", i))

				require.NoError(t, err)
				assert.Equal(t, "req-other", loaded.RequestID)
			}
		})
	}

	t.Run("ShouldBeIdempotent", func(t *testing.T) {
		assert.NoError(t, provider.RevokeOAuth2SessionsByRequestIDs(ctx, []string{"req-a", "req-unknown"}))
		assert.NoError(t, provider.RevokeOAuth2SessionsByRequestIDs(ctx, nil))
	})
}
