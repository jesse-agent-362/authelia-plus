// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/authelia/authelia/v4/internal/model"
)

// authelia-plus: tests for revoking a user's OAuth 2.0 sessions at logout.

func TestSQLProviderRevokeOAuth2SessionsByUsername(t *testing.T) {
	provider := newTestSQLiteProviderWithEncryption(t)
	require.NoError(t, provider.StartupCheck())

	ctx := context.Background()

	subjects := map[string]uuid.UUID{}

	for _, username := range []string{"john", "harry"} {
		subjects[username] = uuid.Must(uuid.NewRandom())

		require.NoError(t, provider.SaveUserOpaqueIdentifier(ctx, model.UserOpaqueIdentifier{
			Service:    "openid",
			SectorID:   "",
			Username:   username,
			Identifier: subjects[username],
		}))
	}

	types := []OAuth2SessionType{
		OAuth2SessionTypeAccessToken,
		OAuth2SessionTypeRefreshToken,
		OAuth2SessionTypeAuthorizeCode,
		OAuth2SessionTypeOpenIDConnect,
	}

	for _, sessionType := range types {
		for username, subject := range subjects {
			require.NoError(t, provider.SaveOAuth2Session(ctx, sessionType, model.OAuth2Session{
				ChallengeID:     model.MustNullUUID(model.NewRandomNullUUID()),
				RequestID:       "req-" + username,
				ClientID:        "test-client",
				Signature:       "sig-" + username,
				Subject:         sql.NullString{Valid: true, String: subject.String()},
				Active:          true,
				RequestedScopes: model.StringSlicePipeDelimited{"openid"},
				GrantedScopes:   model.StringSlicePipeDelimited{"openid"},
				Session:         []byte("{}"),
			}))
		}
	}

	require.NoError(t, provider.RevokeOAuth2SessionsByUsername(ctx, "john"))

	for _, sessionType := range types {
		t.Run(sessionType.String(), func(t *testing.T) {
			_, err := provider.LoadOAuth2Session(ctx, sessionType, "sig-john")

			assert.ErrorIs(t, err, sql.ErrNoRows)

			loaded, err := provider.LoadOAuth2Session(ctx, sessionType, "sig-harry")

			require.NoError(t, err)
			assert.Equal(t, subjects["harry"].String(), loaded.Subject.String)
		})
	}

	t.Run("ShouldBeIdempotent", func(t *testing.T) {
		assert.NoError(t, provider.RevokeOAuth2SessionsByUsername(ctx, "john"))
		assert.NoError(t, provider.RevokeOAuth2SessionsByUsername(ctx, "nobody"))
	})
}
