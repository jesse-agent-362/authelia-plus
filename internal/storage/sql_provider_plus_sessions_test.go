// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/authelia/authelia/v4/internal/model"
)

// authelia-plus: tests for the plus_user_session table.

func newTestPlusUserSession(t *testing.T, username string, now time.Time) model.PlusUserSession {
	t.Helper()

	id, err := uuid.NewV7()
	require.NoError(t, err)

	return model.PlusUserSession{
		ID: id, Username: username, CreatedAt: now, LastActive: now, ExpiresAt: now.Add(time.Hour),
		IP: "192.0.2.1", UserAgent: "Mozilla/5.0", RequestIDs: "[]", BackChannel: "{}",
	}
}

func TestSQLProviderPlusUserSessions(t *testing.T) {
	provider := newTestSQLiteProviderWithEncryption(t)
	require.NoError(t, provider.StartupCheck())

	ctx := context.Background()

	require.NoError(t, provider.PlusUserSessionsSchemaEnsure(ctx))
	require.NoError(t, provider.PlusUserSessionsSchemaEnsure(ctx), "creating the table must be idempotent")

	now := time.Unix(1760000000, 0).UTC()

	john, johnOther, harry := newTestPlusUserSession(t, "john", now), newTestPlusUserSession(t, "john", now), newTestPlusUserSession(t, "harry", now)

	for _, s := range []model.PlusUserSession{john, johnOther, harry} {
		require.NoError(t, provider.SavePlusUserSession(ctx, s))
	}

	require.Error(t, provider.SavePlusUserSession(ctx, john), "the id is the primary key")

	require.NoError(t, provider.UpdatePlusUserSessionActivity(ctx, johnOther.ID, now.Add(time.Minute), now.Add(2*time.Hour)))

	sessions, err := provider.LoadPlusUserSessionsActive(ctx, "john", now)
	require.NoError(t, err)
	require.Len(t, sessions, 2)
	assert.Equal(t, johnOther.ID, sessions[0].ID, "most recently active first")
	assert.Equal(t, john.ID, sessions[1].ID)

	sessions, err = provider.LoadPlusUserSessionsActive(ctx, "john", now.Add(90*time.Minute))
	require.NoError(t, err)
	require.Len(t, sessions, 1, "expired records are not listed")

	ok, err := provider.UpdatePlusUserSessionOpenIDConnect(ctx, john.ID, `["req1"]`, `{"SessionID":"sid"}`)
	require.NoError(t, err)
	assert.True(t, ok)

	ok, err = provider.UpdatePlusUserSessionOpenIDConnect(ctx, uuid.New(), `[]`, `{}`)
	require.NoError(t, err)
	assert.False(t, ok)

	// Requirement 6: one statement matches both the id and the username, so another user's record is not revoked and
	// looks exactly like a missing one.
	ok, err = provider.RevokePlusUserSession(ctx, harry.ID, "john", "self", now)
	require.NoError(t, err)
	assert.False(t, ok)

	ok, err = provider.RevokePlusUserSession(ctx, uuid.New(), "john", "self", now)
	require.NoError(t, err)
	assert.False(t, ok)

	record, err := provider.LoadPlusUserSession(ctx, harry.ID)
	require.NoError(t, err)
	assert.False(t, record.RevokedAt.Valid)

	ok, err = provider.RevokePlusUserSession(ctx, john.ID, "john", "self", now)
	require.NoError(t, err)
	assert.True(t, ok)

	ok, err = provider.RevokePlusUserSession(ctx, john.ID, "john", "self", now)
	require.NoError(t, err)
	assert.False(t, ok, "an already revoked record is not revoked again")

	ids, err := provider.LoadPlusUserSessionRevokedIDs(ctx, now.Add(-time.Minute))
	require.NoError(t, err)
	assert.Equal(t, []uuid.UUID{john.ID}, ids)

	ids, err = provider.LoadPlusUserSessionUnprocessedIDs(ctx, now.Add(-time.Second), 10)
	require.NoError(t, err)
	assert.Empty(t, ids, "too recent to process")

	ids, err = provider.LoadPlusUserSessionUnprocessedIDs(ctx, now, 10)
	require.NoError(t, err)
	assert.Equal(t, []uuid.UUID{john.ID}, ids)

	ok, err = provider.ClaimPlusUserSession(ctx, john.ID, now)
	require.NoError(t, err)
	assert.True(t, ok)

	ok, err = provider.ClaimPlusUserSession(ctx, john.ID, now)
	require.NoError(t, err)
	assert.False(t, ok, "a record is claimed once")

	ok, err = provider.UpdatePlusUserSessionOpenIDConnect(ctx, john.ID, `["req1","req2"]`, `{}`)
	require.NoError(t, err)
	assert.False(t, ok, "a claimed record takes no further grants")

	record, err = provider.LoadPlusUserSession(ctx, john.ID)
	require.NoError(t, err)
	assert.Equal(t, `["req1"]`, record.RequestIDs)
	assert.Equal(t, `{"SessionID":"sid"}`, record.BackChannel)
	assert.Equal(t, "self", record.RevokedBy)

	require.NoError(t, provider.UnclaimPlusUserSession(ctx, john.ID))

	ids, err = provider.LoadPlusUserSessionUnprocessedIDs(ctx, now, 10)
	require.NoError(t, err)
	assert.Equal(t, []uuid.UUID{john.ID}, ids)

	count, err := provider.RevokePlusUserSessionsByUsername(ctx, "JOHN", "cli", now)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count, "only the unrevoked record of john, matched case insensitively")

	require.NoError(t, provider.ClosePlusUserSession(ctx, harry.ID, "replaced", now))

	record, err = provider.LoadPlusUserSession(ctx, harry.ID)
	require.NoError(t, err)
	assert.True(t, record.RevokedAt.Valid)
	assert.True(t, record.ProcessedAt.Valid)

	restart := newTestPlusUserSession(t, "john", now)
	require.NoError(t, provider.SavePlusUserSession(ctx, restart))

	count, err = provider.ClosePlusUserSessions(ctx, "restart", now)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	require.NoError(t, provider.PurgePlusUserSessions(ctx, now.Add(time.Second), now))

	record, err = provider.LoadPlusUserSession(ctx, john.ID)
	require.NoError(t, err)
	assert.Nil(t, record)
}
