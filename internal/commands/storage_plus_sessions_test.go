// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package commands

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/authelia/authelia/v4/internal/mocks"
	"github.com/authelia/authelia/v4/internal/model"
)

// authelia-plus: tests for logging a user out of every session from the command line.

func TestRunStorageUserPlusSessionsRevoke(t *testing.T) {
	now := time.Unix(1760000000, 0).UTC()

	store := mocks.NewPlusSessionsStore()
	id := uuid.New()

	require.NoError(t, store.SavePlusUserSession(context.Background(), model.PlusUserSession{ID: id, Username: "john", ExpiresAt: now.Add(time.Hour)}))

	t.Run("ShouldWarnWhenNoSessionMatches", func(t *testing.T) {
		w, errW := &bytes.Buffer{}, &bytes.Buffer{}

		require.NoError(t, runStorageUserPlusSessionsRevoke(context.Background(), w, errW, store, "John", now))

		assert.Equal(t, "Successfully revoked 0 sessions of user 'John'\n", w.String())
		assert.Contains(t, errW.String(), "Warning: no sessions of user 'John' were revoked")
		assert.False(t, store.Get(id).RevokedAt.Valid, "the username is matched exactly")
	})

	t.Run("ShouldRevokeTheSessionsOfTheUser", func(t *testing.T) {
		w, errW := &bytes.Buffer{}, &bytes.Buffer{}

		require.NoError(t, runStorageUserPlusSessionsRevoke(context.Background(), w, errW, store, "john", now))

		assert.Equal(t, "Successfully revoked 1 sessions of user 'john'\n", w.String())
		assert.Empty(t, errW.String())
		assert.True(t, store.Get(id).RevokedAt.Valid)
	})
}
