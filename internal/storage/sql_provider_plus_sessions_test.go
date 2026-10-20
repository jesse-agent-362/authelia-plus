// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/model"
)

// authelia-plus: tests for the plus_user_session and plus_user_session_grant tables.
//
// They run on SQLite, and also on MySQL and PostgreSQL when PLUS_TEST_MYSQL or PLUS_TEST_POSTGRES
// name a tcp://host:port with an empty 'authelia' database, user 'authelia' and password 'authelia'.

func newTestPlusUserSession(t *testing.T, username string, now time.Time) model.PlusUserSession {
	t.Helper()

	id, err := uuid.NewV7()
	require.NoError(t, err)

	return model.PlusUserSession{
		ID: id, Username: username, CreatedAt: now, LastActive: now, ExpiresAt: now.Add(time.Hour),
		IP: "192.0.2.1", UserAgent: "Mozilla/5.0",
	}
}

func newTestPlusProviders(t *testing.T) map[string]*SQLProvider {
	t.Helper()

	providers := map[string]*SQLProvider{}

	sqlite := newTestSQLiteProviderWithEncryption(t)
	require.NoError(t, sqlite.StartupCheck())

	providers[providerSQLite] = &sqlite.SQLProvider

	for name, env := range map[string]string{providerMySQL: "PLUS_TEST_MYSQL", providerPostgres: "PLUS_TEST_POSTGRES"} {
		raw := os.Getenv(env)
		if raw == "" {
			continue
		}

		address, err := schema.NewAddress(raw)
		require.NoError(t, err)

		sql := schema.StorageSQL{Address: &schema.AddressTCP{Address: *address}, Database: "authelia", Username: "authelia", Password: "authelia", Timeout: 5 * time.Second}

		config := &schema.Configuration{Storage: schema.Storage{EncryptionKey: "authelia-test-key-not-a-secret-authelia-test-key-not-a-secret"}}

		var provider *SQLProvider

		if name == providerMySQL {
			config.Storage.MySQL = &schema.StorageMySQL{StorageSQL: sql}

			p, err := NewMySQLProvider(config, nil)
			require.NoError(t, err)

			provider = &p.SQLProvider
		} else {
			config.Storage.PostgreSQL = &schema.StoragePostgreSQL{StorageSQL: sql, Schema: "public"}

			p, err := NewPostgreSQLProvider(config, nil)
			require.NoError(t, err)

			provider = &p.SQLProvider
		}

		require.NoError(t, provider.StartupCheck())

		ctx := context.Background()

		require.NoError(t, provider.PlusUserSessionsSchemaEnsure(ctx))

		for _, table := range []string{tablePlusUserSessionGrant, tablePlusUserSession} {
			_, err = provider.db.ExecContext(ctx, fmt.Sprintf("DELETE FROM %s;", table))
			require.NoError(t, err)
		}

		providers[name] = provider
	}

	return providers
}

func TestSQLProviderPlusUserSessions(t *testing.T) {
	for name, provider := range newTestPlusProviders(t) {
		t.Run(name, func(t *testing.T) {
			testSQLProviderPlusUserSessions(t, provider)
		})
	}
}

func testSQLProviderPlusUserSessions(t *testing.T, provider *SQLProvider) {
	ctx := context.Background()

	require.NoError(t, provider.PlusUserSessionsSchemaEnsure(ctx))
	require.NoError(t, provider.PlusUserSessionsSchemaEnsure(ctx), "creating the tables must be idempotent")

	now := time.Unix(1760000000, 0).UTC()

	john, johnOther, johnCased, harry := newTestPlusUserSession(t, "john", now), newTestPlusUserSession(t, "john", now), newTestPlusUserSession(t, "John", now), newTestPlusUserSession(t, "harry", now)

	for _, s := range []model.PlusUserSession{john, johnOther, johnCased, harry} {
		require.NoError(t, provider.SavePlusUserSession(ctx, s))
	}

	require.Error(t, provider.SavePlusUserSession(ctx, john), "the id is the primary key")

	require.NoError(t, provider.UpdatePlusUserSessionActivity(ctx, johnOther.ID, now.Add(time.Minute), now.Add(2*time.Hour)))

	sessions, err := provider.LoadPlusUserSessionsActive(ctx, "john", now)
	require.NoError(t, err)
	require.Len(t, sessions, 2, "usernames are matched exactly, so 'John' is someone else")
	assert.Equal(t, johnOther.ID, sessions[0].ID, "most recently active first")
	assert.Equal(t, john.ID, sessions[1].ID)

	sessions, err = provider.LoadPlusUserSessionsActive(ctx, "john", now.Add(90*time.Minute))
	require.NoError(t, err)
	require.Len(t, sessions, 1, "expired records are not listed")

	ok, err := provider.SavePlusUserSessionGrant(ctx, model.PlusUserSessionGrant{SessionID: john.ID, RequestID: "req1"})
	require.NoError(t, err)
	assert.True(t, ok)

	ok, err = provider.SavePlusUserSessionGrant(ctx, model.PlusUserSessionGrant{SessionID: john.ID, RequestID: "req2", ClientID: "app", Subject: "sub", SID: "sid", Issuer: "https://auth.example.com"})
	require.NoError(t, err)
	assert.True(t, ok)

	ok, err = provider.SavePlusUserSessionGrant(ctx, model.PlusUserSessionGrant{SessionID: uuid.New(), RequestID: "req3"})
	require.NoError(t, err)
	assert.False(t, ok, "a missing record takes no grant")

	// Requirement 6: one statement matches both the id and the username, so another user's record is not revoked and
	// looks exactly like a missing one.
	ok, err = provider.RevokePlusUserSession(ctx, harry.ID, "john", "self", now)
	require.NoError(t, err)
	assert.False(t, ok)

	ok, err = provider.RevokePlusUserSession(ctx, johnCased.ID, "john", "self", now)
	require.NoError(t, err)
	assert.False(t, ok, "a username differing only in case is another user")

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

	ok, err = provider.SavePlusUserSessionGrant(ctx, model.PlusUserSessionGrant{SessionID: john.ID, RequestID: "req4"})
	require.NoError(t, err)
	assert.False(t, ok, "a revoked record takes no grant")

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

	grants, err := provider.LoadPlusUserSessionGrants(ctx, john.ID)
	require.NoError(t, err)
	assert.Equal(t, []model.PlusUserSessionGrant{
		{SessionID: john.ID, RequestID: "req1"},
		{SessionID: john.ID, RequestID: "req2", ClientID: "app", Subject: "sub", SID: "sid", Issuer: "https://auth.example.com"},
	}, grants)

	record, err = provider.LoadPlusUserSession(ctx, john.ID)
	require.NoError(t, err)
	assert.Equal(t, "self", record.RevokedBy)
	assert.Equal(t, 2, record.Grants)

	require.NoError(t, provider.UnclaimPlusUserSession(ctx, john.ID))

	ids, err = provider.LoadPlusUserSessionUnprocessedIDs(ctx, now, 10)
	require.NoError(t, err)
	assert.Equal(t, []uuid.UUID{john.ID}, ids)

	count, err := provider.RevokePlusUserSessionsByUsername(ctx, "JOHN", "cli", now)
	require.NoError(t, err)
	assert.Equal(t, int64(0), count, "the username is matched exactly")

	count, err = provider.RevokePlusUserSessionsByUsername(ctx, "john", "cli", now)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count, "only the unrevoked record of john")

	t.Run("End", func(t *testing.T) {
		fresh, revoked := newTestPlusUserSession(t, "harry", now), newTestPlusUserSession(t, "harry", now)

		require.NoError(t, provider.SavePlusUserSession(ctx, fresh))
		require.NoError(t, provider.SavePlusUserSession(ctx, revoked))

		ok, err := provider.RevokePlusUserSession(ctx, revoked.ID, "harry", "self", now)
		require.NoError(t, err)
		require.True(t, ok)

		ok, err = provider.EndPlusUserSession(ctx, fresh.ID, "john", "logout", now)
		require.NoError(t, err)
		assert.False(t, ok, "only the record's own user ends it")

		for _, id := range []uuid.UUID{fresh.ID, revoked.ID} {
			ok, err = provider.EndPlusUserSession(ctx, id, "harry", "logout", now)
			require.NoError(t, err)
			assert.True(t, ok)

			ok, err = provider.EndPlusUserSession(ctx, id, "harry", "logout", now)
			require.NoError(t, err)
			assert.False(t, ok, "a record is claimed once")
		}

		record, err := provider.LoadPlusUserSession(ctx, fresh.ID)
		require.NoError(t, err)
		assert.True(t, record.RevokedAt.Valid)
		assert.True(t, record.ProcessedAt.Valid)
		assert.Equal(t, "logout", record.RevokedBy)

		record, err = provider.LoadPlusUserSession(ctx, revoked.ID)
		require.NoError(t, err)
		assert.True(t, record.ProcessedAt.Valid)
		assert.Equal(t, "self", record.RevokedBy, "an earlier revoke keeps its attribution")
	})

	t.Run("Replace", func(t *testing.T) {
		previous := newTestPlusUserSession(t, "harry", now)

		require.NoError(t, provider.SavePlusUserSession(ctx, previous))

		ok, err := provider.SavePlusUserSessionGrant(ctx, model.PlusUserSessionGrant{SessionID: previous.ID, RequestID: "replace1"})
		require.NoError(t, err)
		require.True(t, ok)

		other := newTestPlusUserSession(t, "john", now)

		ok, err = provider.ReplacePlusUserSession(ctx, previous.ID, other, "replaced")
		require.NoError(t, err)
		assert.False(t, ok, "only the same user re-authenticates")

		next := newTestPlusUserSession(t, "harry", now)

		ok, err = provider.ReplacePlusUserSession(ctx, previous.ID, next, "replaced")
		require.NoError(t, err)
		assert.True(t, ok)

		record, err := provider.LoadPlusUserSession(ctx, previous.ID)
		require.NoError(t, err)
		assert.True(t, record.RevokedAt.Valid)
		assert.True(t, record.ProcessedAt.Valid, "a replaced record must never be processed")

		grants, err := provider.LoadPlusUserSessionGrants(ctx, next.ID)
		require.NoError(t, err)
		require.Len(t, grants, 1, "the grants move to the replacement")
		assert.Equal(t, "replace1", grants[0].RequestID)

		// Requirement 4: a re-authentication racing a revoke of the record it replaces fails, and changes nothing.
		ok, err = provider.RevokePlusUserSession(ctx, next.ID, "harry", "self", now)
		require.NoError(t, err)
		require.True(t, ok)

		escape := newTestPlusUserSession(t, "harry", now)

		ok, err = provider.ReplacePlusUserSession(ctx, next.ID, escape, "replaced")
		require.NoError(t, err)
		assert.False(t, ok)

		record, err = provider.LoadPlusUserSession(ctx, escape.ID)
		require.NoError(t, err)
		assert.Nil(t, record, "no replacement is recorded")

		grants, err = provider.LoadPlusUserSessionGrants(ctx, next.ID)
		require.NoError(t, err)
		assert.Len(t, grants, 1, "the revoked record keeps its grants for processing")

		record, err = provider.LoadPlusUserSession(ctx, next.ID)
		require.NoError(t, err)
		assert.False(t, record.ProcessedAt.Valid, "the revoke is still processed")
	})

	restart := newTestPlusUserSession(t, "john", now)
	require.NoError(t, provider.SavePlusUserSession(ctx, restart))

	count, err = provider.ClosePlusUserSessions(ctx, "restart", now)
	require.NoError(t, err)
	assert.Equal(t, int64(3), count, "johnCased, harry and the restart record")

	require.NoError(t, provider.PurgePlusUserSessions(ctx, now.Add(time.Second), now))

	record, err = provider.LoadPlusUserSession(ctx, john.ID)
	require.NoError(t, err)
	assert.Nil(t, record)

	grants, err = provider.LoadPlusUserSessionGrants(ctx, john.ID)
	require.NoError(t, err)
	assert.Empty(t, grants, "the grants of purged records are purged")
}

// TestSQLProviderPlusUserSessionGrantsConcurrent checks that grants recorded concurrently in
// one session, while the session's revocation is claimed, are never lost. Every grant reported saved must be among the
// grants loaded after the claim, which are the ones the revocation acts on.
func TestSQLProviderPlusUserSessionGrantsConcurrent(t *testing.T) {
	for name, provider := range newTestPlusProviders(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()

			require.NoError(t, provider.PlusUserSessionsSchemaEnsure(ctx))

			now := time.Unix(1760000000, 0).UTC()
			record := newTestPlusUserSession(t, "john", now)

			require.NoError(t, provider.SavePlusUserSession(ctx, record))

			const workers, perWorker = 8, 25

			var (
				wg      sync.WaitGroup
				mu      sync.Mutex
				saved   = map[string]bool{}
				claimed = make(chan struct{})
			)

			for w := range workers {
				wg.Go(func() {
					for i := range perWorker {
						if w == 0 && i == perWorker/2 {
							close(claimed)
						}

						id := fmt.Sprintf("w%d-%d", w, i)

						// Errors, such as SQLite reporting the database busy, fail closed: the grant isn't issued.
						if ok, err := provider.SavePlusUserSessionGrant(ctx, model.PlusUserSessionGrant{SessionID: record.ID, RequestID: id}); err == nil && ok {
							mu.Lock()
							saved[id] = true
							mu.Unlock()
						}
					}
				})
			}

			<-claimed

			var ok bool

			for {
				var err error

				if ok, err = provider.ClaimPlusUserSession(ctx, record.ID, now); err == nil {
					break
				}
			}

			require.True(t, ok)

			grants, err := provider.LoadPlusUserSessionGrants(ctx, record.ID)
			require.NoError(t, err)

			wg.Wait()

			loaded := map[string]bool{}

			for _, g := range grants {
				loaded[g.RequestID] = true
			}

			mu.Lock()
			defer mu.Unlock()

			require.NotEmpty(t, saved)

			for id := range saved {
				assert.True(t, loaded[id], "grant %s was reported saved but is not revoked with the session", id)
			}

			after, err := provider.LoadPlusUserSessionGrants(ctx, record.ID)
			require.NoError(t, err)
			assert.Len(t, after, len(grants), "no grant is added after the claim")
		})
	}
}
