// SPDX-FileCopyrightText: 2026 Authelia
// SPDX-FileCopyrightText: 2026 authelia-plus contributors
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

		// Dropped rather than emptied, so a schema change is picked up.
		for _, table := range []string{tablePlusUserSessionGrant, tablePlusUserSession} {
			_, err = provider.db.ExecContext(ctx, fmt.Sprintf("DROP TABLE IF EXISTS %s;", table))
			require.NoError(t, err)
		}

		require.NoError(t, provider.PlusUserSessionsSchemaEnsure(ctx))

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
	lease := now.Add(-5 * time.Minute)

	john, johnOther, johnCased, johnPadded, harry := newTestPlusUserSession(t, "john", now), newTestPlusUserSession(t, "john", now), newTestPlusUserSession(t, "John", now), newTestPlusUserSession(t, "john ", now), newTestPlusUserSession(t, "harry", now)

	for _, s := range []model.PlusUserSession{john, johnOther, johnCased, johnPadded, harry} {
		require.NoError(t, provider.SavePlusUserSession(ctx, s))
	}

	require.Error(t, provider.SavePlusUserSession(ctx, john), "the id is the primary key")

	ok, err := provider.UpdatePlusUserSessionActivity(ctx, johnOther.ID, now.Add(time.Minute), now.Add(2*time.Hour))
	require.NoError(t, err)
	assert.True(t, ok)

	ok, err = provider.UpdatePlusUserSessionActivity(ctx, uuid.New(), now.Add(time.Minute), now.Add(2*time.Hour))
	require.NoError(t, err)
	assert.False(t, ok, "no record matched")

	sessions, err := provider.LoadPlusUserSessionsActive(ctx, "john", now)
	require.NoError(t, err)
	require.Len(t, sessions, 2, "usernames are matched exactly, so 'John' and 'john ' are someone else")
	assert.Equal(t, johnOther.ID, sessions[0].ID, "most recently active first")
	assert.Equal(t, john.ID, sessions[1].ID)

	sessions, err = provider.LoadPlusUserSessionsActive(ctx, "john", now.Add(90*time.Minute))
	require.NoError(t, err)
	require.Len(t, sessions, 1, "expired records are not listed")

	ok, err = provider.SavePlusUserSessionGrant(ctx, model.PlusUserSessionGrant{SessionID: john.ID, RequestID: "req1"})
	require.NoError(t, err)
	assert.True(t, ok)

	record, err := provider.LoadPlusUserSessionByRequestID(ctx, "req1")
	require.NoError(t, err)
	require.NotNil(t, record)
	assert.Equal(t, john.ID, record.ID)

	record, err = provider.LoadPlusUserSessionByRequestID(ctx, "unknown")
	require.NoError(t, err)
	assert.Nil(t, record)

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

	ok, err = provider.RevokePlusUserSession(ctx, johnPadded.ID, "john", "self", now)
	require.NoError(t, err)
	assert.False(t, ok, "a username differing only in trailing spaces is another user")

	ok, err = provider.RevokePlusUserSession(ctx, uuid.New(), "john", "self", now)
	require.NoError(t, err)
	assert.False(t, ok)

	record, err = provider.LoadPlusUserSession(ctx, harry.ID)
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

	revocations, err := provider.LoadPlusUserSessionRevocations(ctx, now.Add(-time.Minute))
	require.NoError(t, err)
	require.Len(t, revocations, 1)
	assert.Equal(t, john.ID, revocations[0].ID)
	assert.WithinDuration(t, now, revocations[0].RevokedAt, time.Second)

	revocations, err = provider.LoadPlusUserSessionRevocations(ctx, now.Add(time.Second))
	require.NoError(t, err)
	assert.Empty(t, revocations, "only revocations after since")

	ids, err := provider.LoadPlusUserSessionUnprocessedIDs(ctx, now.Add(-time.Second), lease, now, 10)
	require.NoError(t, err)
	assert.Empty(t, ids, "too recent to process")

	ids, err = provider.LoadPlusUserSessionUnprocessedIDs(ctx, now, lease, now, 10)
	require.NoError(t, err)
	assert.Equal(t, []uuid.UUID{john.ID}, ids)

	ok, err = provider.ClaimPlusUserSession(ctx, johnOther.ID, now, lease)
	require.NoError(t, err)
	assert.False(t, ok, "an unrevoked record can't be claimed")

	ok, err = provider.ClaimPlusUserSession(ctx, john.ID, now, lease)
	require.NoError(t, err)
	assert.True(t, ok)

	ok, err = provider.ClaimPlusUserSession(ctx, john.ID, now, lease)
	require.NoError(t, err)
	assert.False(t, ok, "a claim is held for the lease")

	ids, err = provider.LoadPlusUserSessionUnprocessedIDs(ctx, now, lease, now, 10)
	require.NoError(t, err)
	assert.Empty(t, ids, "a claimed record isn't offered while the lease holds")

	// Item 2: an instance that stopped mid-processing never completes or releases its claim; once the lease lapses
	// the record is offered and claimed again.
	later := now.Add(6 * time.Minute)

	ids, err = provider.LoadPlusUserSessionUnprocessedIDs(ctx, later, later.Add(-5*time.Minute), later, 10)
	require.NoError(t, err)
	assert.Equal(t, []uuid.UUID{john.ID}, ids)

	ok, err = provider.ClaimPlusUserSession(ctx, john.ID, later, later.Add(-5*time.Minute))
	require.NoError(t, err)
	assert.True(t, ok, "a lapsed claim is taken over")

	record, err = provider.LoadPlusUserSession(ctx, john.ID)
	require.NoError(t, err)
	assert.True(t, record.ClaimedAt.Valid)
	assert.False(t, record.ProcessedAt.Valid, "a claim alone isn't processing")

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
	assert.Equal(t, 2, record.Attempts, "each claim counts an attempt")

	retry := later.Add(time.Minute)

	require.NoError(t, provider.UnclaimPlusUserSession(ctx, john.ID, retry))

	ids, err = provider.LoadPlusUserSessionUnprocessedIDs(ctx, later, later, later, 10)
	require.NoError(t, err)
	assert.Empty(t, ids, "a released record waits for its retry")

	ids, err = provider.LoadPlusUserSessionUnprocessedIDs(ctx, retry, retry, retry, 10)
	require.NoError(t, err)
	assert.Equal(t, []uuid.UUID{john.ID}, ids, "a released record is offered again once due")

	ok, err = provider.ClaimPlusUserSession(ctx, john.ID, now, lease)
	require.NoError(t, err)
	require.True(t, ok)

	require.NoError(t, provider.CompletePlusUserSession(ctx, john.ID, now))

	ids, err = provider.LoadPlusUserSessionUnprocessedIDs(ctx, later, later, later, 10)
	require.NoError(t, err)
	assert.Empty(t, ids, "a processed record is never offered again")

	ok, err = provider.ClaimPlusUserSession(ctx, john.ID, later, later)
	require.NoError(t, err)
	assert.False(t, ok)

	record, err = provider.LoadPlusUserSession(ctx, john.ID)
	require.NoError(t, err)
	assert.True(t, record.ProcessedAt.Valid)
	assert.False(t, record.ClaimedAt.Valid)

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
		}

		ok, err = provider.SavePlusUserSessionGrant(ctx, model.PlusUserSessionGrant{SessionID: fresh.ID, RequestID: "after-end"})
		require.NoError(t, err)
		assert.False(t, ok, "an ended record takes no grant")

		// Item 1: ending doesn't claim, so the poller still processes the revocation after the logout's own attempt.
		record, err := provider.LoadPlusUserSession(ctx, fresh.ID)
		require.NoError(t, err)
		assert.True(t, record.RevokedAt.Valid)
		assert.False(t, record.ProcessedAt.Valid)
		assert.False(t, record.ClaimedAt.Valid)
		assert.Equal(t, "logout", record.RevokedBy)

		ids, err := provider.LoadPlusUserSessionUnprocessedIDs(ctx, now, lease, now, 100)
		require.NoError(t, err)
		assert.Contains(t, ids, fresh.ID)

		record, err = provider.LoadPlusUserSession(ctx, revoked.ID)
		require.NoError(t, err)
		assert.Equal(t, "self", record.RevokedBy, "an earlier revoke keeps its attribution")

		require.NoError(t, provider.CompletePlusUserSession(ctx, fresh.ID, now))

		ok, err = provider.EndPlusUserSession(ctx, fresh.ID, "harry", "logout", now)
		require.NoError(t, err)
		assert.False(t, ok, "a processed record has nothing left to end")
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

		record, err = provider.LoadPlusUserSession(ctx, next.ID)
		require.NoError(t, err)
		assert.Equal(t, 1, record.Grants, "the grants' count moves with them")

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
	assert.Equal(t, int64(4), count, "johnCased, johnPadded, harry and the restart record")

	// johnOther was revoked by the CLI and never processed.
	_, err = provider.SavePlusUserSessionGrant(ctx, model.PlusUserSessionGrant{SessionID: johnOther.ID, RequestID: "unprocessed"})
	require.NoError(t, err)

	require.NoError(t, provider.PurgePlusUserSessions(ctx, now.Add(time.Second), now))

	record, err = provider.LoadPlusUserSession(ctx, john.ID)
	require.NoError(t, err)
	assert.Nil(t, record)

	grants, err = provider.LoadPlusUserSessionGrants(ctx, john.ID)
	require.NoError(t, err)
	assert.Empty(t, grants, "the grants of purged records are purged")

	// Item 3: a revoked record that was never processed is kept, grants and all, however old.
	record, err = provider.LoadPlusUserSession(ctx, johnOther.ID)
	require.NoError(t, err)
	require.NotNil(t, record)
	assert.False(t, record.ProcessedAt.Valid)
}

func TestSQLProviderPlusUserSessionsRevokeOthers(t *testing.T) {
	for name, provider := range newTestPlusProviders(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			require.NoError(t, provider.PlusUserSessionsSchemaEnsure(ctx))

			now := time.Unix(1760000000, 0).UTC()

			current, live, hidden, harry := newTestPlusUserSession(t, "john", now), newTestPlusUserSession(t, "john", now), newTestPlusUserSession(t, "john", now), newTestPlusUserSession(t, "harry", now)

			// Expired by its expires_at, which a lagging activity write may have left behind a live session.
			hidden.ExpiresAt = now.Add(-time.Hour)

			for _, s := range []model.PlusUserSession{current, live, hidden, harry} {
				require.NoError(t, provider.SavePlusUserSession(ctx, s))
			}

			ok, err := provider.RevokePlusUserSession(ctx, live.ID, "john", "self", now)
			require.NoError(t, err)
			require.True(t, ok)

			// live is revoked but unprocessed; hidden is unrevoked.
			count, ids, err := provider.RevokeOtherPlusUserSessions(ctx, "john", current.ID, "self", now)
			require.NoError(t, err)
			assert.Equal(t, int64(1), count, "only hidden was unrevoked")
			assert.ElementsMatch(t, []uuid.UUID{live.ID, hidden.ID}, ids, "every other revoked and unprocessed record of the user")

			for _, id := range []uuid.UUID{current.ID, harry.ID} {
				record, err := provider.LoadPlusUserSession(ctx, id)
				require.NoError(t, err)
				assert.False(t, record.RevokedAt.Valid)
			}

			record, err := provider.LoadPlusUserSession(ctx, hidden.ID)
			require.NoError(t, err)
			assert.True(t, record.RevokedAt.Valid, "an expired-looking session is revoked too")

			count, ids, err = provider.RevokeOtherPlusUserSessions(ctx, "JOHN", uuid.Nil, "self", now)
			require.NoError(t, err)
			assert.Zero(t, count, "the username is matched exactly")
			assert.Empty(t, ids)
		})
	}
}

func TestSQLProviderPlusUserSessionsRetryOrder(t *testing.T) {
	for name, provider := range newTestPlusProviders(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			require.NoError(t, provider.PlusUserSessionsSchemaEnsure(ctx))

			now := time.Unix(1760000000, 0).UTC()

			failing, fresh := newTestPlusUserSession(t, "john", now), newTestPlusUserSession(t, "john", now)

			for _, s := range []model.PlusUserSession{failing, fresh} {
				require.NoError(t, provider.SavePlusUserSession(ctx, s))
			}

			// failing was revoked first, so it'd come first on age alone.
			ok, err := provider.RevokePlusUserSession(ctx, failing.ID, "john", "self", now.Add(-time.Minute))
			require.NoError(t, err)
			require.True(t, ok)

			ok, err = provider.RevokePlusUserSession(ctx, fresh.ID, "john", "self", now)
			require.NoError(t, err)
			require.True(t, ok)

			ok, err = provider.ClaimPlusUserSession(ctx, failing.ID, now, now)
			require.NoError(t, err)
			require.True(t, ok)

			require.NoError(t, provider.UnclaimPlusUserSession(ctx, failing.ID, now))

			ids, err := provider.LoadPlusUserSessionUnprocessedIDs(ctx, now, now, now, 10)
			require.NoError(t, err)
			assert.Equal(t, []uuid.UUID{fresh.ID, failing.ID}, ids, "a record that failed goes after one never attempted")

			// Logouts and switches go after the revocations by the user or an administrator, however old.
			loggedOut, switched, cli := newTestPlusUserSession(t, "john", now), newTestPlusUserSession(t, "john", now), newTestPlusUserSession(t, "john", now)

			for _, s := range []model.PlusUserSession{loggedOut, switched, cli} {
				require.NoError(t, provider.SavePlusUserSession(ctx, s))
			}

			for _, r := range []struct {
				id uuid.UUID
				by string
				at time.Time
			}{{loggedOut.ID, "logout", now.Add(-time.Hour)}, {switched.ID, "switched", now.Add(-2 * time.Hour)}, {cli.ID, "cli", now}} {
				ok, err = provider.RevokePlusUserSession(ctx, r.id, "john", r.by, r.at)
				require.NoError(t, err)
				require.True(t, ok)
			}

			ids, err = provider.LoadPlusUserSessionUnprocessedIDs(ctx, now, now, now, 10)
			require.NoError(t, err)
			assert.Equal(t, []uuid.UUID{fresh.ID, cli.ID, failing.ID, switched.ID, loggedOut.ID}, ids)
		})
	}
}

// The purge deletes the grants of exactly the records it deletes. A re-authentication moving grants to its new record
// while the purge runs keeps them: a purge matching grants by their record being absent would delete them on
// PostgreSQL, whose re-check of the moved rows still can't see the new record.
func TestSQLProviderPlusUserSessionsPurgeWhileReplacing(t *testing.T) {
	for name, provider := range newTestPlusProviders(t) {
		if name == providerSQLite {
			// SQLite serializes writers, so the two can't interleave.
			continue
		}

		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Unix(1760000000, 0).UTC()

			old, next := newTestPlusUserSession(t, "john", now), newTestPlusUserSession(t, "john", now)
			require.NoError(t, provider.SavePlusUserSession(ctx, old))

			ok, err := provider.SavePlusUserSessionGrant(ctx, model.PlusUserSessionGrant{SessionID: old.ID, RequestID: "req1"})
			require.NoError(t, err)
			require.True(t, ok)

			// The re-authentication's transaction, held open with the grant moved.
			tx, err := provider.db.BeginTxx(ctx, nil)
			require.NoError(t, err)

			_, err = tx.ExecContext(ctx, provider.db.Rebind(queryPlusUserSessionReplaceClose), now, "replaced", now, old.ID, "john")
			require.NoError(t, err)

			_, err = tx.ExecContext(ctx, provider.db.Rebind(queryPlusUserSessionInsert), next.ID, next.Username, next.CreatedAt, next.LastActive, next.ExpiresAt, next.IP, next.UserAgent, 1)
			require.NoError(t, err)

			_, err = tx.ExecContext(ctx, provider.db.Rebind(queryPlusUserSessionGrantMove), next.ID, old.ID)
			require.NoError(t, err)

			purged := make(chan error, 1)

			go func() {
				purged <- provider.PurgePlusUserSessions(ctx, now.Add(-time.Hour), now.Add(-time.Hour))
			}()

			time.Sleep(200 * time.Millisecond)

			require.NoError(t, tx.Commit())
			require.NoError(t, <-purged)

			grants, err := provider.LoadPlusUserSessionGrants(ctx, next.ID)
			require.NoError(t, err)
			assert.Len(t, grants, 1, "the moved grant survives the purge")
		})
	}
}

// The token endpoint looks a grant's record up by request ID on every token request, so request_id needs an index of
// its own: the primary key is led by session_id.
func TestSQLProviderPlusUserSessionsGrantRequestIDIndex(t *testing.T) {
	queries := map[string]string{
		providerSQLite:   `SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND tbl_name = 'plus_user_session_grant' AND name = 'plus_user_session_grant_request_id';`,
		providerMySQL:    `SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'plus_user_session_grant' AND index_name = 'plus_user_session_grant_request_id' AND column_name = 'request_id' AND seq_in_index = 1;`,
		providerPostgres: `SELECT COUNT(*) FROM pg_indexes WHERE tablename = 'plus_user_session_grant' AND indexname = 'plus_user_session_grant_request_id' AND indexdef LIKE '%(request_id)';`,
	}

	for name, provider := range newTestPlusProviders(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			require.NoError(t, provider.PlusUserSessionsSchemaEnsure(ctx))

			var count int

			require.NoError(t, provider.db.GetContext(ctx, &count, queries[name]))
			assert.Equal(t, 1, count)
		})
	}
}

func TestSQLProviderPlusUserSessionsGrantCap(t *testing.T) {
	for name, provider := range newTestPlusProviders(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			require.NoError(t, provider.PlusUserSessionsSchemaEnsure(ctx))

			now := time.Unix(1760000000, 0).UTC()

			record := newTestPlusUserSession(t, "john", now)

			require.NoError(t, provider.SavePlusUserSession(ctx, record))

			// Filled directly: a thousand transactions would make this the slowest test by far.
			_, err := provider.db.ExecContext(ctx, provider.db.Rebind(`UPDATE plus_user_session SET grants = ? WHERE id = ?;`), model.PlusUserSessionMaxGrants-1, record.ID)
			require.NoError(t, err)

			ok, err := provider.SavePlusUserSessionGrant(ctx, model.PlusUserSessionGrant{SessionID: record.ID, RequestID: "last"})
			require.NoError(t, err)
			assert.True(t, ok)

			ok, err = provider.SavePlusUserSessionGrant(ctx, model.PlusUserSessionGrant{SessionID: record.ID, RequestID: "one-too-many"})
			require.NoError(t, err)
			assert.False(t, ok, "a full record takes no more grants")

			next := newTestPlusUserSession(t, "john", now)

			ok, err = provider.ReplacePlusUserSession(ctx, record.ID, next, "replaced")
			require.NoError(t, err)
			require.True(t, ok)

			ok, err = provider.SavePlusUserSessionGrant(ctx, model.PlusUserSessionGrant{SessionID: next.ID, RequestID: "after-replace"})
			require.NoError(t, err)
			assert.False(t, ok, "a re-authentication doesn't reset the count")
		})
	}
}

// TestSQLProviderPlusUserSessionGrantsConcurrent checks that grants recorded concurrently in one session, while the
// session is revoked, are never lost. Every grant reported saved must be among the grants loaded after the revoke,
// which are the ones a logout or the poller acts on. On SQLite, which serializes writers, this can't tell the row lock
// apart from a check-then-insert; the MySQL and PostgreSQL runs are the real proof.
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
				revoked = make(chan struct{})
			)

			for w := range workers {
				wg.Go(func() {
					for i := range perWorker {
						if w == 0 && i == perWorker/2 {
							close(revoked)
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

			<-revoked

			var ok bool

			for {
				var err error

				if ok, err = provider.RevokePlusUserSession(ctx, record.ID, "john", "self", now); err == nil {
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
			assert.Len(t, after, len(grants), "no grant is added after the revoke")
		})
	}
}
