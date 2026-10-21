// SPDX-FileCopyrightText: 2026 authelia-plus contributors
//
// SPDX-License-Identifier: Apache-2.0

package mocks

import (
	"context"
	"database/sql"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/authelia/authelia/v4/internal/model"
)

// authelia-plus: an in-memory store of the user session records, for tests.

// NewPlusSessionsStore returns an empty PlusSessionsStore.
func NewPlusSessionsStore() *PlusSessionsStore {
	return &PlusSessionsStore{Records: map[uuid.UUID]*model.PlusUserSession{}, Errors: map[string]error{}}
}

// PlusSessionsStore is an in-memory store of the user session records. A method whose name is a key of Errors fails
// with that error.
type PlusSessionsStore struct {
	mu sync.Mutex

	Records map[uuid.UUID]*model.PlusUserSession
	Grants  []model.PlusUserSessionGrant
	Errors  map[string]error

	// RevocationsSince records the since argument of each LoadPlusUserSessionRevocations call.
	RevocationsSince []time.Time

	// RevocationsError, when set, is the error of a LoadPlusUserSessionRevocations call by its since argument.
	RevocationsError func(since time.Time) error
}

// Get returns a copy of the record with this ID, or nil.
func (s *PlusSessionsStore) Get(id uuid.UUID) *model.PlusUserSession {
	s.mu.Lock()
	defer s.mu.Unlock()

	if r, ok := s.Records[id]; ok {
		c := *r

		return &c
	}

	return nil
}

// SetError makes the method fail with err, or succeed again when err is nil.
func (s *PlusSessionsStore) SetError(method string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err == nil {
		delete(s.Errors, method)
	} else {
		s.Errors[method] = err
	}
}

func (s *PlusSessionsStore) PlusUserSessionsSchemaEnsure(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.Errors["PlusUserSessionsSchemaEnsure"]
}

func (s *PlusSessionsStore) SavePlusUserSession(_ context.Context, r model.PlusUserSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.Errors["SavePlusUserSession"]; err != nil {
		return err
	}

	s.Records[r.ID] = &r

	return nil
}

func (s *PlusSessionsStore) LoadPlusUserSession(_ context.Context, id uuid.UUID) (*model.PlusUserSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.Errors["LoadPlusUserSession"]; err != nil {
		return nil, err
	}

	if r, ok := s.Records[id]; ok {
		c := *r

		return &c, nil
	}

	return nil, nil
}

func (s *PlusSessionsStore) LoadPlusUserSessionsActive(_ context.Context, username string, now time.Time) (records []model.PlusUserSession, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err = s.Errors["LoadPlusUserSessionsActive"]; err != nil {
		return nil, err
	}

	for _, r := range s.Records {
		if r.Username == username && !r.RevokedAt.Valid && r.ExpiresAt.After(now) {
			records = append(records, *r)
		}
	}

	sort.Slice(records, func(i, j int) bool { return records[i].LastActive.After(records[j].LastActive) })

	return records, nil
}

func (s *PlusSessionsStore) UpdatePlusUserSessionActivity(_ context.Context, id uuid.UUID, lastActive, expiresAt time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.Errors["UpdatePlusUserSessionActivity"]; err != nil {
		return false, err
	}

	r, ok := s.Records[id]
	if !ok || r.RevokedAt.Valid {
		return false, nil
	}

	r.LastActive, r.ExpiresAt = lastActive, expiresAt

	return true, nil
}

func (s *PlusSessionsStore) LoadPlusUserSessionByRequestID(_ context.Context, requestID string) (*model.PlusUserSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.Errors["LoadPlusUserSessionByRequestID"]; err != nil {
		return nil, err
	}

	for _, g := range s.Grants {
		if g.RequestID == requestID {
			if r, ok := s.Records[g.SessionID]; ok {
				c := *r

				return &c, nil
			}
		}
	}

	return nil, nil
}

func (s *PlusSessionsStore) ReplacePlusUserSession(_ context.Context, previous uuid.UUID, r model.PlusUserSession, revokedBy string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.Errors["ReplacePlusUserSession"]; err != nil {
		return false, err
	}

	p, ok := s.Records[previous]
	if !ok || p.Username != r.Username || p.RevokedAt.Valid || p.ProcessedAt.Valid {
		return false, nil
	}

	p.RevokedAt, p.RevokedBy, p.ProcessedAt = sql.NullTime{Time: r.CreatedAt, Valid: true}, revokedBy, sql.NullTime{Time: r.CreatedAt, Valid: true}

	r.Grants = p.Grants
	s.Records[r.ID] = &r

	for i := range s.Grants {
		if s.Grants[i].SessionID == previous {
			s.Grants[i].SessionID = r.ID
		}
	}

	return true, nil
}

func (s *PlusSessionsStore) SavePlusUserSessionGrant(_ context.Context, grant model.PlusUserSessionGrant) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.Errors["SavePlusUserSessionGrant"]; err != nil {
		return false, err
	}

	r, ok := s.Records[grant.SessionID]
	if !ok || r.RevokedAt.Valid || r.ProcessedAt.Valid || r.Grants >= model.PlusUserSessionMaxGrants {
		return false, nil
	}

	r.Grants++

	s.Grants = append(s.Grants, grant)

	return true, nil
}

func (s *PlusSessionsStore) LoadPlusUserSessionGrants(_ context.Context, id uuid.UUID) (grants []model.PlusUserSessionGrant, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err = s.Errors["LoadPlusUserSessionGrants"]; err != nil {
		return nil, err
	}

	for _, g := range s.Grants {
		if g.SessionID == id {
			grants = append(grants, g)
		}
	}

	return grants, nil
}

func (s *PlusSessionsStore) RevokePlusUserSession(_ context.Context, id uuid.UUID, username, revokedBy string, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.Errors["RevokePlusUserSession"]; err != nil {
		return false, err
	}

	r, ok := s.Records[id]
	if !ok || r.Username != username || r.RevokedAt.Valid {
		return false, nil
	}

	r.RevokedAt, r.RevokedBy = sql.NullTime{Time: now, Valid: true}, revokedBy

	return true, nil
}

func (s *PlusSessionsStore) RevokeOtherPlusUserSessions(_ context.Context, username string, except uuid.UUID, revokedBy string, now time.Time) (count int64, ids []uuid.UUID, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err = s.Errors["RevokeOtherPlusUserSessions"]; err != nil {
		return 0, nil, err
	}

	for id, r := range s.Records {
		if r.Username != username || id == except {
			continue
		}

		if !r.RevokedAt.Valid {
			r.RevokedAt, r.RevokedBy = sql.NullTime{Time: now, Valid: true}, revokedBy
			count++
		}

		if !r.ProcessedAt.Valid {
			ids = append(ids, id)
		}
	}

	return count, ids, nil
}

func (s *PlusSessionsStore) RevokePlusUserSessionsByUsername(_ context.Context, username, revokedBy string, now time.Time) (count int64, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err = s.Errors["RevokePlusUserSessionsByUsername"]; err != nil {
		return 0, err
	}

	for _, r := range s.Records {
		if r.Username == username && !r.RevokedAt.Valid {
			r.RevokedAt, r.RevokedBy = sql.NullTime{Time: now, Valid: true}, revokedBy
			count++
		}
	}

	return count, nil
}

func (s *PlusSessionsStore) ClosePlusUserSessions(_ context.Context, revokedBy string, now time.Time) (count int64, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err = s.Errors["ClosePlusUserSessions"]; err != nil {
		return 0, err
	}

	for _, r := range s.Records {
		if !r.RevokedAt.Valid {
			r.RevokedAt, r.RevokedBy, r.ProcessedAt = sql.NullTime{Time: now, Valid: true}, revokedBy, sql.NullTime{Time: now, Valid: true}
			count++
		}
	}

	return count, nil
}

func (s *PlusSessionsStore) EndPlusUserSession(_ context.Context, id uuid.UUID, username, revokedBy string, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.Errors["EndPlusUserSession"]; err != nil {
		return false, err
	}

	r, ok := s.Records[id]
	if !ok || r.Username != username || r.ProcessedAt.Valid {
		return false, nil
	}

	if !r.RevokedAt.Valid {
		r.RevokedAt, r.RevokedBy = sql.NullTime{Time: now, Valid: true}, revokedBy
	}

	return true, nil
}

func (s *PlusSessionsStore) LoadPlusUserSessionRevocations(_ context.Context, since time.Time) (revocations []model.PlusUserSessionRevocation, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.RevocationsSince = append(s.RevocationsSince, since)

	if err = s.Errors["LoadPlusUserSessionRevocations"]; err != nil {
		return nil, err
	}

	if s.RevocationsError != nil {
		if err = s.RevocationsError(since); err != nil {
			return nil, err
		}
	}

	for id, r := range s.Records {
		if r.RevokedAt.Valid && r.RevokedAt.Time.After(since) {
			revocations = append(revocations, model.PlusUserSessionRevocation{ID: id, RevokedAt: r.RevokedAt.Time})
		}
	}

	return revocations, nil
}

func (s *PlusSessionsStore) LoadPlusUserSessionUnprocessedIDs(_ context.Context, before, leaseBefore, now time.Time, limit int) (ids []uuid.UUID, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err = s.Errors["LoadPlusUserSessionUnprocessedIDs"]; err != nil {
		return nil, err
	}

	var due []*model.PlusUserSession

	for _, r := range s.Records {
		if r.RevokedAt.Valid && !r.RevokedAt.Time.After(before) && !r.ProcessedAt.Valid && (!r.ClaimedAt.Valid || r.ClaimedAt.Time.Before(leaseBefore)) && (!r.RetryAt.Valid || !r.RetryAt.Time.After(now)) {
			due = append(due, r)
		}
	}

	sort.Slice(due, func(i, j int) bool {
		if pi, pj := mockPlusPriority(due[i]), mockPlusPriority(due[j]); pi != pj {
			return pi < pj
		}

		if due[i].Attempts != due[j].Attempts {
			return due[i].Attempts < due[j].Attempts
		}

		return due[i].RevokedAt.Time.Before(due[j].RevokedAt.Time)
	})

	for _, r := range due[:min(len(due), limit)] {
		ids = append(ids, r.ID)
	}

	return ids, nil
}

func mockPlusPriority(r *model.PlusUserSession) int {
	if r.RevokedBy == "self" || r.RevokedBy == "cli" {
		return 0
	}

	return 1
}

func (s *PlusSessionsStore) ClaimPlusUserSession(_ context.Context, id uuid.UUID, now, leaseBefore time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.Errors["ClaimPlusUserSession"]; err != nil {
		return false, err
	}

	r, ok := s.Records[id]
	if !ok || !r.RevokedAt.Valid || r.ProcessedAt.Valid || (r.ClaimedAt.Valid && !r.ClaimedAt.Time.Before(leaseBefore)) {
		return false, nil
	}

	r.ClaimedAt = sql.NullTime{Time: now, Valid: true}
	r.Attempts++

	return true, nil
}

func (s *PlusSessionsStore) CompletePlusUserSession(ctx context.Context, id uuid.UUID, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.Errors["CompletePlusUserSession"]; err != nil {
		return err
	}

	// As a database would, so a write made with a cancelled context fails.
	if err := ctx.Err(); err != nil {
		return err
	}

	if r, ok := s.Records[id]; ok && !r.ProcessedAt.Valid {
		r.ProcessedAt, r.ClaimedAt = sql.NullTime{Time: now, Valid: true}, sql.NullTime{}
	}

	return nil
}

func (s *PlusSessionsStore) UnclaimPlusUserSession(ctx context.Context, id uuid.UUID, retryAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.Errors["UnclaimPlusUserSession"]; err != nil {
		return err
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	if r, ok := s.Records[id]; ok && !r.ProcessedAt.Valid {
		r.ClaimedAt, r.RetryAt = sql.NullTime{}, sql.NullTime{Time: retryAt, Valid: true}
	}

	return nil
}

func (s *PlusSessionsStore) PurgePlusUserSessions(_ context.Context, revokedBefore, expiredBefore time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.Errors["PurgePlusUserSessions"]; err != nil {
		return err
	}

	for id, r := range s.Records {
		if (r.RevokedAt.Valid && r.RevokedAt.Time.Before(revokedBefore) && r.ProcessedAt.Valid) || (!r.RevokedAt.Valid && r.ExpiresAt.Before(expiredBefore)) {
			delete(s.Records, id)
		}
	}

	grants := s.Grants[:0]

	for _, g := range s.Grants {
		if _, ok := s.Records[g.SessionID]; ok {
			grants = append(grants, g)
		}
	}

	s.Grants = grants

	return nil
}
