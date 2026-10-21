// SPDX-FileCopyrightText: 2026 authelia-plus contributors
//
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"github.com/google/uuid"
	"github.com/valyala/fasthttp"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
)

// authelia-plus: revoked user sessions are rejected wherever a session is loaded.

// PlusSessions tracks the user session records which the user can list and revoke.
type PlusSessions interface {
	// Revoked reports whether the user session record with this ID was revoked. It must not block on I/O.
	Revoked(id uuid.UUID) bool

	// Touch records activity on the user session. It must not block on I/O.
	Touch(userSession *UserSession, config schema.SessionCookie)
}

// SetPlusSessions makes every session of this provider reject the user sessions which plus reports as revoked.
func (p *Provider) SetPlusSessions(plus PlusSessions) {
	for _, s := range p.sessions {
		s.plus = plus
	}
}

// plusRevoked reports whether the loaded user session was revoked, destroying it if so. The caller must treat the
// session as anonymous whenever this returns true, even if destroying it failed. Every authentication records the
// session, so an authenticated session without a PlusID predates the records: it can't be revoked, so it's rejected
// too, and its user logs in once more.
func (p *Session) plusRevoked(ctx *fasthttp.RequestCtx, userSession *UserSession) bool {
	if p.plus == nil || userSession.Username == "" {
		return false
	}

	if userSession.PlusID == uuid.Nil || p.plus.Revoked(userSession.PlusID) {
		_ = p.sessionHolder.Destroy(ctx)

		return true
	}

	p.plus.Touch(userSession, p.Config)

	return false
}
