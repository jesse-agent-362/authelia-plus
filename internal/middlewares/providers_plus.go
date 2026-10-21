// SPDX-FileCopyrightText: 2026 authelia-plus contributors
//
// SPDX-License-Identifier: Apache-2.0

package middlewares

import (
	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/model"
	plussessions "github.com/authelia/authelia/v4/internal/plus/sessions"
)

// authelia-plus: the record of user sessions, which the user can list and revoke.

// ProviderNamePlusSessions is the name of the user session records provider in startup checks.
const ProviderNamePlusSessions = "plus-sessions"

// setupPlusSessions creates the user session records and makes every session provider reject revoked sessions.
func (p *Providers) setupPlusSessions(config *schema.Configuration) {
	store, ok := p.StorageProvider.(plussessions.Store)
	if !ok || p.SessionProvider == nil {
		return
	}

	p.PlusSessions = plussessions.New(config, store, p.Clock)

	p.SessionProvider.SetPlusSessions(p.PlusSessions)
}

// plusSessionsStartupCheck returns the startup check of the user session records, or nil when there are none, so a
// missing provider fails the startup checks rather than being skipped.
func plusSessionsStartupCheck(manager *plussessions.Manager) model.StartupCheck {
	if manager == nil {
		return nil
	}

	return manager
}
