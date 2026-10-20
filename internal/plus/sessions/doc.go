// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

// Package sessions is authelia-plus' record of user sessions, which lets a user list their sessions and revoke them,
// and lets an administrator revoke every session of a user.
//
// Every first factor authentication gets a new record, and its ID is kept in the user session data. A revoke only
// marks the record; the in-memory set of revoked IDs makes every instance reject the session wherever it's loaded, and
// a poller performs the side effects (revoking the OpenID Connect 1.0 grants of the session and sending Back-Channel
// Logout tokens) once per record.
//
// It is a stopgap until upstream ships session management, and is removed with its table at that point.
package sessions
