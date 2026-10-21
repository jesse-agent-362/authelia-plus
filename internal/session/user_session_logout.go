// SPDX-FileCopyrightText: 2026 authelia-plus contributors
//
// SPDX-License-Identifier: Apache-2.0

package session

// authelia-plus: OpenID Connect 1.0 logout state.

// OpenIDConnectLogout is the state needed to end this session's OpenID Connect 1.0 grants when the session ends.
type OpenIDConnectLogout struct {
	// RequestIDs are the authorization requests made in this session. Their tokens are revoked when it ends.
	RequestIDs []string

	// SessionID is the 'sid' claim issued to Back-Channel Logout clients for this session.
	SessionID string

	// Clients are the Back-Channel Logout clients which were issued an ID Token in this session.
	Clients []OpenIDConnectLogoutClient
}

// OpenIDConnectLogoutClient is a client which was issued an ID Token in this session, and the subject it was issued for.
type OpenIDConnectLogoutClient struct {
	ClientID string
	Subject  string
}

// AddOpenIDConnectLogoutClient records that clientID was issued an ID Token for subject in this session. It reports
// whether the session changed and so needs saving. OpenIDConnect must already be set.
func (s *UserSession) AddOpenIDConnectLogoutClient(clientID, subject string) (changed bool) {
	for _, c := range s.OpenIDConnect.Clients {
		if c.ClientID == clientID && c.Subject == subject {
			return false
		}
	}

	s.OpenIDConnect.Clients = append(s.OpenIDConnect.Clients, OpenIDConnectLogoutClient{ClientID: clientID, Subject: subject})

	return true
}
