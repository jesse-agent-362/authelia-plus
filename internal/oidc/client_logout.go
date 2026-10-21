// SPDX-FileCopyrightText: 2026 authelia-plus contributors
//
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	oauthelia2 "authelia.com/provider/oauth2"
)

// authelia-plus: OpenID Connect RP-Initiated Logout 1.0 and Back-Channel Logout 1.0 client metadata.

// GetPostLogoutRedirectURIs returns the URIs the client may name as 'post_logout_redirect_uri'.
func (c *RegisteredClient) GetPostLogoutRedirectURIs() (uris []string) {
	return c.PostLogoutRedirectURIs
}

// GetBackChannelLogoutURI returns the URI Logout Tokens are delivered to, empty when the client does not take part.
func (c *RegisteredClient) GetBackChannelLogoutURI() (uri string) {
	return c.BackChannelLogoutURI
}

// GetBackChannelLogoutSessionRequired returns true when the client requires the 'sid' claim in Logout Tokens.
func (c *RegisteredClient) GetBackChannelLogoutSessionRequired() (required bool) {
	return c.BackChannelLogoutSessionRequired
}

var (
	_ oauthelia2.RPInitiatedLogoutClient = (*RegisteredClient)(nil)
	_ oauthelia2.BackChannelLogoutClient = (*RegisteredClient)(nil)
)
