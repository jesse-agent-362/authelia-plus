// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	oauthelia2 "authelia.com/provider/oauth2"
)

// authelia-plus: OpenID Connect RP-Initiated Logout 1.0 client metadata.

// GetPostLogoutRedirectURIs returns the URIs the client may name as 'post_logout_redirect_uri'.
func (c *RegisteredClient) GetPostLogoutRedirectURIs() (uris []string) {
	return c.PostLogoutRedirectURIs
}

var (
	_ oauthelia2.RPInitiatedLogoutClient = (*RegisteredClient)(nil)
)
