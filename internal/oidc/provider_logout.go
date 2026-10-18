// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"net/http"

	oauthelia2 "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/x/errorsx"
)

// authelia-plus: OpenID Connect RP-Initiated Logout 1.0.

// logoutProvider is the part of *oauthelia2.Fosite that implements logout, which oauthelia2.Provider does not expose.
type logoutProvider interface {
	NewRPInitiatedLogoutRequest(ctx context.Context, r *http.Request) (requester oauthelia2.RPInitiatedLogoutRequester, err error)
}

// NewRPInitiatedLogoutRequest parses and validates a request to the end session endpoint.
func (p *OpenIDConnectProvider) NewRPInitiatedLogoutRequest(ctx context.Context, r *http.Request) (requester oauthelia2.RPInitiatedLogoutRequester, err error) {
	provider, ok := p.Provider.(logoutProvider)
	if !ok {
		return oauthelia2.NewRPInitiatedLogoutRequest(), errorsx.WithStack(oauthelia2.ErrServerError.WithDebug("The provider does not implement RP-Initiated Logout."))
	}

	return provider.NewRPInitiatedLogoutRequest(ctx, r)
}

var (
	_ logoutProvider = (*oauthelia2.Fosite)(nil)
)
