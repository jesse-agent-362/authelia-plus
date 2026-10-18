// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"fmt"
)

// authelia-plus: OpenID Connect RP-Initiated Logout 1.0.

const (
	EndpointEndSession     = "end-session"
	EndpointPathEndSession = EndpointPathRoot + "/" + EndpointEndSession
)

// setLogoutDiscovery advertises the end session endpoint.
func setLogoutDiscovery(options *OpenIDConnectWellKnownConfiguration, issuer string) {
	options.OpenIDConnectRPInitiatedLogoutDiscoveryOptions = &OpenIDConnectRPInitiatedLogoutDiscoveryOptions{
		EndSessionEndpoint: fmt.Sprintf("%s%s", issuer, EndpointPathEndSession),
	}
}
