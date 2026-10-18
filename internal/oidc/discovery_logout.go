// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"fmt"
)

// authelia-plus: OpenID Connect RP-Initiated Logout 1.0 and Back-Channel Logout 1.0.

const (
	// EndpointEndSession is the name of the OpenID Connect RP-Initiated Logout 1.0 end session endpoint.
	EndpointEndSession = "end-session"

	// EndpointPathEndSession is the path of the end session endpoint.
	EndpointPathEndSession = EndpointPathRoot + "/" + EndpointEndSession
)

// setLogoutDiscovery advertises the end session endpoint and Back-Channel Logout support.
func setLogoutDiscovery(options *OpenIDConnectWellKnownConfiguration, issuer string) {
	options.OpenIDConnectRPInitiatedLogoutDiscoveryOptions = &OpenIDConnectRPInitiatedLogoutDiscoveryOptions{
		EndSessionEndpoint: fmt.Sprintf("%s%s", issuer, EndpointPathEndSession),
	}

	options.OpenIDConnectBackChannelLogoutDiscoveryOptions = &OpenIDConnectBackChannelLogoutDiscoveryOptions{
		BackChannelLogoutSupported:        true,
		BackChannelLogoutSessionSupported: true,
	}
}
