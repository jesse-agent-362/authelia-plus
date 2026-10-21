// SPDX-FileCopyrightText: 2026 authelia-plus contributors
//
// SPDX-License-Identifier: Apache-2.0

package oidc_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	oauthelia2 "authelia.com/provider/oauth2"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/oidc"
)

// authelia-plus: tests for OpenID Connect RP-Initiated Logout 1.0 and Back-Channel Logout 1.0.

//nolint:gosec // Test Credentials.
func TestOpenIDConnectProvider_LogoutDiscovery(t *testing.T) {
	provider := oidc.NewOpenIDConnectProvider(&schema.Configuration{
		IdentityProviders: schema.IdentityProviders{
			OIDC: &schema.IdentityProvidersOpenIDConnect{
				IssuerCertificateChain: schema.X509CertificateChain{},
				IssuerPrivateKey:       x509PrivateKeyRSA2048,
				HMACSecret:             "asbdhaaskmdlkamdklasmdlkams",
				Clients: []schema.IdentityProvidersOpenIDConnectClient{
					{
						ID:                  "a-client",
						Secret:              tOpenIDConnectPlainTextClientSecret,
						AuthorizationPolicy: onefactor,
						RedirectURIs:        []string{"https://google.com"},
					},
				},
			},
		},
	}, nil, nil)

	require.NotNil(t, provider)

	data, err := json.Marshal(provider.GetOpenIDConnectWellKnownConfiguration(examplecom))

	require.NoError(t, err)

	disco := map[string]any{}

	require.NoError(t, json.Unmarshal(data, &disco))

	assert.Equal(t, "https://example.com/api/oidc/end-session", disco["end_session_endpoint"])
	assert.Equal(t, true, disco["backchannel_logout_supported"])
	assert.Equal(t, true, disco["backchannel_logout_session_supported"])
}

func TestNewClient_Logout(t *testing.T) {
	t.Run("ShouldMapLogoutOptions", func(t *testing.T) {
		client := oidc.NewClient(schema.IdentityProvidersOpenIDConnectClient{
			ID:                               myclient,
			RedirectURIs:                     []string{examplecom},
			PostLogoutRedirectURIs:           []string{"https://example.com/logged-out", "https://example.com/bye"},
			BackChannelLogoutURI:             "https://example.com/backchannel",
			BackChannelLogoutSessionRequired: true,
		}, &schema.IdentityProvidersOpenIDConnect{}, nil)

		rp, ok := client.(oauthelia2.RPInitiatedLogoutClient)

		require.True(t, ok)
		assert.Equal(t, []string{"https://example.com/logged-out", "https://example.com/bye"}, rp.GetPostLogoutRedirectURIs())

		bc, ok := client.(oauthelia2.BackChannelLogoutClient)

		require.True(t, ok)
		assert.Equal(t, "https://example.com/backchannel", bc.GetBackChannelLogoutURI())
		assert.True(t, bc.GetBackChannelLogoutSessionRequired())
	})

	t.Run("ShouldDefaultToNoLogoutOptions", func(t *testing.T) {
		client := oidc.NewClient(schema.IdentityProvidersOpenIDConnectClient{ID: myclient}, &schema.IdentityProvidersOpenIDConnect{}, nil)

		rp, ok := client.(oauthelia2.RPInitiatedLogoutClient)

		require.True(t, ok)
		assert.Empty(t, rp.GetPostLogoutRedirectURIs())

		bc, ok := client.(oauthelia2.BackChannelLogoutClient)

		require.True(t, ok)
		assert.Equal(t, "", bc.GetBackChannelLogoutURI())
		assert.False(t, bc.GetBackChannelLogoutSessionRequired())
	})
}
