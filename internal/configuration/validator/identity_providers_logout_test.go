// SPDX-FileCopyrightText: 2026 Authelia
// SPDX-FileCopyrightText: 2026 authelia-plus contributors
//
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
)

func TestValidateOIDCClientPostLogoutRedirectURIs(t *testing.T) {
	testCases := []struct {
		name     string
		have     []string
		expected []string
	}{
		{"ShouldAllowNone", nil, nil},
		{"ShouldAllowAbsolute", []string{"https://app.example.com/logged-out", "com.example.app:/logout"}, nil},
		{
			"ShouldErrorNotAbsolute",
			[]string{"/logged-out"},
			[]string{"identity_providers: oidc: clients: client 'app': option 'post_logout_redirect_uris' has an invalid value: post logout redirect uri '/logged-out' must have a scheme but it's absent"},
		},
		{
			"ShouldErrorFragment",
			[]string{"https://app.example.com/#bye"},
			[]string{"identity_providers: oidc: clients: client 'app': option 'post_logout_redirect_uris' has an invalid value: post logout redirect uri 'https://app.example.com/#bye' must not have a fragment"},
		},
		{
			"ShouldErrorUnparsable",
			[]string{"http://abc@%two"},
			[]string{"identity_providers: oidc: clients: client 'app': option 'post_logout_redirect_uris' has an invalid value: post logout redirect uri 'http://abc@%two' could not be parsed: parse \"http://abc@%two\": invalid URL escape \"%tw\""},
		},
		{
			"ShouldErrorScriptSchemes",
			[]string{"javascript:alert(1)", "JavaScript:alert(2)", "data:text/html,hi"},
			[]string{
				"identity_providers: oidc: clients: client 'app': option 'post_logout_redirect_uris' has an invalid value: post logout redirect uri 'javascript:alert(1)' must not use the 'javascript' scheme",
				"identity_providers: oidc: clients: client 'app': option 'post_logout_redirect_uris' has an invalid value: post logout redirect uri 'JavaScript:alert(2)' must not use the 'javascript' scheme",
				"identity_providers: oidc: clients: client 'app': option 'post_logout_redirect_uris' has an invalid value: post logout redirect uri 'data:text/html,hi' must not use the 'data' scheme",
			},
		},
		{
			"ShouldErrorDuplicates",
			[]string{"https://app.example.com", "https://app.example.com"},
			[]string{"identity_providers: oidc: clients: client 'app': option 'post_logout_redirect_uris' must have unique values but the values 'https://app.example.com' are duplicated"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &schema.IdentityProvidersOpenIDConnect{
				Clients: []schema.IdentityProvidersOpenIDConnectClient{{ID: "app", PostLogoutRedirectURIs: tc.have}},
			}

			validator := schema.NewStructValidator()

			validateOIDCClientPostLogoutRedirectURIs(0, config, validator)

			assert.Len(t, validator.Warnings(), 0)
			assertErrorStrings(t, tc.expected, validator.Errors())
		})
	}
}

func TestValidateOIDCClientBackChannelLogout(t *testing.T) {
	testCases := []struct {
		name     string
		uri      string
		required bool
		expected []string
	}{
		{"ShouldAllowNone", "", false, nil},
		{"ShouldAllowSameOrigin", "https://app.example.com/backchannel-logout", true, nil},
		{"ShouldAllowSameOriginOtherRedirect", "http://app.internal:8080/logout", false, nil},
		{
			"ShouldErrorSessionRequiredWithoutURI", "", true,
			[]string{"identity_providers: oidc: clients: client 'app': option 'backchannel_logout_session_required' is true but 'backchannel_logout_uri' is absent"},
		},
		{
			"ShouldErrorOtherHost", "https://evil.example.com/logout", false,
			[]string{"identity_providers: oidc: clients: client 'app': option 'backchannel_logout_uri' with value 'https://evil.example.com/logout' must have the same scheme, host and port as one of the 'redirect_uris'"},
		},
		{
			"ShouldErrorOtherPort", "https://app.example.com:8443/logout", false,
			[]string{"identity_providers: oidc: clients: client 'app': option 'backchannel_logout_uri' with value 'https://app.example.com:8443/logout' must have the same scheme, host and port as one of the 'redirect_uris'"},
		},
		{
			"ShouldErrorOtherScheme", "http://app.example.com/logout", false,
			[]string{"identity_providers: oidc: clients: client 'app': option 'backchannel_logout_uri' with value 'http://app.example.com/logout' must have the same scheme, host and port as one of the 'redirect_uris'"},
		},
		{
			"ShouldErrorNotHTTP", "app://logout", false,
			[]string{"identity_providers: oidc: clients: client 'app': option 'backchannel_logout_uri' with value 'app://logout' must be an absolute 'http' or 'https' URI"},
		},
		{
			"ShouldErrorRelative", "/logout", false,
			[]string{"identity_providers: oidc: clients: client 'app': option 'backchannel_logout_uri' with value '/logout' must be an absolute 'http' or 'https' URI"},
		},
		{
			"ShouldErrorFragment", "https://app.example.com/logout#x", false,
			[]string{"identity_providers: oidc: clients: client 'app': option 'backchannel_logout_uri' with value 'https://app.example.com/logout#x' must not have a fragment"},
		},
		{
			"ShouldErrorUnparsable", "http://abc@%two", false,
			[]string{"identity_providers: oidc: clients: client 'app': option 'backchannel_logout_uri' with value 'http://abc@%two' could not be parsed: parse \"http://abc@%two\": invalid URL escape \"%tw\""},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &schema.IdentityProvidersOpenIDConnect{
				Clients: []schema.IdentityProvidersOpenIDConnectClient{
					{
						ID:                               "app",
						RedirectURIs:                     []string{"https://app.example.com/callback", "http://app.internal:8080/callback"},
						BackChannelLogoutURI:             tc.uri,
						BackChannelLogoutSessionRequired: tc.required,
					},
				},
			}

			validator := schema.NewStructValidator()

			validateOIDCClientBackChannelLogout(0, config, validator)

			assert.Len(t, validator.Warnings(), 0)
			assertErrorStrings(t, tc.expected, validator.Errors())
		})
	}
}

func assertErrorStrings(t *testing.T, expected []string, actual []error) {
	t.Helper()

	have := make([]string, len(actual))

	for i, err := range actual {
		have[i] = err.Error()
	}

	if len(expected) == 0 {
		assert.Empty(t, have)
		return
	}

	assert.Equal(t, expected, have)
}
