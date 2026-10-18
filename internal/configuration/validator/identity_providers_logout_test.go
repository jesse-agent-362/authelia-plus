// SPDX-FileCopyrightText: 2026 Authelia
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
