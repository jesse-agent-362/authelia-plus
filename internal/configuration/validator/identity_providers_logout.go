// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"fmt"
	"net/url"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/utils"
)

// authelia-plus: client options for OpenID Connect RP-Initiated Logout 1.0.

const (
	attrOIDCPostLogoutRedirectURIs = "post_logout_redirect_uris"

	errFmtOIDCClientPostLogoutRedirectURIHas          = errFmtOIDCClientOption + "'post_logout_redirect_uris' has "
	errFmtOIDCClientPostLogoutRedirectURICantBeParsed = errFmtOIDCClientPostLogoutRedirectURIHas +
		"an invalid value: post logout redirect uri '%s' could not be parsed: %v"
	errFmtOIDCClientPostLogoutRedirectURINotAbsolute = errFmtOIDCClientPostLogoutRedirectURIHas +
		"an invalid value: post logout redirect uri '%s' must have a scheme but it's absent"
	errFmtOIDCClientPostLogoutRedirectURIFragment = errFmtOIDCClientPostLogoutRedirectURIHas +
		"an invalid value: post logout redirect uri '%s' must not have a fragment"
)

func validateOIDCClientPostLogoutRedirectURIs(c int, config *schema.IdentityProvidersOpenIDConnect, validator *schema.StructValidator) {
	var (
		parsed *url.URL
		err    error
	)

	for _, uri := range config.Clients[c].PostLogoutRedirectURIs {
		if parsed, err = url.Parse(uri); err != nil {
			validator.Push(fmt.Errorf(errFmtOIDCClientPostLogoutRedirectURICantBeParsed, config.Clients[c].ID, uri, err))
			continue
		}

		if !parsed.IsAbs() {
			validator.Push(fmt.Errorf(errFmtOIDCClientPostLogoutRedirectURINotAbsolute, config.Clients[c].ID, uri))
		} else if parsed.Fragment != "" {
			validator.Push(fmt.Errorf(errFmtOIDCClientPostLogoutRedirectURIFragment, config.Clients[c].ID, uri))
		}
	}

	_, duplicates := validateList(config.Clients[c].PostLogoutRedirectURIs, nil, true)

	if len(duplicates) != 0 {
		validator.Push(fmt.Errorf(errFmtOIDCClientInvalidEntryDuplicates, config.Clients[c].ID, attrOIDCPostLogoutRedirectURIs, utils.StringJoinAnd(duplicates)))
	}
}
