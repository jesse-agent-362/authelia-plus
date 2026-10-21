// SPDX-FileCopyrightText: 2026 Authelia
// SPDX-FileCopyrightText: 2026 authelia-plus contributors
//
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/utils"
)

// authelia-plus: client options for OpenID Connect RP-Initiated Logout 1.0 and Back-Channel Logout 1.0.

const (
	attrOIDCPostLogoutRedirectURIs = "post_logout_redirect_uris"

	errFmtOIDCClientPostLogoutRedirectURIHas          = errFmtOIDCClientOption + "'post_logout_redirect_uris' has "
	errFmtOIDCClientPostLogoutRedirectURICantBeParsed = errFmtOIDCClientPostLogoutRedirectURIHas +
		"an invalid value: post logout redirect uri '%s' could not be parsed: %v"
	errFmtOIDCClientPostLogoutRedirectURINotAbsolute = errFmtOIDCClientPostLogoutRedirectURIHas +
		"an invalid value: post logout redirect uri '%s' must have a scheme but it's absent"
	errFmtOIDCClientPostLogoutRedirectURIFragment = errFmtOIDCClientPostLogoutRedirectURIHas +
		"an invalid value: post logout redirect uri '%s' must not have a fragment"
	errFmtOIDCClientPostLogoutRedirectURIScheme = errFmtOIDCClientPostLogoutRedirectURIHas +
		"an invalid value: post logout redirect uri '%s' must not use the '%s' scheme"

	errFmtOIDCClientBackChannelLogoutURIIs           = errFmtOIDCClientOption + "'backchannel_logout_uri' with value '%s' "
	errFmtOIDCClientBackChannelLogoutURICantBeParsed = errFmtOIDCClientBackChannelLogoutURIIs + "could not be parsed: %v"
	errFmtOIDCClientBackChannelLogoutURIScheme       = errFmtOIDCClientBackChannelLogoutURIIs + "must be an absolute 'http' or 'https' URI"
	errFmtOIDCClientBackChannelLogoutURIFragment     = errFmtOIDCClientBackChannelLogoutURIIs + "must not have a fragment"
	errFmtOIDCClientBackChannelLogoutURIOrigin       = errFmtOIDCClientBackChannelLogoutURIIs +
		"must have the same scheme, host and port as one of the 'redirect_uris'"
	errFmtOIDCClientBackChannelLogoutSessionRequiredNoURI = errFmtOIDCClientOption +
		"'backchannel_logout_session_required' is true but 'backchannel_logout_uri' is absent"
)

// postLogoutRedirectURIForbiddenSchemes are schemes a browser would execute or read locally rather than navigate to.
// Custom schemes stay allowed for native clients.
var postLogoutRedirectURIForbiddenSchemes = []string{"javascript", "data", "vbscript", "file", "blob"}

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
		} else if scheme := strings.ToLower(parsed.Scheme); utils.IsStringInSlice(scheme, postLogoutRedirectURIForbiddenSchemes) {
			validator.Push(fmt.Errorf(errFmtOIDCClientPostLogoutRedirectURIScheme, config.Clients[c].ID, uri, scheme))
		}
	}

	_, duplicates := validateList(config.Clients[c].PostLogoutRedirectURIs, nil, true)

	if len(duplicates) != 0 {
		validator.Push(fmt.Errorf(errFmtOIDCClientInvalidEntryDuplicates, config.Clients[c].ID, attrOIDCPostLogoutRedirectURIs, utils.StringJoinAnd(duplicates)))
	}
}

// validateOIDCClientBackChannelLogout checks the back-channel logout URI. Authelia itself makes a request to it, so it
// must share the scheme, host and port of one of the client's redirect URIs (Back-Channel Logout 1.0 Section 2.2);
// that keeps it pointed at the client rather than anywhere on the network.
func validateOIDCClientBackChannelLogout(c int, config *schema.IdentityProvidersOpenIDConnect, validator *schema.StructValidator) {
	client := config.Clients[c]

	if client.BackChannelLogoutURI == "" {
		if client.BackChannelLogoutSessionRequired {
			validator.Push(fmt.Errorf(errFmtOIDCClientBackChannelLogoutSessionRequiredNoURI, client.ID))
		}

		return
	}

	parsed, err := url.Parse(client.BackChannelLogoutURI)

	switch {
	case err != nil:
		validator.Push(fmt.Errorf(errFmtOIDCClientBackChannelLogoutURICantBeParsed, client.ID, client.BackChannelLogoutURI, err))
		return
	case !parsed.IsAbs() || (parsed.Scheme != schemeHTTPS && parsed.Scheme != schemeHTTP):
		validator.Push(fmt.Errorf(errFmtOIDCClientBackChannelLogoutURIScheme, client.ID, client.BackChannelLogoutURI))
		return
	case parsed.Fragment != "":
		validator.Push(fmt.Errorf(errFmtOIDCClientBackChannelLogoutURIFragment, client.ID, client.BackChannelLogoutURI))
		return
	}

	for _, redirectURI := range client.RedirectURIs {
		if r, err := url.Parse(redirectURI); err == nil && r.Scheme == parsed.Scheme && r.Host == parsed.Host {
			return
		}
	}

	validator.Push(fmt.Errorf(errFmtOIDCClientBackChannelLogoutURIOrigin, client.ID, client.BackChannelLogoutURI))
}
