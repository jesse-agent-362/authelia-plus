// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"net/url"
	"time"

	"github.com/authelia/authelia/v4/internal/authentication"
	"github.com/authelia/authelia/v4/internal/clock"
	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/expression"
	"github.com/authelia/authelia/v4/internal/random"
	"github.com/authelia/authelia/v4/internal/storage"
)

// authelia-plus: Back-Channel Logout outlives the request that triggered it.

// NewDetachedContext returns a Context which captures parent's issuer and providers but not its lifetime, so it stays
// valid after the request parent belongs to has completed. It is cancelled after timeout.
func NewDetachedContext(parent Context, timeout time.Duration) (ctx Context, cancel context.CancelFunc, err error) {
	var issuer *url.URL

	if issuer, err = parent.IssuerURL(); err != nil {
		return nil, nil, err
	}

	detached := &detachedContext{
		issuer:   issuer,
		clock:    parent.GetClock(),
		random:   parent.GetRandom(),
		config:   parent.GetConfiguration(),
		storage:  parent.GetProviderStorage(),
		users:    parent.GetUserProvider(),
		resolver: parent.GetProviderUserAttributeResolver(),
	}

	detached.Context, cancel = context.WithTimeout(context.Background(), timeout)

	return detached, cancel, nil
}

type detachedContext struct {
	context.Context

	issuer   *url.URL
	clock    clock.Provider
	random   random.Provider
	config   *schema.Configuration
	storage  storage.Provider
	users    authentication.UserProvider
	resolver expression.UserAttributeResolver
}

func (c *detachedContext) IssuerURL() (issuerURL *url.URL, err error) {
	return c.issuer, nil
}

func (c *detachedContext) GetClock() (clock clock.Provider) {
	return c.clock
}

func (c *detachedContext) GetRandom() (random random.Provider) {
	return c.random
}

func (c *detachedContext) GetConfiguration() (config *schema.Configuration) {
	return c.config
}

func (c *detachedContext) GetProviderStorage() storage.Provider {
	return c.storage
}

func (c *detachedContext) GetUserProvider() authentication.UserProvider {
	return c.users
}

func (c *detachedContext) GetProviderUserAttributeResolver() expression.UserAttributeResolver {
	return c.resolver
}
