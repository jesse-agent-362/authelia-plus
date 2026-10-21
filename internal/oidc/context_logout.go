// SPDX-FileCopyrightText: 2026 authelia-plus contributors
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

	ctx, cancel = NewDetachedContextFromProviders(issuer, DetachedContextProviders{
		Clock:    parent.GetClock(),
		Random:   parent.GetRandom(),
		Config:   parent.GetConfiguration(),
		Storage:  parent.GetProviderStorage(),
		Users:    parent.GetUserProvider(),
		Resolver: parent.GetProviderUserAttributeResolver(),
	}, timeout)

	return ctx, cancel, nil
}

// DetachedContextProviders are the providers a detached Context carries.
type DetachedContextProviders struct {
	Clock    clock.Provider
	Random   random.Provider
	Config   *schema.Configuration
	Storage  storage.Provider
	Users    authentication.UserProvider
	Resolver expression.UserAttributeResolver
}

// NewDetachedContextFromProviders returns a Context for issuer which is not tied to any request, for work done outside
// of one. It is cancelled after timeout.
func NewDetachedContextFromProviders(issuer *url.URL, providers DetachedContextProviders, timeout time.Duration) (ctx Context, cancel context.CancelFunc) {
	detached := &detachedContext{
		issuer:   issuer,
		clock:    providers.Clock,
		random:   providers.Random,
		config:   providers.Config,
		storage:  providers.Storage,
		users:    providers.Users,
		resolver: providers.Resolver,
	}

	detached.Context, cancel = context.WithTimeout(context.Background(), timeout)

	return detached, cancel
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
