// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"

	"github.com/sirupsen/logrus"

	"github.com/authelia/authelia/v4/internal/handlers"
	plussessions "github.com/authelia/authelia/v4/internal/plus/sessions"
)

// authelia-plus: the background work of the user session records.

const serviceTypePlusSessions = "plus-sessions"

// ProvisionPlusSessions provisions the service which writes session activity and processes revocations.
func ProvisionPlusSessions(ctx Context) (service Provider, err error) {
	providers := ctx.GetProviders()

	if providers.PlusSessions == nil {
		return nil, nil
	}

	log := ctx.GetLogger().WithFields(map[string]any{logFieldService: serviceTypePlusSessions})

	providers.PlusSessions.SetProcessor(handlers.NewPlusSessionsProcessor(&providers, ctx.GetConfiguration(), log))

	cctx, cancel := context.WithCancel(ctx)

	return &PlusSessions{manager: providers.PlusSessions, ctx: cctx, cancel: cancel, log: log}, nil
}

// PlusSessions runs the background work of the user session records.
type PlusSessions struct {
	manager *plussessions.Manager
	ctx     context.Context
	cancel  context.CancelFunc
	log     *logrus.Entry
}

// ServiceType returns the service type for this service, which is always 'plus-sessions'.
func (service *PlusSessions) ServiceType() string {
	return serviceTypePlusSessions
}

// ServiceName returns the individual name for this service, which is always 'main'.
func (service *PlusSessions) ServiceName() string {
	return "main"
}

// Run the session record poller until the service is shut down.
func (service *PlusSessions) Run() (err error) {
	defer func() {
		if r := recover(); r != nil {
			service.log.WithError(recoverErr(r)).Error("Critical error caught (recovered)")
		}
	}()

	service.manager.Run(service.ctx)

	return nil
}

// Shutdown the session record poller.
func (service *PlusSessions) Shutdown() {
	service.cancel()
}

// Log returns the logger configured for the service.
func (service *PlusSessions) Log() *logrus.Entry {
	return service.log
}
