// SPDX-FileCopyrightText: 2026 Authelia
// SPDX-FileCopyrightText: 2026 authelia-plus contributors
//
// SPDX-License-Identifier: Apache-2.0

package middlewares

import (
	"github.com/valyala/fasthttp"

	"github.com/authelia/authelia/v4/internal/authentication"
	"github.com/authelia/authelia/v4/internal/model"
)

// authelia-plus: the session list and revoke need the user's full authentication.

// RequireFullAuth requires the user to have authenticated with every factor they can: the second factor too when they
// have one enrolled, so a stolen password alone can't list or revoke sessions.
func RequireFullAuth(next RequestHandler) RequestHandler {
	return func(ctx *AutheliaCtx) {
		userSession, err := ctx.GetSession()
		if err != nil || userSession.IsAnonymous() {
			ctx.ReplyForbidden()
			return
		}

		level := userSession.AuthenticationLevel(ctx.Configuration.WebAuthn.EnablePasskey2FA)

		if level < authentication.OneFactor {
			ctx.ReplyForbidden()
			return
		}

		if level < authentication.TwoFactor {
			var info model.UserInfo

			if info, err = ctx.Providers.StorageProvider.LoadUserInfo(ctx, userSession.Username); err != nil {
				ctx.Logger.WithError(err).Error("Error occurred attempting to lookup user information during a full authentication check.")

				ctx.ReplyForbidden()

				return
			}

			if info.HasTOTP || info.HasWebAuthn || info.HasDuo {
				if err = ctx.ReplyJSON(OKResponse{Status: "KO", Data: ElevatedForbiddenResponse{SecondFactor: true}}, fasthttp.StatusForbidden); err != nil {
					ctx.Logger.WithError(err).Error("Error occurred encoding JSON response during a full authentication check.")
				}

				return
			}
		}

		next(ctx)
	}
}
