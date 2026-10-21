// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package middlewares_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"

	"github.com/authelia/authelia/v4/internal/authentication"
	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/mocks"
	"github.com/authelia/authelia/v4/internal/model"
)

// authelia-plus: requirement 5, the session list and revoke need the full authentication level of the user.
func TestRequireFullAuth(t *testing.T) {
	testCases := []struct {
		name     string
		level    authentication.Level
		info     *model.UserInfo
		err      error
		expected int
		second   bool
	}{
		{"ShouldRejectAnonymous", authentication.NotAuthenticated, nil, nil, fasthttp.StatusForbidden, false},
		{"ShouldPassOneFactorWithoutSecondFactor", authentication.OneFactor, &model.UserInfo{}, nil, fasthttp.StatusOK, false},
		{"ShouldRejectOneFactorWithTOTP", authentication.OneFactor, &model.UserInfo{HasTOTP: true}, nil, fasthttp.StatusForbidden, true},
		{"ShouldRejectOneFactorWithWebAuthn", authentication.OneFactor, &model.UserInfo{HasWebAuthn: true}, nil, fasthttp.StatusForbidden, true},
		{"ShouldRejectOneFactorWithDuo", authentication.OneFactor, &model.UserInfo{HasDuo: true}, nil, fasthttp.StatusForbidden, true},
		{"ShouldRejectOneFactorWhenLookupFails", authentication.OneFactor, &model.UserInfo{}, errors.New("db down"), fasthttp.StatusForbidden, false},
		{"ShouldPassTwoFactor", authentication.TwoFactor, nil, nil, fasthttp.StatusOK, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mock := mocks.NewMockAutheliaCtx(t)

			defer mock.Close()

			userSession, err := mock.Ctx.GetSession()
			require.NoError(t, err)

			switch tc.level {
			case authentication.OneFactor:
				userSession.Username = john
				userSession.AuthenticationMethodRefs.UsernameAndPassword = true
			case authentication.TwoFactor:
				userSession.Username = john
				userSession.AuthenticationMethodRefs.UsernameAndPassword = true
				userSession.AuthenticationMethodRefs.TOTP = true
			}

			require.NoError(t, mock.Ctx.SaveSession(userSession))

			if tc.info != nil {
				mock.StorageMock.EXPECT().LoadUserInfo(mock.Ctx, john).Return(*tc.info, tc.err)
			}

			middlewares.RequireFullAuth(NilHandler)(mock.Ctx)

			assert.Equal(t, tc.expected, mock.Ctx.Response.StatusCode())

			if tc.expected == fasthttp.StatusOK {
				assert.Equal(t, "Example Nil", string(mock.Ctx.Response.Body()))

				return
			}

			assert.NotEqual(t, "Example Nil", string(mock.Ctx.Response.Body()))

			if tc.second {
				data := &struct {
					Data middlewares.ElevatedForbiddenResponse `json:"data"`
				}{}

				require.NoError(t, json.Unmarshal(mock.Ctx.Response.Body(), data))
				assert.True(t, data.Data.SecondFactor)
			}
		})
	}
}
