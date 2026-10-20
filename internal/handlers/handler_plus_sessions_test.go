// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
	"go.uber.org/mock/gomock"

	"github.com/authelia/authelia/v4/internal/authentication"
	"github.com/authelia/authelia/v4/internal/mocks"
	"github.com/authelia/authelia/v4/internal/model"
	plussessions "github.com/authelia/authelia/v4/internal/plus/sessions"
	"github.com/authelia/authelia/v4/internal/session"
)

// authelia-plus: the user session records at the handlers.

func expectTestPlusPasswordSuccess(mock *mocks.MockAutheliaCtx) {
	mock.StorageMock.EXPECT().LoadBannedIP(gomock.Eq(mock.Ctx), gomock.Any()).Return(nil, nil).AnyTimes()
	mock.StorageMock.EXPECT().LoadBannedUser(gomock.Eq(mock.Ctx), gomock.Eq(testValue)).Return(nil, nil).AnyTimes()
	mock.UserProviderMock.EXPECT().CheckUserPassword(gomock.Eq(testValue), gomock.Eq("hello")).Return(true, nil).AnyTimes()
	mock.UserProviderMock.EXPECT().GetDetails(gomock.Eq(testValue)).Return(&authentication.UserDetails{Username: testValue}, nil).AnyTimes()
	mock.StorageMock.EXPECT().AppendAuthenticationLog(mock.Ctx, gomock.Any()).Return(nil).AnyTimes()
}

func doTestPlusPasswordLogin(t *testing.T, mock *mocks.MockAutheliaCtx) session.UserSession {
	t.Helper()

	mock.Ctx.Response.Reset()
	mock.Ctx.Request.SetBodyString(`{"username":"test","password":"hello"}`)

	FirstFactorPasswordPOST(nil)(mock.Ctx)

	userSession, err := mock.Ctx.GetSession()

	require.NoError(t, err)

	return userSession
}

func TestPlusSessionsFirstFactorPassword(t *testing.T) {
	t.Run("ShouldCreateFreshRecordOnEveryLogin", func(t *testing.T) {
		mock := mocks.NewMockAutheliaCtx(t)
		defer mock.Close()

		expectTestPlusPasswordSuccess(mock)

		first := doTestPlusPasswordLogin(t, mock)

		require.Equal(t, fasthttp.StatusOK, mock.Ctx.Response.StatusCode())
		require.NotEqual(t, uuid.Nil, first.PlusID)

		record := mock.PlusSessionsStore.Get(first.PlusID)

		require.NotNil(t, record)
		assert.Equal(t, testValue, record.Username)
		assert.False(t, record.RevokedAt.Valid)

		second := doTestPlusPasswordLogin(t, mock)

		require.Equal(t, fasthttp.StatusOK, mock.Ctx.Response.StatusCode())
		assert.NotEqual(t, uuid.Nil, second.PlusID)
		assert.NotEqual(t, first.PlusID, second.PlusID)
		assert.NotNil(t, mock.PlusSessionsStore.Get(second.PlusID))
	})

	t.Run("ShouldFailClosedWhenRecordFails", func(t *testing.T) {
		mock := mocks.NewMockAutheliaCtx(t)
		defer mock.Close()

		expectTestPlusPasswordSuccess(mock)
		mock.PlusSessionsStore.SetError("SavePlusUserSession", errors.New("disk full"))

		userSession := doTestPlusPasswordLogin(t, mock)

		mock.Assert401KO(t, "Authentication failed. Check your credentials.")
		assert.True(t, userSession.IsAnonymous())
		assert.Equal(t, uuid.Nil, userSession.PlusID)
		assert.Empty(t, mock.PlusSessionsStore.Records)
	})

	t.Run("ShouldReplaceRecordOnReauthentication", func(t *testing.T) {
		mock := mocks.NewMockAutheliaCtx(t)
		defer mock.Close()

		expectTestPlusPasswordSuccess(mock)

		before := doTestPlusPasswordLogin(t, mock)

		require.NotEqual(t, uuid.Nil, before.PlusID)

		mock.Ctx.Response.Reset()
		mock.Ctx.Request.SetBodyString(`{"password":"hello"}`)

		FirstFactorReauthenticatePOST(nil)(mock.Ctx)

		require.Equal(t, fasthttp.StatusOK, mock.Ctx.Response.StatusCode())

		after, err := mock.Ctx.GetSession()

		require.NoError(t, err)
		assert.NotEqual(t, uuid.Nil, after.PlusID)
		assert.NotEqual(t, before.PlusID, after.PlusID)

		old := mock.PlusSessionsStore.Get(before.PlusID)

		require.NotNil(t, old)
		assert.True(t, old.RevokedAt.Valid)
		assert.True(t, old.ProcessedAt.Valid, "a replaced record must never reach the processor")
		assert.Equal(t, plussessions.RevokedByReplace, old.RevokedBy)
	})
}

func TestPlusSessionsGET(t *testing.T) {
	mock := mocks.NewMockAutheliaCtx(t)
	defer mock.Close()

	expectTestPlusPasswordSuccess(mock)

	current := doTestPlusPasswordLogin(t, mock)

	require.NotEqual(t, uuid.Nil, current.PlusID)

	other := uuid.Must(uuid.NewV7())
	now := mock.Clock.Now()

	mock.PlusSessionsStore.Records[other] = &model.PlusUserSession{
		ID:          other,
		Username:    testValue,
		CreatedAt:   now,
		LastActive:  now,
		ExpiresAt:   now.Add(time.Hour),
		IP:          "192.0.2.1",
		UserAgent:   "Other",
		RequestIDs:  `["secret-request-id"]`,
		BackChannel: `{"sid":"secret-sid"}`,
	}

	mock.Ctx.Response.Reset()

	PlusSessionsGET(mock.Ctx)

	require.Equal(t, fasthttp.StatusOK, mock.Ctx.Response.StatusCode())

	body := mock.Ctx.Response.Body()

	assert.NotContains(t, string(body), "secret-request-id")
	assert.NotContains(t, string(body), "secret-sid")

	var response struct {
		Status string           `json:"status"`
		Data   []map[string]any `json:"data"`
	}

	require.NoError(t, json.Unmarshal(body, &response))
	require.Len(t, response.Data, 2)

	for _, item := range response.Data {
		keys := make([]string, 0, len(item))

		for key := range item {
			keys = append(keys, key)
		}

		sort.Strings(keys)

		assert.Equal(t, []string{"created_at", "current", "expires_at", "id", "last_active", "reported_ip", "user_agent"}, keys)
		assert.Equal(t, item["id"] == current.PlusID.String(), item["current"])
	}
}

func TestPlusSessionsOpenIDConnectAuthorization(t *testing.T) {
	setup := func(t *testing.T) (mock *mocks.MockAutheliaCtx, id uuid.UUID) {
		t.Helper()

		mock = mocks.NewMockAutheliaCtx(t)

		userSession := newTestOIDCUserSession(1)

		require.NoError(t, plusSessionsCreate(mock.Ctx, mock.Ctx.Configuration.Session.Cookies[0], &userSession, testUsername, false))
		require.NoError(t, mock.Ctx.SaveSession(userSession))

		setupTestOIDCAuthorizationCodeFlow(t, mock, newTestOIDCBackChannelLogoutClient(t, "https://app.example.com/backchannel-logout"))

		return mock, userSession.PlusID
	}

	authorize := func(t *testing.T, mock *mocks.MockAutheliaCtx) url.Values {
		t.Helper()

		rw, r := newTestOAuth2Request(t, fasthttp.MethodGet, testOIDCAuthorizationEndpoint, newTestOIDCAuthorizationValues())

		OAuth2AuthorizationGET(mock.Ctx, rw, r)

		require.Equal(t, http.StatusSeeOther, rw.Code)

		location, err := url.Parse(rw.Header().Get(fasthttp.HeaderLocation))

		require.NoError(t, err)

		return location.Query()
	}

	t.Run("ShouldRecordGrants", func(t *testing.T) {
		mock, id := setup(t)
		defer mock.Close()

		query := authorize(t, mock)

		require.NotEmpty(t, query.Get(testOIDCFormParameterCode))

		record := mock.PlusSessionsStore.Get(id)

		require.NotNil(t, record)
		assert.NotEmpty(t, record.RequestIDs)
		assert.Contains(t, record.BackChannel, testOIDCAuthorizationCodeID)
	})

	t.Run("ShouldNotIssueCodeWhenRecordFails", func(t *testing.T) {
		mock, _ := setup(t)
		defer mock.Close()

		mock.PlusSessionsStore.SetError("UpdatePlusUserSessionOpenIDConnect", errors.New("disk full"))

		query := authorize(t, mock)

		assert.Empty(t, query.Get(testOIDCFormParameterCode))
		assert.Equal(t, "server_error", query.Get("error"))
	})

	t.Run("ShouldNotIssueCodeWhenRecordClaimed", func(t *testing.T) {
		mock, id := setup(t)
		defer mock.Close()

		// Another instance revoked and claimed the record between the session load and the authorization.
		mock.PlusSessionsStore.Records[id].RevokedAt.Valid = true
		mock.PlusSessionsStore.Records[id].ProcessedAt.Valid = true

		query := authorize(t, mock)

		assert.Empty(t, query.Get(testOIDCFormParameterCode))
		assert.Equal(t, "server_error", query.Get("error"))
	})
}
