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
	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/mocks"
	"github.com/authelia/authelia/v4/internal/model"
	"github.com/authelia/authelia/v4/internal/oidc"
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

		old := mock.PlusSessionsStore.Get(first.PlusID)

		require.NotNil(t, old)
		assert.True(t, old.RevokedAt.Valid, "logging in again closes the record of the session it replaces")
		assert.Equal(t, plussessions.RevokedByReplace, old.RevokedBy)
	})

	t.Run("ShouldRevokeRecordOfAnotherUserOnLogin", func(t *testing.T) {
		mock := mocks.NewMockAutheliaCtx(t)
		defer mock.Close()

		expectTestPlusPasswordSuccess(mock)

		first := doTestPlusPasswordLogin(t, mock)

		require.Equal(t, fasthttp.StatusOK, mock.Ctx.Response.StatusCode())

		// The same browser, logged in as someone else.
		mock.PlusSessionsStore.Records[first.PlusID].Username = "harry"

		userSession, err := mock.Ctx.GetSession()
		require.NoError(t, err)

		userSession.Username = "harry"
		require.NoError(t, mock.Ctx.SaveSession(userSession))

		second := doTestPlusPasswordLogin(t, mock)

		require.Equal(t, fasthttp.StatusOK, mock.Ctx.Response.StatusCode())
		assert.NotEqual(t, first.PlusID, second.PlusID)

		old := mock.PlusSessionsStore.Get(first.PlusID)

		assert.True(t, old.RevokedAt.Valid)
		assert.False(t, old.ProcessedAt.Valid, "another user's session is revoked as on a logout, grants and all")
		assert.Equal(t, plussessions.RevokedBySwitch, old.RevokedBy)
	})

	t.Run("ShouldLoginWhenPreviousRecordWasRevokedMeanwhile", func(t *testing.T) {
		mock := mocks.NewMockAutheliaCtx(t)
		defer mock.Close()

		expectTestPlusPasswordSuccess(mock)

		first := doTestPlusPasswordLogin(t, mock)

		require.Equal(t, fasthttp.StatusOK, mock.Ctx.Response.StatusCode())

		// Revoked in the store by another instance, which this one hasn't refreshed yet.
		_, err := mock.PlusSessionsStore.RevokePlusUserSession(mock.Ctx, first.PlusID, testValue, plussessions.RevokedBySelf, mock.Clock.Now())
		require.NoError(t, err)

		second := doTestPlusPasswordLogin(t, mock)

		require.Equal(t, fasthttp.StatusOK, mock.Ctx.Response.StatusCode())
		assert.NotEqual(t, uuid.Nil, second.PlusID)
		assert.NotEqual(t, first.PlusID, second.PlusID)
		assert.Equal(t, plussessions.RevokedBySelf, mock.PlusSessionsStore.Get(first.PlusID).RevokedBy)
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
		ID:         other,
		Username:   testValue,
		CreatedAt:  now,
		LastActive: now,
		ExpiresAt:  now.Add(time.Hour),
		IP:         "192.0.2.1",
		UserAgent:  "Other",
	}

	mock.PlusSessionsStore.Grants = append(mock.PlusSessionsStore.Grants, model.PlusUserSessionGrant{SessionID: other, RequestID: "secret-request-id", ClientID: "app", Subject: "secret-subject", SID: "secret-sid"})

	mock.Ctx.Response.Reset()

	PlusSessionsGET(mock.Ctx)

	require.Equal(t, fasthttp.StatusOK, mock.Ctx.Response.StatusCode())

	body := mock.Ctx.Response.Body()

	assert.NotContains(t, string(body), "secret-request-id")
	assert.NotContains(t, string(body), "secret-sid")
	assert.NotContains(t, string(body), "secret-subject")

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

		require.NoError(t, plusSessionsCreate(mock.Ctx, mock.Ctx.Configuration.Session.Cookies[0], &userSession, userSession.PlusID, userSession.Username, testUsername, false))
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

		grants, err := mock.PlusSessionsStore.LoadPlusUserSessionGrants(mock.Ctx, id)

		require.NoError(t, err)
		require.Len(t, grants, 1)
		assert.NotEmpty(t, grants[0].RequestID)
		assert.Equal(t, testOIDCAuthorizationCodeID, grants[0].ClientID)
		assert.NotEmpty(t, grants[0].SID)
		assert.NotEmpty(t, grants[0].Issuer)
	})

	t.Run("ShouldNotIssueCodeWhenRecordFails", func(t *testing.T) {
		mock, _ := setup(t)
		defer mock.Close()

		mock.PlusSessionsStore.SetError("SavePlusUserSessionGrant", errors.New("disk full"))

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

// Item 4: a re-authentication racing a revoke of the same session, which this instance hasn't polled yet, must not
// carry the session over to a fresh record.
func TestPlusSessionsReauthenticateRevokedElsewhere(t *testing.T) {
	mock := mocks.NewMockAutheliaCtx(t)
	defer mock.Close()

	expectTestPlusPasswordSuccess(mock)

	before := doTestPlusPasswordLogin(t, mock)

	require.NotEqual(t, uuid.Nil, before.PlusID)

	count, err := plussessions.RevokeUser(mock.Ctx, mock.PlusSessionsStore, testValue, mock.Clock.Now())

	require.NoError(t, err)
	require.Equal(t, int64(1), count)
	require.False(t, mock.Ctx.Providers.PlusSessions.Revoked(before.PlusID), "the revoke must not have been polled yet")

	mock.Ctx.Response.Reset()
	mock.Ctx.Request.SetBodyString(`{"password":"hello"}`)

	FirstFactorReauthenticatePOST(nil)(mock.Ctx)

	mock.Assert401KO(t, "Authentication failed. Check your credentials.")
	assert.Len(t, mock.PlusSessionsStore.Records, 1, "no replacement record may be created")

	after, err := mock.Ctx.GetSession()

	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, after.PlusID)
	assert.Equal(t, before.PlusID, after.PlusID)
}

func TestPlusSessionsDeviceAuthorization(t *testing.T) {
	setup := func(t *testing.T) (mock *mocks.MockAutheliaCtx, id uuid.UUID, values url.Values, consent *model.OAuth2ConsentSession) {
		t.Helper()

		mock = mocks.NewMockAutheliaCtxWithUserSession(t, newTestOIDCUserSession(1))

		userSession, err := mock.Ctx.GetSession()

		require.NoError(t, err)
		require.NotEqual(t, uuid.Nil, userSession.PlusID)

		config := newTestOIDCConfig(t)
		config.Clients = []schema.IdentityProvidersOpenIDConnectClient{newTestOIDCDeviceCodeClient(t)}

		setupTestOIDCProvider(t, mock, config)
		setupTestOIDCDeviceCodeStore(t, mock)
		setupTestOIDCSessionStore(t, mock)
		setupTestOIDCSubjectStore(t, mock)
		setupTestOIDCUserDetails(t, mock)

		userCode := mustGetTestOIDCUserCode(t, mock)

		consent = newTestOIDCConsentSession(t, mock, mustGetTestOIDCSubject(t, mock, testOIDCDeviceCodeID))
		consent.ClientID = testOIDCDeviceCodeID
		consent.Authorized = true
		consent.GrantedScopes = model.StringSlicePipeDelimited{oidc.ScopeOpenID}

		mock.StorageMock.EXPECT().
			LoadOAuth2ConsentSessionByChallengeID(gomock.Any(), consent.ChallengeID).
			AnyTimes().
			Return(consent, nil)

		return mock, userSession.PlusID, url.Values{
			oidc.FormParameterUserCode: []string{userCode},
			oidc.FormParameterFlowID:   []string{consent.ChallengeID.String()},
		}, consent
	}

	t.Run("ShouldRecordGrant", func(t *testing.T) {
		mock, id, values, consent := setup(t)
		defer mock.Close()

		mock.StorageMock.EXPECT().SaveOAuth2ConsentSessionGranted(gomock.Any(), consent.ID).Times(1).Return(nil)

		rw, r := newTestOAuth2Request(t, fasthttp.MethodPut, testOIDCDeviceAuthorizationEndpoint, values)

		OAuth2DeviceAuthorizationPUT(mock.Ctx, rw, r)

		require.Equal(t, http.StatusOK, rw.Code)

		grants, err := mock.PlusSessionsStore.LoadPlusUserSessionGrants(mock.Ctx, id)

		require.NoError(t, err)
		require.Len(t, grants, 1)
		assert.NotEmpty(t, grants[0].RequestID)
	})

	t.Run("ShouldNotApproveWhenRecordFails", func(t *testing.T) {
		mock, id, values, _ := setup(t)
		defer mock.Close()

		mock.PlusSessionsStore.SetError("SavePlusUserSessionGrant", errors.New("disk full"))

		// No SaveOAuth2ConsentSessionGranted expectation is set, so approving the device fails the test.
		rw, r := newTestOAuth2Request(t, fasthttp.MethodPut, testOIDCDeviceAuthorizationEndpoint, values)

		OAuth2DeviceAuthorizationPUT(mock.Ctx, rw, r)

		assert.NotEqual(t, http.StatusOK, rw.Code)
		assert.Contains(t, rw.Body.String(), "server_error")

		grants, err := mock.PlusSessionsStore.LoadPlusUserSessionGrants(mock.Ctx, id)

		require.NoError(t, err)
		assert.Empty(t, grants)
	})
}

func TestPlusSessionsLogout(t *testing.T) {
	setup := func(t *testing.T) (mock *mocks.MockAutheliaCtx, userSession session.UserSession) {
		t.Helper()

		mock = mocks.NewMockAutheliaCtxWithUserSession(t, newTestOIDCUserSession(1))

		client := newTestOIDCAuthorizationCodeClient(t)
		client.ConsentMode = "implicit"

		setupTestOIDCAuthorizationCodeFlow(t, mock, client)

		userSession, err := mock.Ctx.GetSession()

		require.NoError(t, err)
		require.NotEqual(t, uuid.Nil, userSession.PlusID)

		return mock, userSession
	}

	t.Run("ShouldCloseRecordAndRevokeGrantsFromTheTable", func(t *testing.T) {
		mock, userSession := setup(t)
		defer mock.Close()

		// Item 1: the grant is in the table but not in this copy of the session, as when a concurrent authorization's
		// session save lost the race.
		ok, err := mock.PlusSessionsStore.SavePlusUserSessionGrant(mock.Ctx, model.PlusUserSessionGrant{SessionID: userSession.PlusID, RequestID: "lost-request-id"})

		require.NoError(t, err)
		require.True(t, ok)
		require.Nil(t, userSession.OpenIDConnect)

		mock.StorageMock.EXPECT().RevokeOAuth2SessionsByRequestIDs(gomock.Any(), []string{"lost-request-id"}).Times(1).Return(nil)

		oauth2Logout(mock.Ctx, &userSession)

		record := mock.PlusSessionsStore.Get(userSession.PlusID)

		require.NotNil(t, record)
		assert.True(t, record.RevokedAt.Valid)
		assert.False(t, record.ProcessedAt.Valid, "the poller revokes the grants again")
		assert.Equal(t, plussessions.RevokedByLogout, record.RevokedBy)
		assert.True(t, mock.Ctx.Providers.PlusSessions.Revoked(userSession.PlusID))
	})

	// Item 1: a failed revoke at logout only logs; the record stays for the poller, whose processor revokes the grants.
	t.Run("ShouldLeaveFailedRevokeToThePoller", func(t *testing.T) {
		mock, userSession := setup(t)
		defer mock.Close()

		ok, err := mock.PlusSessionsStore.SavePlusUserSessionGrant(mock.Ctx, model.PlusUserSessionGrant{SessionID: userSession.PlusID, RequestID: "request-id"})

		require.NoError(t, err)
		require.True(t, ok)

		gomock.InOrder(
			mock.StorageMock.EXPECT().RevokeOAuth2SessionsByRequestIDs(gomock.Any(), []string{"request-id"}).Return(errors.New("database is locked")),
			mock.StorageMock.EXPECT().RevokeOAuth2SessionsByRequestIDs(gomock.Any(), []string{"request-id"}).Return(nil),
		)

		oauth2Logout(mock.Ctx, &userSession)

		now := mock.Clock.Now().UTC().Add(time.Minute)

		ids, err := mock.PlusSessionsStore.LoadPlusUserSessionUnprocessedIDs(mock.Ctx, now, now, now, 10)

		require.NoError(t, err)
		require.Equal(t, []uuid.UUID{userSession.PlusID}, ids, "the revocation is left for the poller")

		record := mock.PlusSessionsStore.Get(userSession.PlusID)
		grants, err := mock.PlusSessionsStore.LoadPlusUserSessionGrants(mock.Ctx, userSession.PlusID)

		require.NoError(t, err)

		processor := NewPlusSessionsProcessor(&mock.Ctx.Providers, &mock.Ctx.Configuration, mock.Ctx.Logger)

		require.NoError(t, processor(mock.Ctx, record, grants))
	})

	t.Run("ShouldNotSendLogoutTokenTwiceForLogout", func(t *testing.T) {
		setupTestOIDCBackChannelLogoutInline(t)

		receiver := newTestBackChannelLogoutReceiver(t)

		mock := mocks.NewMockAutheliaCtxWithUserSession(t, newTestOIDCUserSession(1))
		defer mock.Close()

		setupTestOIDCAuthorizationCodeFlow(t, mock, newTestOIDCBackChannelLogoutClient(t, receiver.URL))

		userSession, err := mock.Ctx.GetSession()
		require.NoError(t, err)

		ok, err := mock.PlusSessionsStore.SavePlusUserSessionGrant(mock.Ctx, model.PlusUserSessionGrant{SessionID: userSession.PlusID, RequestID: "request-id", ClientID: testOIDCAuthorizationCodeID, Subject: "subject", SID: "sid", Issuer: "https://login.example.com:8080"})

		require.NoError(t, err)
		require.True(t, ok)

		mock.StorageMock.EXPECT().RevokeOAuth2SessionsByRequestIDs(gomock.Any(), []string{"request-id"}).Return(nil).Times(2)

		oauth2Logout(mock.Ctx, &userSession)

		require.Len(t, receiver.Tokens(), 1)

		record := mock.PlusSessionsStore.Get(userSession.PlusID)
		require.Equal(t, plussessions.RevokedByLogout, record.RevokedBy)

		grants, err := mock.PlusSessionsStore.LoadPlusUserSessionGrants(mock.Ctx, userSession.PlusID)
		require.NoError(t, err)

		processor := NewPlusSessionsProcessor(&mock.Ctx.Providers, &mock.Ctx.Configuration, mock.Ctx.Logger)

		require.NoError(t, processor(mock.Ctx, record, grants))
		assert.Len(t, receiver.Tokens(), 1, "the poller revokes the grants again but sends no second Logout Token")
	})

	t.Run("ShouldNotRevokeGrantsOfProcessedRecord", func(t *testing.T) {
		mock, userSession := setup(t)
		defer mock.Close()

		_, err := mock.PlusSessionsStore.SavePlusUserSessionGrant(mock.Ctx, model.PlusUserSessionGrant{SessionID: userSession.PlusID, RequestID: "request-id"})

		require.NoError(t, err)

		// Another instance revoked and processed the record already.
		mock.PlusSessionsStore.Records[userSession.PlusID].RevokedAt.Valid = true
		mock.PlusSessionsStore.Records[userSession.PlusID].ProcessedAt.Valid = true

		// No storage expectation is set, so any revocation fails the test.
		oauth2Logout(mock.Ctx, &userSession)
	})
}

func TestPlusSessionsEndedWhenRefreshInvalidates(t *testing.T) {
	t.Run("ShouldEndRecordOnAuthz", func(t *testing.T) {
		mock := mocks.NewMockAutheliaCtxWithUserSession(t, newTestOIDCUserSession(1))
		defer mock.Close()

		userSession, err := mock.Ctx.GetSession()
		require.NoError(t, err)
		require.NotEqual(t, uuid.Nil, userSession.PlusID)

		authz := NewAuthzBuilder().WithImplementationForwardAuth().WithStrategies(NewCookieSessionAuthnStrategy(schema.NewRefreshIntervalDurationAlways())).Build()

		target, err := url.ParseRequestURI("https://one-factor.example.com")
		require.NoError(t, err)

		setRequestForwardAuth(mock.Ctx, fasthttp.MethodGet, target, true, false)

		mock.UserProviderMock.EXPECT().GetDetails(userSession.Username).Return(nil, authentication.ErrUserNotFound)

		authz.Handler(mock.Ctx)

		record := mock.PlusSessionsStore.Get(userSession.PlusID)

		assert.True(t, record.RevokedAt.Valid, "the record of a session destroyed for a deleted user is closed")
		assert.Equal(t, plussessions.RevokedByLogout, record.RevokedBy)
	})

	t.Run("ShouldEndRecordOnConsent", func(t *testing.T) {
		mock := mocks.NewMockAutheliaCtxWithUserSession(t, newTestOIDCUserSession(1))
		defer mock.Close()

		mock.Ctx.Configuration.AuthenticationBackend.RefreshInterval = schema.NewRefreshIntervalDurationAlways()

		client := newTestOIDCAuthorizationCodeClient(t)
		client.ConsentMode = "implicit"

		config := newTestOIDCConfig(t)
		config.Clients = []schema.IdentityProvidersOpenIDConnectClient{client}

		// As setupTestOIDCAuthorizationCodeFlow, but the user is gone from the backend.
		setupTestOIDCProvider(t, mock, config)
		setupTestOIDCSessionStore(t, mock)
		setupTestOIDCConsentStore(t, mock)
		setupTestOIDCSubjectStore(t, mock)

		userSession, err := mock.Ctx.GetSession()
		require.NoError(t, err)

		mock.UserProviderMock.EXPECT().GetDetails(userSession.Username).Return(nil, authentication.ErrUserNotFound)

		rw, r := newTestOAuth2Request(t, fasthttp.MethodGet, testOIDCAuthorizationEndpoint, newTestOIDCAuthorizationValues())

		OAuth2AuthorizationGET(mock.Ctx, rw, r)

		record := mock.PlusSessionsStore.Get(userSession.PlusID)

		assert.True(t, record.RevokedAt.Valid, "the record of a session destroyed for a deleted user is closed")
		assert.Equal(t, plussessions.RevokedByLogout, record.RevokedBy)
	})
}
