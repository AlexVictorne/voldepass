//go:build integration

package integration

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/alexvictorne/voldepass/internal/domain"
)

// TestScenario_RegisterAddSyncSecondClient покрывает основной сквозной сценарий:
// регистрация → добавление всех 5 типов данных → sync → второй клиент → login → pull →
// данные совпадают.
func TestScenario_RegisterAddSyncSecondClient(t *testing.T) {
	srv := newTestServer(t)
	login := uniqueLogin(t)
	token, _ := registerAndLogin(t, srv, login, "master-password")

	types := []domain.DataType{
		domain.DataTypeCredentials, domain.DataTypeText, domain.DataTypeBinary,
		domain.DataTypeCard, domain.DataTypeOTP,
	}
	for i, dt := range types {
		createTestRecord(t, srv, token, dt, "ciphertext-"+string(rune('a'+i)))
	}

	// "Второй клиент": логинимся заново (новый access-токен), пуллим с нуля.
	token2, _ := registerAndLoginExistingUser(t, srv, login, "master-password")
	pulled := syncPull(t, srv, token2, 0)
	assert.Len(t, pulled.Records, len(types))
}

// TestScenario_PushConflict проверяет обнаружение конфликта версий при push с устаревшей BaseVersion.
func TestScenario_PushConflict(t *testing.T) {
	srv := newTestServer(t)
	login := uniqueLogin(t)
	token, _ := registerAndLogin(t, srv, login, "master-password")

	created := createTestRecord(t, srv, token, domain.DataTypeText, "v1")

	resp, _ := syncPush(t, srv, token, "conflict-key-1", domain.SyncPushRequest{
		Records: []domain.RecordDTO{
			{ID: created.ID, Type: domain.DataTypeText, Ciphertext: []byte("v2"), Nonce: []byte("nonce-value12"), BaseVersion: 0},
		},
	})
	require.Len(t, resp.Results, 1)
	assert.Equal(t, domain.PushStatusConflict, resp.Results[0].Status)
}

// TestScenario_DeleteTombstone проверяет, что удаление становится видимым при Pull как tombstone.
func TestScenario_DeleteTombstone(t *testing.T) {
	srv := newTestServer(t)
	login := uniqueLogin(t)
	token, _ := registerAndLogin(t, srv, login, "master-password")

	created := createTestRecord(t, srv, token, domain.DataTypeText, "v1")

	delResp := doJSON(t, contextBg(), http.MethodDelete, srv.URL+"/api/v1/records/"+created.ID, nil, token)
	require.Equal(t, http.StatusNoContent, delResp.StatusCode)
	delResp.Body.Close()

	pulled := syncPull(t, srv, token, 0)
	require.Len(t, pulled.Records, 1)
	assert.True(t, pulled.Records[0].IsDeleted)
}

// TestScenario_IdempotentPushReplay проверяет, что повторный push с тем же
// Idempotency-Key не применяет upsert повторно и возвращает тот же результат.
func TestScenario_IdempotentPushReplay(t *testing.T) {
	srv := newTestServer(t)
	login := uniqueLogin(t)
	token, _ := registerAndLogin(t, srv, login, "master-password")

	req := domain.SyncPushRequest{Records: []domain.RecordDTO{
		{ID: "idem-rec-1", Type: domain.DataTypeText, Ciphertext: []byte("v1"), Nonce: []byte("nonce-value12"), BaseVersion: 0},
	}}

	resp1, _ := syncPush(t, srv, token, "same-key", req)
	resp2, _ := syncPush(t, srv, token, "same-key", req)
	assert.Equal(t, resp1, resp2, "replayed push must return the cached result")

	pulled := syncPull(t, srv, token, 0)
	require.Len(t, pulled.Records, 1)
	assert.Equal(t, resp1.Results[0].ServerRecord.Version, pulled.Records[0].Version, "version must not have incremented twice")
}

// TestScenario_ReplayLogin проверяет защиту от replay: повторное использование
// уже погашенного authMsg должно быть отклонено.
func TestScenario_ReplayLogin(t *testing.T) {
	srv := newTestServer(t)
	login := uniqueLogin(t)

	authKey, nonce := registerAndCaptureChallenge(t, srv, login, "master-password")

	authMsg := hmacAuthMsg(authKey, nonce)
	loginResp := doJSON(t, contextBg(), http.MethodPost, srv.URL+"/api/v1/login", map[string]any{
		"login": login, "auth_msg": authMsg,
	}, "")
	require.Equal(t, http.StatusOK, loginResp.StatusCode)
	loginResp.Body.Close()

	// Повторная попытка с тем же authMsg — challenge уже погашен.
	replayResp := doJSON(t, contextBg(), http.MethodPost, srv.URL+"/api/v1/login", map[string]any{
		"login": login, "auth_msg": authMsg,
	}, "")
	defer replayResp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, replayResp.StatusCode)
}

// TestScenario_RefreshRotationTheftDetection проверяет ротацию refresh-токена и
// детект кражи при повторном использовании уже ротированного токена.
func TestScenario_RefreshRotationTheftDetection(t *testing.T) {
	srv := newTestServer(t)
	login := uniqueLogin(t)
	_, refreshToken := registerAndLogin(t, srv, login, "master-password")

	refreshResp := doJSON(t, contextBg(), http.MethodPost, srv.URL+"/api/v1/refresh", map[string]any{
		"refresh_token": refreshToken,
	}, "")
	require.Equal(t, http.StatusOK, refreshResp.StatusCode)
	refreshResp.Body.Close()

	// Повторное использование уже ротированного refresh-токена — детект кражи.
	replayResp := doJSON(t, contextBg(), http.MethodPost, srv.URL+"/api/v1/refresh", map[string]any{
		"refresh_token": refreshToken,
	}, "")
	defer replayResp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, replayResp.StatusCode)
}

// TestScenario_IncompatibleAPIVersion проверяет 426 Upgrade Required при
// несовместимой major-версии X-API-Version.
func TestScenario_IncompatibleAPIVersion(t *testing.T) {
	srv := newTestServer(t)
	login := uniqueLogin(t)
	token, _ := registerAndLogin(t, srv, login, "master-password")

	req, err := http.NewRequestWithContext(contextBg(), http.MethodGet, srv.URL+"/api/v1/sync", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-API-Version", "99.0.0")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUpgradeRequired, resp.StatusCode)
}

// registerAndLoginExistingUser логинится в уже зарегистрированный аккаунт (второй "клиент").
func registerAndLoginExistingUser(t *testing.T, srv *testServer, login, password string) (accessToken, refreshToken string) {
	t.Helper()
	authKey, nonce := challengeExistingUser(t, srv, login, password)
	authMsg := hmacAuthMsg(authKey, nonce)

	loginResp := doJSON(t, contextBg(), http.MethodPost, srv.URL+"/api/v1/login", map[string]any{
		"login": login, "auth_msg": authMsg,
	}, "")
	require.Equal(t, http.StatusOK, loginResp.StatusCode)
	defer loginResp.Body.Close()

	var tokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	require.NoError(t, decodeJSON(loginResp, &tokens))
	return tokens.AccessToken, tokens.RefreshToken
}

// registerAndCaptureChallenge регистрирует пользователя и возвращает authKey + serverNonce
// для последующей ручной сборки authMsg (используется в replay-тестах).
func registerAndCaptureChallenge(t *testing.T, srv *testServer, login, password string) (authKey []byte, nonce string) {
	t.Helper()
	registerUserOnly(t, srv, login, password)
	return challengeExistingUser(t, srv, login, password)
}
