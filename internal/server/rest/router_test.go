package rest_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/alexvictorne/voldepass/internal/client/crypto"
	"github.com/alexvictorne/voldepass/internal/domain"
	serverauth "github.com/alexvictorne/voldepass/internal/server/auth"
	"github.com/alexvictorne/voldepass/internal/server/rest"
	"github.com/alexvictorne/voldepass/internal/server/service"
	"github.com/alexvictorne/voldepass/internal/server/storage/inmem"
)

var fastParams = domain.KdfParams{Time: 1, Memory: 16 * 1024, Threads: 1, KeyLen: 32}

// newTestServer собирает полный REST-сервер поверх in-memory зависимостей (CORS отключён).
func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return newTestServerWithCORS(t, nil)
}

// newTestServerWithCORS — как newTestServer, но с настраиваемым списком разрешённых CORS-origin.
func newTestServerWithCORS(t *testing.T, corsAllowedOrigins []string) *httptest.Server {
	t.Helper()

	users := inmem.NewUserRepository()
	records := inmem.NewRecordRepository()
	idempotency := inmem.NewIdempotencyStore()

	jwt := serverauth.NewJWTManager([]byte("test-secret-32-bytes-long-enough"), 15*time.Minute)
	challenges := serverauth.NewChallengeStore(time.Minute)
	refresh := serverauth.NewRefreshTokenService(inmem.NewRefreshTokenStore(), time.Hour)
	attempts := inmem.NewLoginAttemptTracker(5, time.Minute)

	authSvc := service.NewAuthService(users, challenges, jwt, refresh, attempts)
	vaultSvc := service.NewVaultService(records)
	syncSvc := service.NewSyncService(records, idempotency)

	router := rest.NewRouter(
		rest.NewAuthHandlers(authSvc),
		rest.NewVaultHandlers(vaultSvc),
		rest.NewSyncHandlers(syncSvc),
		jwt,
		corsAllowedOrigins,
		zerolog.Nop(),
		attempts,
	)
	return httptest.NewServer(router)
}

func doJSON(t *testing.T, method, url string, body any, token string) *http.Response {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		data, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewReader(data)
	} else {
		reader = bytes.NewReader(nil)
	}

	req, err := http.NewRequest(method, url, reader)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

// registerAndLogin регистрирует пользователя и логинится, возвращая access-токен.
func registerAndLogin(t *testing.T, baseURL, login, password string) string {
	t.Helper()

	salt, err := crypto.GenerateSalt()
	require.NoError(t, err)
	authKey, encKey := crypto.DeriveKeys(password, salt, fastParams)

	dataKey, err := crypto.GenerateDataKey()
	require.NoError(t, err)
	wrapped, err := crypto.WrapKey(encKey, dataKey)
	require.NoError(t, err)

	regResp := doJSON(t, http.MethodPost, baseURL+"/api/v1/register", map[string]any{
		"login":            login,
		"auth_verifier":    authKey,
		"kdf_salt":         salt,
		"kdf_params":       fastParams,
		"wrapped_data_key": wrapped,
	}, "")
	require.Equal(t, http.StatusCreated, regResp.StatusCode)
	regResp.Body.Close()

	challResp := doJSON(t, http.MethodPost, baseURL+"/api/v1/login/challenge", map[string]any{"login": login}, "")
	require.Equal(t, http.StatusOK, challResp.StatusCode)
	var chall struct {
		ServerNonce string `json:"server_nonce"`
	}
	require.NoError(t, json.NewDecoder(challResp.Body).Decode(&chall))
	challResp.Body.Close()

	authMsg := crypto.AuthMessage(authKey, []byte(chall.ServerNonce))
	loginResp := doJSON(t, http.MethodPost, baseURL+"/api/v1/login", map[string]any{
		"login":    login,
		"auth_msg": authMsg,
	}, "")
	require.Equal(t, http.StatusOK, loginResp.StatusCode)
	var tokens struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.NewDecoder(loginResp.Body).Decode(&tokens))
	loginResp.Body.Close()

	return tokens.AccessToken
}

func TestRouter_RegisterLoginFlow(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	token := registerAndLogin(t, srv.URL, "alice", "master-password")
	assert.NotEmpty(t, token)
}

func TestRouter_RecordCRUD(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	token := registerAndLogin(t, srv.URL, "alice", "master-password")

	createResp := doJSON(t, http.MethodPost, srv.URL+"/api/v1/records", map[string]any{
		"type":       domain.DataTypeText,
		"ciphertext": []byte("secret"),
		"nonce":      []byte("nonce1234567"),
	}, token)
	require.Equal(t, http.StatusCreated, createResp.StatusCode)
	var created map[string]any
	require.NoError(t, json.NewDecoder(createResp.Body).Decode(&created))
	createResp.Body.Close()
	id := created["id"].(string)

	getResp := doJSON(t, http.MethodGet, srv.URL+"/api/v1/records/"+id, nil, token)
	require.Equal(t, http.StatusOK, getResp.StatusCode)
	getResp.Body.Close()

	deleteResp := doJSON(t, http.MethodDelete, srv.URL+"/api/v1/records/"+id, nil, token)
	assert.Equal(t, http.StatusNoContent, deleteResp.StatusCode)
	deleteResp.Body.Close()
}

func TestRouter_RecordCRUD_Unauthorized(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	resp := doJSON(t, http.MethodGet, srv.URL+"/api/v1/records", nil, "")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()
}

func TestRouter_SyncPushAndPull(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	token := registerAndLogin(t, srv.URL, "alice", "master-password")

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/sync", bytes.NewReader(mustJSON(t, domain.SyncPushRequest{
		Records: []domain.RecordDTO{
			{ID: "r1", Type: domain.DataTypeText, Ciphertext: []byte("ct"), Nonce: []byte("nonce"), BaseVersion: 0},
		},
	})))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Idempotency-Key", "test-key-1")
	req.Header.Set("Content-Type", "application/json")

	pushResp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, pushResp.StatusCode)
	var pushOut domain.SyncPushResponse
	require.NoError(t, json.NewDecoder(pushResp.Body).Decode(&pushOut))
	pushResp.Body.Close()
	require.Len(t, pushOut.Results, 1)
	assert.Equal(t, domain.PushStatusApplied, pushOut.Results[0].Status)

	pullResp := doJSON(t, http.MethodGet, srv.URL+"/api/v1/sync?since=0", nil, token)
	require.Equal(t, http.StatusOK, pullResp.StatusCode)
	var pullOut domain.SyncPullResponse
	require.NoError(t, json.NewDecoder(pullResp.Body).Decode(&pullOut))
	pullResp.Body.Close()
	require.Len(t, pullOut.Records, 1)
	assert.Equal(t, "r1", pullOut.Records[0].ID)
}

func TestRouter_SyncPush_MissingIdempotencyKey(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	token := registerAndLogin(t, srv.URL, "alice", "master-password")

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/v1/sync", domain.SyncPushRequest{}, token)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()
}

func TestRouter_IncompatibleAPIVersion(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/sync", nil)
	require.NoError(t, err)
	req.Header.Set("X-API-Version", "99.0.0")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUpgradeRequired, resp.StatusCode)
	resp.Body.Close()
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	require.NoError(t, err)
	return data
}
