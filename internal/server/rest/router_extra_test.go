package rest_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/alexvictorne/voldepass/internal/client/crypto"
	"github.com/alexvictorne/voldepass/internal/domain"
)

func TestRouter_SwaggerUIServed(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/swagger/index.html")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestRouter_RecordUpdate(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	token := registerAndLogin(t, srv.URL, "alice", "master-password")

	createResp := doJSON(t, http.MethodPost, srv.URL+"/api/v1/records", map[string]any{
		"type": domain.DataTypeText, "ciphertext": []byte("v1"), "nonce": []byte("nonce1234567"),
	}, token)
	require.Equal(t, http.StatusCreated, createResp.StatusCode)
	var created map[string]any
	require.NoError(t, json.NewDecoder(createResp.Body).Decode(&created))
	createResp.Body.Close()
	id := created["id"].(string)
	version := created["version"].(float64)

	updateResp := doJSON(t, http.MethodPut, srv.URL+"/api/v1/records/"+id, map[string]any{
		"type": domain.DataTypeText, "ciphertext": []byte("v2"), "nonce": []byte("nonce1234567"),
		"base_version": int64(version),
	}, token)
	defer updateResp.Body.Close()
	assert.Equal(t, http.StatusOK, updateResp.StatusCode)
}

func TestRouter_RecordUpdate_InvalidBody(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	token := registerAndLogin(t, srv.URL, "alice", "master-password")

	req, err := http.NewRequest(http.MethodPut, srv.URL+"/api/v1/records/some-id", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestRouter_RecordGet_InvalidID(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	token := registerAndLogin(t, srv.URL, "alice", "master-password")

	resp := doJSON(t, http.MethodGet, srv.URL+"/api/v1/records/not-a-uuid", nil, token)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "malformed id must be rejected before it reaches the repository")
}

func TestRouter_RecordDelete_InvalidID(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	token := registerAndLogin(t, srv.URL, "alice", "master-password")

	resp := doJSON(t, http.MethodDelete, srv.URL+"/api/v1/records/not-a-uuid", nil, token)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestRouter_SyncPush_InvalidRecordID(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	token := registerAndLogin(t, srv.URL, "alice", "master-password")

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/sync", bytes.NewReader(mustJSON(t, domain.SyncPushRequest{
		Records: []domain.RecordDTO{
			{ID: "not-a-uuid", Type: domain.DataTypeText, Ciphertext: []byte("ct"), Nonce: []byte("nonce")},
		},
	})))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Idempotency-Key", "invalid-id-key")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "a non-UUID record id in a push batch must be rejected")
}

func TestRouter_SyncPush_InvalidRecordType(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	token := registerAndLogin(t, srv.URL, "alice", "master-password")

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/sync", bytes.NewReader(mustJSON(t, domain.SyncPushRequest{
		Records: []domain.RecordDTO{
			{ID: uuid.NewString(), Type: domain.DataType(99), Ciphertext: []byte("ct"), Nonce: []byte("nonce")},
		},
	})))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Idempotency-Key", "invalid-type-key")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "an out-of-range record type must be rejected")
}

func TestRouter_Create_InvalidRecordType(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	token := registerAndLogin(t, srv.URL, "alice", "master-password")

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/v1/records", map[string]any{
		"type": 99, "ciphertext": []byte("ct"), "nonce": []byte("nonce1234567"),
	}, token)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "an out-of-range record type must be rejected")
}

func TestRouter_Register_LoginTooLong(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	longLogin := strings.Repeat("a", 201)
	resp := doJSON(t, http.MethodPost, srv.URL+"/api/v1/register", map[string]any{
		"login": longLogin, "auth_verifier": []byte("verifier"),
		"kdf_salt": []byte("salt"), "kdf_params": fastParams, "wrapped_data_key": []byte("wrapped"),
	}, "")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "a login exceeding the VARCHAR(200) column must be rejected before it reaches Postgres")
}

func TestRouter_SyncPush_IdempotencyKeyTooLong(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	token := registerAndLogin(t, srv.URL, "alice", "master-password")

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/sync", bytes.NewReader(mustJSON(t, domain.SyncPushRequest{})))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Idempotency-Key", strings.Repeat("k", 201))
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "an idempotency key exceeding the VARCHAR(200) column must be rejected")
}

func TestRouter_RecordList_Empty(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	token := registerAndLogin(t, srv.URL, "alice", "master-password")

	resp := doJSON(t, http.MethodGet, srv.URL+"/api/v1/records", nil, token)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var list []map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&list))
	assert.Empty(t, list)
}

func TestRouter_RecordList_AfterCreate(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	token := registerAndLogin(t, srv.URL, "alice", "master-password")

	createResp := doJSON(t, http.MethodPost, srv.URL+"/api/v1/records", map[string]any{
		"type": domain.DataTypeText, "ciphertext": []byte("v1"), "nonce": []byte("nonce1234567"),
	}, token)
	createResp.Body.Close()

	resp := doJSON(t, http.MethodGet, srv.URL+"/api/v1/records", nil, token)
	defer resp.Body.Close()
	var list []map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&list))
	assert.Len(t, list, 1)
}

func TestRouter_Refresh(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	refreshTok := loginAndGetRefreshToken(t, srv.URL, "alice", "master-password")

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/v1/refresh", map[string]any{"refresh_token": refreshTok}, "")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestRouter_Refresh_InvalidToken(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/v1/refresh", map[string]any{"refresh_token": "garbage"}, "")
	defer resp.Body.Close()
	// Неизвестный токен — это ошибка аутентификации (401), а не "ресурс не найден".
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestRouter_Register_InvalidBody(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/api/v1/register", "application/json", nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestRouter_Register_OversizedBody проверяет лимит тела запроса для auth-эндпоинтов
// (Register/Challenge/Refresh — доступны без авторизации, поэтому особенно важно отсекать
// произвольно большие тела до их вычитывания в память, см. maxAuthRequestBodyBytes).
func TestRouter_Register_OversizedBody(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	// Полезная нагрузка должна оставаться синтаксически валидным префиксом JSON (здесь —
	// один большой строковый litera), иначе json.Decoder падает с SyntaxError на первом же
	// невалидном байте, не успев дочитать тело до реального превышения MaxBytesReader.
	oversized := []byte(`{"login":"` + strings.Repeat("a", 64*1024+1) + `"}`)
	resp, err := http.Post(srv.URL+"/api/v1/register", "application/json", bytes.NewReader(oversized))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode, "body over the auth request limit must be rejected")
}

// TestRouter_RecordCreate_OversizedBody проверяет лимит тела для Create/Update
// (maxRecordRequestBodyBytes) — записи несут реальный полезный груз (ciphertext,
// в т.ч. Binary-вложения), поэтому лимит выше, чем для auth-эндпоинтов, но всё ещё ограничен.
func TestRouter_RecordCreate_OversizedBody(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	token := registerAndLogin(t, srv.URL, "alice", "master-password")

	oversized := []byte(`{"ciphertext":"` + strings.Repeat("a", 10<<20+1) + `"}`)
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/records", bytes.NewReader(oversized))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode, "body over the record request limit must be rejected")
}

// TestRouter_SyncPush_OversizedBody проверяет лимит тела для Push-батча
// (maxSyncPushRequestBodyBytes) — самый большой из трёх, т.к. несёт пачку записей
// (клиент по умолчанию чанкует по 100 записей за раз).
func TestRouter_SyncPush_OversizedBody(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	token := registerAndLogin(t, srv.URL, "alice", "master-password")

	oversized := []byte(`{"records":[{"ciphertext":"` + strings.Repeat("a", 50<<20+1) + `"}]}`)
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/sync", bytes.NewReader(oversized))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Idempotency-Key", "oversized-body-key")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode, "body over the sync push request limit must be rejected")
}

func TestRouter_Login_InvalidBody(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/api/v1/login", "application/json", nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestRouter_Challenge_InvalidBody(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/api/v1/login/challenge", "application/json", nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestRouter_Refresh_InvalidBody(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/api/v1/refresh", "application/json", nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// loginAndGetRefreshToken выполняет полный register+challenge+login и возвращает refresh-токен.
func loginAndGetRefreshToken(t *testing.T, baseURL, login, password string) string {
	t.Helper()

	salt, err := crypto.GenerateSalt()
	require.NoError(t, err)
	authKey, encKey := crypto.DeriveKeys(password, salt, fastParams)

	dataKey, err := crypto.GenerateDataKey()
	require.NoError(t, err)
	wrapped, err := crypto.WrapKey(encKey, dataKey)
	require.NoError(t, err)

	regResp := doJSON(t, http.MethodPost, baseURL+"/api/v1/register", map[string]any{
		"login": login, "auth_verifier": authKey,
		"kdf_salt": salt, "kdf_params": fastParams, "wrapped_data_key": wrapped,
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
		"login": login, "auth_msg": authMsg,
	}, "")
	require.Equal(t, http.StatusOK, loginResp.StatusCode)
	defer loginResp.Body.Close()

	var tokens struct {
		RefreshToken string `json:"refresh_token"`
	}
	require.NoError(t, json.NewDecoder(loginResp.Body).Decode(&tokens))
	return tokens.RefreshToken
}

func TestRouter_CORS_AllowedOriginReflectedInPreflight(t *testing.T) {
	srv := newTestServerWithCORS(t, []string{"https://app.example.com"})
	defer srv.Close()

	req, err := http.NewRequest(http.MethodOptions, srv.URL+"/api/v1/records", nil)
	require.NoError(t, err)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", http.MethodGet)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, "https://app.example.com", resp.Header.Get("Access-Control-Allow-Origin"))
}

func TestRouter_CORS_DisallowedOriginNotReflected(t *testing.T) {
	srv := newTestServerWithCORS(t, []string{"https://app.example.com"})
	defer srv.Close()

	req, err := http.NewRequest(http.MethodOptions, srv.URL+"/api/v1/records", nil)
	require.NoError(t, err)
	req.Header.Set("Origin", "https://evil.example.com")
	req.Header.Set("Access-Control-Request-Method", http.MethodGet)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Empty(t, resp.Header.Get("Access-Control-Allow-Origin"), "an origin not on the allowlist must not be reflected back")
}

func TestRouter_CORS_DisabledByDefault(t *testing.T) {
	srv := newTestServer(t) // CORS отключён (corsAllowedOrigins == nil)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodOptions, srv.URL+"/api/v1/records", nil)
	require.NoError(t, err)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", http.MethodGet)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Empty(t, resp.Header.Get("Access-Control-Allow-Origin"), "CORS must be off entirely when no origins are configured")
}
