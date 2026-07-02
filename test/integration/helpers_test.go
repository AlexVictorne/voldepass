//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/alexvictorne/voldepass/internal/client/crypto"
	"github.com/alexvictorne/voldepass/internal/domain"
	serverauth "github.com/alexvictorne/voldepass/internal/server/auth"
	"github.com/alexvictorne/voldepass/internal/server/rest"
	"github.com/alexvictorne/voldepass/internal/server/service"
	"github.com/alexvictorne/voldepass/internal/server/storage/inmem"
	"github.com/alexvictorne/voldepass/internal/server/storage/postgres"
)

// newLoginAttemptTrackerNoLimit возвращает трекер с заведомо большим лимитом —
// эти тесты фокусируются на бизнес-логике, а не на rate-limiting.
func newLoginAttemptTrackerNoLimit() *inmem.LoginAttemptTracker {
	return inmem.NewLoginAttemptTracker(1_000_000, time.Hour)
}

var fastKdfParams = domain.KdfParams{Time: 1, Memory: 16 * 1024, Threads: 1, KeyLen: 32}

// testServer оборачивает httptest.Server, поднятый поверх реального PostgreSQL.
type testServer struct {
	*httptest.Server
}

// newTestServer собирает полный REST-сервер поверх PostgreSQL, поднятого в TestMain.
func newTestServer(t *testing.T) *testServer {
	t.Helper()

	users := postgres.NewUserRepository(testPool)
	records := postgres.NewRecordRepository(testPool)
	idempotency := postgres.NewIdempotencyStore(testPool)
	refreshTokens := postgres.NewRefreshTokenStore(testPool)

	jwt := serverauth.NewJWTManager([]byte("integration-test-secret-32-bytes"), 15*time.Minute)
	challenges := serverauth.NewChallengeStore(time.Minute)
	refresh := serverauth.NewRefreshTokenService(refreshTokens, time.Hour)
	// Лимит попыток намеренно высокий — эти тесты не про rate-limit ошибочного логина.
	attempts := newLoginAttemptTrackerNoLimit()

	authSvc := service.NewAuthService(users, challenges, jwt, refresh, attempts)
	vaultSvc := service.NewVaultService(records)
	syncSvc := service.NewSyncService(records, idempotency)

	router := rest.NewRouter(
		rest.NewAuthHandlers(authSvc),
		rest.NewVaultHandlers(vaultSvc),
		rest.NewSyncHandlers(syncSvc),
		jwt,
	)
	return &testServer{Server: httptest.NewServer(router)}
}

// uniqueLogin генерирует уникальный логин для изоляции данных теста в общей БД контейнера.
func uniqueLogin(t *testing.T) string {
	t.Helper()
	return "user-" + uuid.NewString()
}

// registerAndLogin регистрирует пользователя и логинится, возвращая access и refresh токены.
func registerAndLogin(t *testing.T, srv *testServer, login, password string) (accessToken, refreshToken string) {
	t.Helper()
	ctx := context.Background()

	salt, err := crypto.GenerateSalt()
	require.NoError(t, err)
	authKey, encKey := crypto.DeriveKeys(password, salt, fastKdfParams)

	dataKey, err := crypto.GenerateDataKey()
	require.NoError(t, err)
	wrapped, err := crypto.WrapKey(encKey, dataKey)
	require.NoError(t, err)

	regResp := doJSON(t, ctx, http.MethodPost, srv.URL+"/api/v1/register", map[string]any{
		"login": login, "auth_verifier": authKey,
		"kdf_salt": salt, "kdf_params": fastKdfParams, "wrapped_data_key": wrapped,
	}, "")
	require.Equal(t, http.StatusCreated, regResp.StatusCode)
	regResp.Body.Close()

	challResp := doJSON(t, ctx, http.MethodPost, srv.URL+"/api/v1/login/challenge", map[string]any{"login": login}, "")
	require.Equal(t, http.StatusOK, challResp.StatusCode)
	var chall struct {
		ServerNonce string `json:"server_nonce"`
	}
	require.NoError(t, json.NewDecoder(challResp.Body).Decode(&chall))
	challResp.Body.Close()

	authMsg := crypto.AuthMessage(authKey, []byte(chall.ServerNonce))
	loginResp := doJSON(t, ctx, http.MethodPost, srv.URL+"/api/v1/login", map[string]any{
		"login": login, "auth_msg": authMsg,
	}, "")
	require.Equal(t, http.StatusOK, loginResp.StatusCode)
	var tokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	require.NoError(t, json.NewDecoder(loginResp.Body).Decode(&tokens))
	loginResp.Body.Close()

	return tokens.AccessToken, tokens.RefreshToken
}

// createTestRecord создаёт запись через REST API от имени залогиненного пользователя.
func createTestRecord(t *testing.T, srv *testServer, token string, dataType domain.DataType, ciphertext string) domain.RecordDTO {
	t.Helper()
	resp := doJSON(t, context.Background(), http.MethodPost, srv.URL+"/api/v1/records", map[string]any{
		"type": dataType, "ciphertext": []byte(ciphertext), "nonce": []byte("test-nonce-12"),
	}, token)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	defer resp.Body.Close()

	var dto domain.RecordDTO
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&dto))
	return dto
}

// syncPull выполняет GET /sync?since= от имени залогиненного пользователя.
func syncPull(t *testing.T, srv *testServer, token string, since int64) domain.SyncPullResponse {
	t.Helper()
	url := fmt.Sprintf("%s/api/v1/sync?since=%d", srv.URL, since)
	resp := doJSON(t, context.Background(), http.MethodGet, url, nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()

	var out domain.SyncPullResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	return out
}

// syncPush выполняет POST /sync с заголовком Idempotency-Key.
func syncPush(t *testing.T, srv *testServer, token, idempotencyKey string, req domain.SyncPushRequest) (domain.SyncPushResponse, *http.Response) {
	t.Helper()
	data, err := json.Marshal(req)
	require.NoError(t, err)

	httpReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/api/v1/sync", bytes.NewReader(data))
	require.NoError(t, err)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Idempotency-Key", idempotencyKey)

	resp, err := http.DefaultClient.Do(httpReq)
	require.NoError(t, err)
	defer resp.Body.Close()

	var out domain.SyncPushResponse
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out, resp
}

// contextBg — короткий алиас для context.Background(), используемый в тестовых сценариях.
func contextBg() context.Context {
	return context.Background()
}

// decodeJSON декодирует тело ответа в out.
func decodeJSON(resp *http.Response, out any) error {
	return json.NewDecoder(resp.Body).Decode(out)
}

// registerUserOnly регистрирует пользователя, не выполняя login.
func registerUserOnly(t *testing.T, srv *testServer, login, password string) (authKey []byte) {
	t.Helper()

	salt, err := crypto.GenerateSalt()
	require.NoError(t, err)
	var encKey []byte
	authKey, encKey = crypto.DeriveKeys(password, salt, fastKdfParams)

	dataKey, err := crypto.GenerateDataKey()
	require.NoError(t, err)
	wrapped, err := crypto.WrapKey(encKey, dataKey)
	require.NoError(t, err)

	resp := doJSON(t, context.Background(), http.MethodPost, srv.URL+"/api/v1/register", map[string]any{
		"login": login, "auth_verifier": authKey,
		"kdf_salt": salt, "kdf_params": fastKdfParams, "wrapped_data_key": wrapped,
	}, "")
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	resp.Body.Close()
	return authKey
}

// challengeExistingUser запрашивает challenge для уже зарегистрированного пользователя
// и заново выводит authKey из ответа сервера (kdf_salt/kdf_params), как это делает клиент при login.
func challengeExistingUser(t *testing.T, srv *testServer, login, password string) (authKey []byte, nonce string) {
	t.Helper()

	resp := doJSON(t, context.Background(), http.MethodPost, srv.URL+"/api/v1/login/challenge", map[string]any{"login": login}, "")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()

	var chall struct {
		ServerNonce string           `json:"server_nonce"`
		KdfSalt     []byte           `json:"kdf_salt"`
		KdfParams   domain.KdfParams `json:"kdf_params"`
	}
	require.NoError(t, decodeJSON(resp, &chall))

	authKey, _ = crypto.DeriveKeys(password, chall.KdfSalt, chall.KdfParams)
	return authKey, chall.ServerNonce
}

// hmacAuthMsg — тонкая обёртка над crypto.AuthMessage для читаемости тестов.
func hmacAuthMsg(authKey []byte, nonce string) []byte {
	return crypto.AuthMessage(authKey, []byte(nonce))
}

// doJSON — низкоуровневый JSON-запрос с опциональным Bearer-токеном.
func doJSON(t *testing.T, ctx context.Context, method, url string, body any, token string) *http.Response {
	t.Helper()

	var reader *bytes.Reader
	if body != nil {
		data, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewReader(data)
	} else {
		reader = bytes.NewReader(nil)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}
