package rest_test

import (
	"encoding/json"
	"net/http"
	"testing"

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
	// Неизвестный токен транслируется как ErrNotFound (нет такого refresh-токена).
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestRouter_Register_InvalidBody(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/api/v1/register", "application/json", nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
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
