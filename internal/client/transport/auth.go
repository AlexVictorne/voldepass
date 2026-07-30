package transport

import (
	"context"
	"fmt"

	"github.com/alexvictorne/voldepass/internal/domain"
)

type registerRequest struct {
	Login          string           `json:"login"`
	AuthVerifier   []byte           `json:"auth_verifier"`
	KdfSalt        []byte           `json:"kdf_salt"`
	KdfParams      domain.KdfParams `json:"kdf_params"`
	WrappedDataKey []byte           `json:"wrapped_data_key"`
}

// Register регистрирует нового пользователя на сервере.
func (c *Client) Register(ctx context.Context, login string, authVerifier []byte, profile domain.Profile) error {
	req := registerRequest{
		Login:          login,
		AuthVerifier:   authVerifier,
		KdfSalt:        profile.KdfSalt,
		KdfParams:      profile.KdfParams,
		WrappedDataKey: profile.WrappedDataKey,
	}
	if err := c.doJSON(ctx, "POST", "/api/v1/register", req, nil, false, nil); err != nil {
		return fmt.Errorf("register: %w", err)
	}
	return nil
}

type challengeRequest struct {
	Login string `json:"login"`
}

// ChallengeResult — ответ сервера на запрос challenge: nonce и криптографический профиль.
type ChallengeResult struct {
	ServerNonce string
	Profile     domain.Profile
}

type challengeResponse struct {
	ServerNonce    string           `json:"server_nonce"`
	KdfSalt        []byte           `json:"kdf_salt"`
	KdfParams      domain.KdfParams `json:"kdf_params"`
	WrappedDataKey []byte           `json:"wrapped_data_key"`
}

// Challenge запрашивает serverNonce и криптографический профиль для входа (первая фаза login).
func (c *Client) Challenge(ctx context.Context, login string) (ChallengeResult, error) {
	var resp challengeResponse
	if err := c.doJSON(ctx, "POST", "/api/v1/login/challenge", challengeRequest{Login: login}, &resp, false, nil); err != nil {
		return ChallengeResult{}, fmt.Errorf("challenge: %w", err)
	}
	return ChallengeResult{
		ServerNonce: resp.ServerNonce,
		Profile: domain.Profile{
			KdfSalt:        resp.KdfSalt,
			KdfParams:      resp.KdfParams,
			WrappedDataKey: resp.WrappedDataKey,
		},
	}, nil
}

type loginRequest struct {
	Login   string `json:"login"`
	AuthMsg []byte `json:"auth_msg"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// Login завершает вторую фазу входа: отправляет authMsg = HMAC(authKey, serverNonce)
// и сохраняет полученные access/refresh токены в клиенте.
func (c *Client) Login(ctx context.Context, login string, authMsg []byte) error {
	var resp tokenResponse
	if err := c.doJSON(ctx, "POST", "/api/v1/login", loginRequest{Login: login, AuthMsg: authMsg}, &resp, false, nil); err != nil {
		return fmt.Errorf("login: %w", err)
	}
	c.SetTokens(resp.AccessToken, resp.RefreshToken)
	return nil
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// Refresh обновляет access-токен, используя сохранённый refresh-токен, и сохраняет новую пару.
func (c *Client) Refresh(ctx context.Context) error {
	var resp tokenResponse
	if err := c.doJSON(ctx, "POST", "/api/v1/refresh", refreshRequest{RefreshToken: c.refreshToken}, &resp, false, nil); err != nil {
		return fmt.Errorf("refresh: %w", err)
	}
	c.SetTokens(resp.AccessToken, resp.RefreshToken)
	return nil
}
