package rest

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/alexvictorne/voldepass/internal/domain"
	"github.com/alexvictorne/voldepass/internal/server/service"
)

// authService — интерфейс, требуемый auth-хендлерами. Реализуется service.AuthService.
type authService interface {
	Register(ctx context.Context, login string, authVerifier []byte, profile domain.Profile) (domain.User, error)
	Challenge(ctx context.Context, login string) (nonce string, profile domain.Profile, err error)
	Login(ctx context.Context, login string, authMsg []byte) (tokens service.AuthTokens, err error)
	Refresh(ctx context.Context, refreshToken string) (tokens service.AuthTokens, err error)
}

// AuthHandlers — HTTP-хендлеры регистрации и аутентификации.
type AuthHandlers struct {
	svc authService
}

// NewAuthHandlers создаёт хендлеры аутентификации поверх сервиса.
func NewAuthHandlers(svc authService) *AuthHandlers {
	return &AuthHandlers{svc: svc}
}

type registerRequest struct {
	Login          string           `json:"login"`
	AuthVerifier   []byte           `json:"auth_verifier"`
	KdfSalt        []byte           `json:"kdf_salt"`
	KdfParams      domain.KdfParams `json:"kdf_params"`
	WrappedDataKey []byte           `json:"wrapped_data_key"`
}

// Register godoc
//
//	@Summary		Register a new user
//	@Description	Creates a new user with a zero-knowledge crypto profile. The server never
//	@Description	sees the master password or the derived encryption key.
//	@Tags			auth
//	@Accept			json
//	@Produce		json
//	@Param			request	body		registerRequest	true	"Registration payload"
//	@Success		201		{object}	map[string]string
//	@Failure		400		{object}	errorResponse
//	@Failure		409		{object}	errorResponse	"login already taken"
//	@Router			/register [post]
func (h *AuthHandlers) Register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, domain.ErrInvalidArgument)
		return
	}

	profile := domain.Profile{
		KdfSalt:        req.KdfSalt,
		KdfParams:      req.KdfParams,
		WrappedDataKey: req.WrappedDataKey,
		ProfileVersion: 1,
	}

	u, err := h.svc.Register(r.Context(), req.Login, req.AuthVerifier, profile)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": u.ID, "login": u.Login})
}

type challengeRequest struct {
	Login string `json:"login"`
}

type challengeResponse struct {
	ServerNonce    string           `json:"server_nonce"`
	KdfSalt        []byte           `json:"kdf_salt"`
	KdfParams      domain.KdfParams `json:"kdf_params"`
	WrappedDataKey []byte           `json:"wrapped_data_key"`
}

// Challenge godoc
//
//	@Summary		Request a login challenge
//	@Description	First phase of challenge-response login. Returns a one-time serverNonce
//	@Description	(consumed on first use) plus the user's crypto profile needed to derive keys.
//	@Tags			auth
//	@Accept			json
//	@Produce		json
//	@Param			request	body		challengeRequest	true	"Login identifier"
//	@Success		200		{object}	challengeResponse
//	@Failure		400		{object}	errorResponse
//	@Failure		404		{object}	errorResponse	"unknown login"
//	@Router			/login/challenge [post]
func (h *AuthHandlers) Challenge(w http.ResponseWriter, r *http.Request) {
	var req challengeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, domain.ErrInvalidArgument)
		return
	}

	nonce, profile, err := h.svc.Challenge(r.Context(), req.Login)
	if err != nil {
		writeError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, challengeResponse{
		ServerNonce:    nonce,
		KdfSalt:        profile.KdfSalt,
		KdfParams:      profile.KdfParams,
		WrappedDataKey: profile.WrappedDataKey,
	})
}

type loginRequest struct {
	Login   string `json:"login"`
	AuthMsg []byte `json:"auth_msg"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// Login godoc
//
//	@Summary		Complete challenge-response login
//	@Description	Second phase of login. authMsg = HMAC-SHA256(authKey, serverNonce), computed
//	@Description	entirely client-side; the master password and authKey never cross the wire.
//	@Tags			auth
//	@Accept			json
//	@Produce		json
//	@Param			request	body		loginRequest	true	"Login and computed authMsg"
//	@Success		200		{object}	tokenResponse
//	@Failure		400		{object}	errorResponse
//	@Failure		401		{object}	errorResponse	"invalid authMsg or expired/consumed challenge"
//	@Failure		429		{object}	errorResponse	"rate limited"
//	@Router			/login [post]
func (h *AuthHandlers) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, domain.ErrInvalidArgument)
		return
	}

	tokens, err := h.svc.Login(r.Context(), req.Login, req.AuthMsg)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, tokenResponse{AccessToken: tokens.AccessToken, RefreshToken: tokens.RefreshToken})
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// Refresh godoc
//
//	@Summary		Rotate the refresh token and issue a new access token
//	@Description	The old refresh token is invalidated. Reusing an already-rotated token
//	@Description	revokes the entire token family (theft detection).
//	@Tags			auth
//	@Accept			json
//	@Produce		json
//	@Param			request	body		refreshRequest	true	"Current refresh token"
//	@Success		200		{object}	tokenResponse
//	@Failure		400		{object}	errorResponse
//	@Failure		401		{object}	errorResponse	"expired, unknown, or reused token"
//	@Router			/refresh [post]
func (h *AuthHandlers) Refresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, domain.ErrInvalidArgument)
		return
	}

	tokens, err := h.svc.Refresh(r.Context(), req.RefreshToken)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, tokenResponse{AccessToken: tokens.AccessToken, RefreshToken: tokens.RefreshToken})
}
