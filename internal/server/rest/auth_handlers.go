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

// Register обрабатывает POST /api/v1/register.
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

// Challenge обрабатывает POST /api/v1/login/challenge.
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

// Login обрабатывает POST /api/v1/login.
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

// Refresh обрабатывает POST /api/v1/refresh.
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
