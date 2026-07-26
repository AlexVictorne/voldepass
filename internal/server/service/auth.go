package service

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/alexvictorne/voldepass/internal/domain"
)

// JWTIssuer выдаёт и проверяет access-токены. Реализуется internal/server/auth.JWTManager.
type JWTIssuer interface {
	Issue(userID string) (string, error)
	Parse(tokenStr string) (userID string, err error)
}

// ChallengeIssuer выдаёт и гасит одноразовые serverNonce. Реализуется internal/server/auth.ChallengeStore.
type ChallengeIssuer interface {
	Issue(login string) (nonce string, err error)
	Consume(login string) (string, error)
}

// RefreshIssuer выдаёт и ротирует refresh-токены. Реализуется internal/server/auth.RefreshTokenService.
type RefreshIssuer interface {
	Issue(ctx context.Context, userID string) (token string, err error)
	Rotate(ctx context.Context, oldToken string) (newToken string, userID string, err error)
	Revoke(ctx context.Context, userID string) error
}

// AuthTokens — пара токенов, выдаваемых после успешной аутентификации.
type AuthTokens struct {
	AccessToken  string
	RefreshToken string
}

// AuthService реализует регистрацию и challenge-response аутентификацию.
type AuthService struct {
	users      UserRepository
	challenges ChallengeIssuer
	jwt        JWTIssuer
	refresh    RefreshIssuer
	attempts   LoginAttemptTracker
}

// NewAuthService создаёт сервис аутентификации поверх портов-зависимостей.
func NewAuthService(
	users UserRepository,
	challenges ChallengeIssuer,
	jwt JWTIssuer,
	refresh RefreshIssuer,
	attempts LoginAttemptTracker,
) *AuthService {
	return &AuthService{
		users:      users,
		challenges: challenges,
		jwt:        jwt,
		refresh:    refresh,
		attempts:   attempts,
	}
}

// Register создаёт нового пользователя с криптографическим профилем.
// authVerifier — authKey, выведенный клиентом из мастер-пароля (используется для challenge-response).
func (s *AuthService) Register(ctx context.Context, login string, authVerifier []byte, profile domain.Profile) (domain.User, error) {
	u := domain.User{
		ID:           newID(),
		Login:        login,
		AuthVerifier: authVerifier,
		CreatedAt:    time.Now().UTC(),
	}
	profile.UserID = u.ID

	if err := s.users.Create(ctx, u, profile); err != nil {
		return domain.User{}, fmt.Errorf("register user: %w", err)
	}
	return u, nil
}

// Challenge выдаёт serverNonce и криптографический профиль пользователя для входа.
func (s *AuthService) Challenge(ctx context.Context, login string) (nonce string, profile domain.Profile, err error) {
	u, err := s.users.GetByLogin(ctx, login)
	if err != nil {
		return "", domain.Profile{}, fmt.Errorf("challenge: %w", err)
	}

	profile, err = s.users.GetProfile(ctx, u.ID)
	if err != nil {
		return "", domain.Profile{}, fmt.Errorf("challenge: get profile: %w", err)
	}

	nonce, err = s.challenges.Issue(login)
	if err != nil {
		return "", domain.Profile{}, fmt.Errorf("challenge: issue nonce: %w", err)
	}
	return nonce, profile, nil
}

// Login проверяет authMsg против погашенного challenge и выдаёт пару токенов.
// Учитывает rate-limit: при превышении лимита попыток возвращает ErrRateLimited.
func (s *AuthService) Login(ctx context.Context, login string, authMsg []byte) (AuthTokens, error) {
	allowed, err := s.attempts.Allowed(ctx, login)
	if err != nil {
		return AuthTokens{}, fmt.Errorf("login: check rate limit: %w", err)
	}
	if !allowed {
		return AuthTokens{}, domain.ErrRateLimited
	}

	nonce, err := s.challenges.Consume(login)
	if err != nil {
		_ = s.attempts.Inc(ctx, login)
		return AuthTokens{}, fmt.Errorf("login: %w", domain.ErrUnauthorized)
	}

	u, err := s.users.GetByLogin(ctx, login)
	if err != nil {
		_ = s.attempts.Inc(ctx, login)
		return AuthTokens{}, fmt.Errorf("login: %w", domain.ErrUnauthorized)
	}

	if !verifyAuthMessage(u.AuthVerifier, []byte(nonce), authMsg) {
		_ = s.attempts.Inc(ctx, login)
		return AuthTokens{}, domain.ErrUnauthorized
	}

	_ = s.attempts.Reset(ctx, login)

	access, err := s.jwt.Issue(u.ID)
	if err != nil {
		return AuthTokens{}, fmt.Errorf("login: issue access token: %w", err)
	}
	refresh, err := s.refresh.Issue(ctx, u.ID)
	if err != nil {
		return AuthTokens{}, fmt.Errorf("login: issue refresh token: %w", err)
	}
	return AuthTokens{AccessToken: access, RefreshToken: refresh}, nil
}

// Refresh ротирует refresh-токен и выдаёт новую пару токенов.
func (s *AuthService) Refresh(ctx context.Context, refreshToken string) (AuthTokens, error) {
	newRefresh, userID, err := s.refresh.Rotate(ctx, refreshToken)
	if err != nil {
		if errors.Is(err, domain.ErrUnauthorized) {
			return AuthTokens{}, domain.ErrUnauthorized
		}
		return AuthTokens{}, fmt.Errorf("refresh: %w", err)
	}

	access, err := s.jwt.Issue(userID)
	if err != nil {
		return AuthTokens{}, fmt.Errorf("refresh: issue access token: %w", err)
	}
	return AuthTokens{AccessToken: access, RefreshToken: newRefresh}, nil
}

// verifyAuthMessage проверяет authMsg = HMAC-SHA256(authKeyVerifier, serverNonce) в
// constant-time (hmac.Equal), чтобы исключить timing-атаки. authKeyVerifier — authKey,
// сохранённый сервером при регистрации; сам authKey никогда не передаётся по сети.
//
// HMAC пересчитывается здесь, а не через internal/client/crypto.AuthMessage — сервер
// не должен зависеть от пакета клиента (гексагональная архитектура: клиент и сервер
// независимы, общий протокол не должен требовать общего кода поверх контракта API).
func verifyAuthMessage(authKeyVerifier, serverNonce, authMsg []byte) bool {
	mac := hmac.New(sha256.New, authKeyVerifier)
	mac.Write(serverNonce)
	expected := mac.Sum(nil)
	return hmac.Equal(expected, authMsg)
}
