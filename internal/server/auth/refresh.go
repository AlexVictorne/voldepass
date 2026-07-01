package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	"github.com/alexvictorne/voldepass/internal/domain"
	"github.com/alexvictorne/voldepass/internal/server/service"
)

// RefreshTokenService управляет refresh-токенами: выдача, ротация, revoke.
//
// Схема детекта кражи: при ротации старый токен инвалидируется.
// Если атакующий использует уже ротированный токен — это означает, что
// легитимный пользователь уже получил новый токен, либо старый был похищен.
// В обоих случаях отзываются все токены пользователя (RevokeAll).
type RefreshTokenService struct {
	store service.RefreshTokenStore
	ttl   time.Duration
}

// NewRefreshTokenService создаёт сервис с заданным хранилищем и TTL токена.
func NewRefreshTokenService(store service.RefreshTokenStore, ttl time.Duration) *RefreshTokenService {
	return &RefreshTokenService{store: store, ttl: ttl}
}

// Issue генерирует новый opaque refresh-токен, сохраняет его хеш и возвращает сам токен.
func (s *RefreshTokenService) Issue(ctx context.Context, userID string) (token string, err error) {
	raw := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", fmt.Errorf("generate refresh token: %w", err)
	}
	token = hex.EncodeToString(raw)
	hash := hashToken(token)

	if err := s.store.Save(ctx, userID, hash, time.Now().Add(s.ttl)); err != nil {
		return "", fmt.Errorf("save refresh token: %w", err)
	}
	return token, nil
}

// Rotate инвалидирует старый токен и выдаёт новый.
// Если oldToken уже был использован (revoked) — детект кражи: отзываются все токены.
func (s *RefreshTokenService) Rotate(ctx context.Context, oldToken string) (newToken string, userID string, err error) {
	oldHash := hashToken(oldToken)

	uid, revoked, expiresAt, err := s.store.Get(ctx, oldHash)
	if err != nil {
		return "", "", fmt.Errorf("get refresh token: %w", err)
	}

	if revoked {
		// Детект кражи: токен уже был ротирован, отзываем всё.
		_ = s.store.RevokeAll(ctx, uid)
		return "", "", domain.ErrUnauthorized
	}

	if time.Now().After(expiresAt) {
		return "", "", domain.ErrUnauthorized
	}

	raw := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", "", fmt.Errorf("generate new refresh token: %w", err)
	}
	newToken = hex.EncodeToString(raw)
	newHash := hashToken(newToken)

	if err := s.store.Rotate(ctx, oldHash, newHash, uid, time.Now().Add(s.ttl)); err != nil {
		return "", "", fmt.Errorf("rotate refresh token: %w", err)
	}
	return newToken, uid, nil
}

// Revoke отзывает все refresh-токены пользователя (при logout).
func (s *RefreshTokenService) Revoke(ctx context.Context, userID string) error {
	return s.store.RevokeAll(ctx, userID)
}

// hashToken возвращает SHA-256 hex-хеш токена для хранения в БД.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
