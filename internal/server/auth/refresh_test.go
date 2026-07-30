package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/alexvictorne/voldepass/internal/domain"
	"github.com/alexvictorne/voldepass/internal/server/auth"
	"github.com/alexvictorne/voldepass/internal/server/storage/inmem"
)

func newRefreshService(ttl time.Duration) *auth.RefreshTokenService {
	store := inmem.NewRefreshTokenStore()
	return auth.NewRefreshTokenService(store, ttl)
}

func TestRefreshToken_IssueAndRotate(t *testing.T) {
	svc := newRefreshService(time.Hour)
	ctx := context.Background()

	token, err := svc.Issue(ctx, "u1")
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	newToken, uid, err := svc.Rotate(ctx, token)
	require.NoError(t, err)
	assert.Equal(t, "u1", uid)
	assert.NotEmpty(t, newToken)
	assert.NotEqual(t, token, newToken)
}

func TestRefreshToken_RotateInvalidatesOld(t *testing.T) {
	svc := newRefreshService(time.Hour)
	ctx := context.Background()

	token, _ := svc.Issue(ctx, "u1")
	svc.Rotate(ctx, token)

	// Повторная ротация того же (уже ротированного) токена → детект кражи.
	_, _, err := svc.Rotate(ctx, token)
	assert.ErrorIs(t, err, domain.ErrUnauthorized, "reuse of rotated token must trigger theft detection")
}

func TestRefreshToken_TheftDetectionRevokesAll(t *testing.T) {
	svc := newRefreshService(time.Hour)
	ctx := context.Background()

	// Выдаём два токена одному пользователю.
	token1, _ := svc.Issue(ctx, "u1")
	token2, _ := svc.Issue(ctx, "u1")

	// Ротируем первый → легитимная ротация.
	_, _, err := svc.Rotate(ctx, token1)
	require.NoError(t, err)

	// Атакующий переиспользует уже ротированный token1 → все токены должны быть отозваны.
	_, _, err = svc.Rotate(ctx, token1)
	assert.ErrorIs(t, err, domain.ErrUnauthorized)

	// token2 тоже должен быть отозван.
	_, _, err = svc.Rotate(ctx, token2)
	assert.ErrorIs(t, err, domain.ErrUnauthorized)
}

func TestRefreshToken_Expired(t *testing.T) {
	svc := newRefreshService(-time.Second)
	ctx := context.Background()

	token, _ := svc.Issue(ctx, "u1")
	_, _, err := svc.Rotate(ctx, token)
	assert.ErrorIs(t, err, domain.ErrUnauthorized, "expired token must be rejected")
}

func TestRefreshToken_UnknownToken(t *testing.T) {
	svc := newRefreshService(time.Hour)
	ctx := context.Background()

	_, _, err := svc.Rotate(ctx, "unknown-token")
	assert.Error(t, err)
}

func TestRefreshToken_Revoke(t *testing.T) {
	svc := newRefreshService(time.Hour)
	ctx := context.Background()

	token, _ := svc.Issue(ctx, "u1")
	require.NoError(t, svc.Revoke(ctx, "u1"))

	_, _, err := svc.Rotate(ctx, token)
	assert.ErrorIs(t, err, domain.ErrUnauthorized, "revoked token must be rejected")
}

func TestRefreshToken_UniqueTokens(t *testing.T) {
	svc := newRefreshService(time.Hour)
	ctx := context.Background()

	t1, _ := svc.Issue(ctx, "u1")
	t2, _ := svc.Issue(ctx, "u1")
	assert.NotEqual(t, t1, t2)
}
