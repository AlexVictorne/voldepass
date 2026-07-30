package service_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/alexvictorne/voldepass/internal/client/crypto"
	"github.com/alexvictorne/voldepass/internal/domain"
	serverauth "github.com/alexvictorne/voldepass/internal/server/auth"
	"github.com/alexvictorne/voldepass/internal/server/service"
	"github.com/alexvictorne/voldepass/internal/server/storage/inmem"
)

var fastParams = domain.KdfParams{Time: 1, Memory: 16 * 1024, Threads: 1, KeyLen: 32}

// newAuthService собирает AuthService из полнофункциональных in-memory зависимостей.
func newAuthService(t *testing.T) *service.AuthService {
	t.Helper()
	users := inmem.NewUserRepository()
	challenges := serverauth.NewChallengeStore(time.Minute)
	jwt := serverauth.NewJWTManager([]byte("test-secret-32-bytes-long-enough"), 15*time.Minute)
	refresh := serverauth.NewRefreshTokenService(inmem.NewRefreshTokenStore(), time.Hour)
	attempts := inmem.NewLoginAttemptTracker(5, time.Minute)
	return service.NewAuthService(users, challenges, jwt, refresh, attempts)
}

// registerTestUser регистрирует пользователя с реальным крипто-профилем и возвращает authKey.
func registerTestUser(t *testing.T, svc *service.AuthService, login, password string) []byte {
	t.Helper()
	ctx := context.Background()

	salt, err := crypto.GenerateSalt()
	require.NoError(t, err)
	authKey, encKey := crypto.DeriveKeys(password, salt, fastParams)

	dataKey, err := crypto.GenerateDataKey()
	require.NoError(t, err)
	wrapped, err := crypto.WrapKey(encKey, dataKey)
	require.NoError(t, err)

	profile := domain.Profile{
		KdfSalt:        salt,
		KdfParams:      fastParams,
		WrappedDataKey: wrapped,
		ProfileVersion: 1,
	}

	_, err = svc.Register(ctx, login, authKey, profile)
	require.NoError(t, err)
	return authKey
}

func TestAuthService_RegisterAndLogin(t *testing.T) {
	svc := newAuthService(t)
	ctx := context.Background()
	authKey := registerTestUser(t, svc, "alice", "master-password")

	nonce, profile, err := svc.Challenge(ctx, "alice")
	require.NoError(t, err)
	assert.NotEmpty(t, profile.WrappedDataKey)

	authMsg := crypto.AuthMessage(authKey, []byte(nonce))
	tokens, err := svc.Login(ctx, "alice", authMsg)
	require.NoError(t, err)
	assert.NotEmpty(t, tokens.AccessToken)
	assert.NotEmpty(t, tokens.RefreshToken)
}

func TestAuthService_RegisterDuplicateLogin(t *testing.T) {
	svc := newAuthService(t)
	registerTestUser(t, svc, "alice", "pw1")

	_, err := svc.Register(context.Background(), "alice", []byte("x"), domain.Profile{})
	assert.ErrorIs(t, err, domain.ErrAlreadyExists)
}

func TestAuthService_Login_WrongAuthMsg(t *testing.T) {
	svc := newAuthService(t)
	ctx := context.Background()
	registerTestUser(t, svc, "alice", "correct-password")

	nonce, _, err := svc.Challenge(ctx, "alice")
	require.NoError(t, err)

	wrongKey, _ := crypto.DeriveKeys("wrong-password", []byte("different-salt-of-32-bytes-long"), fastParams)
	authMsg := crypto.AuthMessage(wrongKey, []byte(nonce))

	_, err = svc.Login(ctx, "alice", authMsg)
	assert.ErrorIs(t, err, domain.ErrUnauthorized)
}

func TestAuthService_Login_ReplayedNonce(t *testing.T) {
	svc := newAuthService(t)
	ctx := context.Background()
	authKey := registerTestUser(t, svc, "alice", "master-password")

	nonce, _, err := svc.Challenge(ctx, "alice")
	require.NoError(t, err)
	authMsg := crypto.AuthMessage(authKey, []byte(nonce))

	_, err = svc.Login(ctx, "alice", authMsg)
	require.NoError(t, err)

	// Повторная попытка входа с тем же authMsg (challenge уже погашен) → отказ.
	_, err = svc.Login(ctx, "alice", authMsg)
	assert.ErrorIs(t, err, domain.ErrUnauthorized)
}

func TestAuthService_Login_UnknownUser(t *testing.T) {
	svc := newAuthService(t)
	ctx := context.Background()

	_, _, err := svc.Challenge(ctx, "ghost")
	assert.Error(t, err)
}

func TestAuthService_Login_RateLimited(t *testing.T) {
	svc := newAuthService(t)
	ctx := context.Background()
	registerTestUser(t, svc, "alice", "correct-password")

	wrongKey, _ := crypto.DeriveKeys("wrong", []byte("salt-that-is-32-bytes-long-here!"), fastParams)

	// Лимит трекера — 5 попыток.
	for i := 0; i < 5; i++ {
		nonce, _, err := svc.Challenge(ctx, "alice")
		require.NoError(t, err)
		authMsg := crypto.AuthMessage(wrongKey, []byte(nonce))
		_, err = svc.Login(ctx, "alice", authMsg)
		assert.ErrorIs(t, err, domain.ErrUnauthorized)
	}

	// 6-я попытка — заблокирована лимитом, даже challenge не запросить смысла нет.
	_, err := svc.Login(ctx, "alice", []byte("anything"))
	assert.ErrorIs(t, err, domain.ErrRateLimited)
}

func TestAuthService_Refresh(t *testing.T) {
	svc := newAuthService(t)
	ctx := context.Background()
	authKey := registerTestUser(t, svc, "alice", "master-password")

	nonce, _, err := svc.Challenge(ctx, "alice")
	require.NoError(t, err)
	authMsg := crypto.AuthMessage(authKey, []byte(nonce))
	tokens, err := svc.Login(ctx, "alice", authMsg)
	require.NoError(t, err)

	newTokens, err := svc.Refresh(ctx, tokens.RefreshToken)
	require.NoError(t, err)
	assert.NotEmpty(t, newTokens.AccessToken)
	assert.NotEqual(t, tokens.RefreshToken, newTokens.RefreshToken)

	// Старый refresh-токен больше не годится.
	_, err = svc.Refresh(ctx, tokens.RefreshToken)
	assert.ErrorIs(t, err, domain.ErrUnauthorized)
}

func TestAuthService_Refresh_UnknownToken(t *testing.T) {
	svc := newAuthService(t)

	// Токен, которого никогда не существовало (ErrNotFound на уровне хранилища),
	// должен транслироваться как ErrUnauthorized — это ошибка аутентификации,
	// а не "ресурс не найден" (иначе REST-слой отдал бы 404 вместо 401).
	_, err := svc.Refresh(context.Background(), "never-issued-token")
	assert.ErrorIs(t, err, domain.ErrUnauthorized)
	assert.NotErrorIs(t, err, domain.ErrNotFound)
}
