package transport_test

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/alexvictorne/voldepass/internal/client/crypto"
	"github.com/alexvictorne/voldepass/internal/client/transport"
	"github.com/alexvictorne/voldepass/internal/domain"
	serverauth "github.com/alexvictorne/voldepass/internal/server/auth"
	"github.com/alexvictorne/voldepass/internal/server/rest"
	"github.com/alexvictorne/voldepass/internal/server/service"
	"github.com/alexvictorne/voldepass/internal/server/storage/inmem"
)

var fastParams = domain.KdfParams{Time: 1, Memory: 16 * 1024, Threads: 1, KeyLen: 32}

// newLiveServer поднимает полноценный REST-сервер поверх in-memory зависимостей
// для сквозных тестов клиентского транспорта.
func newLiveServer(t *testing.T) *httptest.Server {
	t.Helper()

	users := inmem.NewUserRepository()
	records := inmem.NewRecordRepository()
	idempotency := inmem.NewIdempotencyStore()

	jwt := serverauth.NewJWTManager([]byte("test-secret-32-bytes-long-enough"), 15*time.Minute)
	challenges := serverauth.NewChallengeStore(time.Minute)
	refresh := serverauth.NewRefreshTokenService(inmem.NewRefreshTokenStore(), time.Hour)
	attempts := inmem.NewLoginAttemptTracker(5, time.Minute)

	authSvc := service.NewAuthService(users, challenges, jwt, refresh, attempts)
	vaultSvc := service.NewVaultService(records)
	syncSvc := service.NewSyncService(records, idempotency)

	router := rest.NewRouter(
		rest.NewAuthHandlers(authSvc, zerolog.Nop()),
		rest.NewVaultHandlers(vaultSvc, zerolog.Nop()),
		rest.NewSyncHandlers(syncSvc, zerolog.Nop()),
		jwt,
		nil,
		zerolog.Nop(),
		attempts,
	)
	return httptest.NewServer(router)
}

// registerAndLoginClient регистрирует и логинит пользователя через реальный Client.
func registerAndLoginClient(t *testing.T, c *transport.Client, login, password string) {
	t.Helper()
	ctx := context.Background()

	salt, err := crypto.GenerateSalt()
	require.NoError(t, err)
	authKey, encKey := crypto.DeriveKeys(password, salt, fastParams)

	dataKey, err := crypto.GenerateDataKey()
	require.NoError(t, err)
	wrapped, err := crypto.WrapKey(encKey, dataKey)
	require.NoError(t, err)

	err = c.Register(ctx, login, authKey, domain.Profile{
		KdfSalt:        salt,
		KdfParams:      fastParams,
		WrappedDataKey: wrapped,
	})
	require.NoError(t, err)

	chall, err := c.Challenge(ctx, login)
	require.NoError(t, err)

	authMsg := crypto.AuthMessage(authKey, []byte(chall.ServerNonce))
	require.NoError(t, c.Login(ctx, login, authMsg))
}

func TestClient_RecordCRUD_LiveServer(t *testing.T) {
	srv := newLiveServer(t)
	defer srv.Close()

	c, err := transport.New(transport.Options{BaseURL: srv.URL, MaxRetries: 1})
	require.NoError(t, err)
	registerAndLoginClient(t, c, "alice", "master-password")

	ctx := context.Background()
	created, err := c.CreateRecord(ctx, domain.RecordDTO{
		Type:       domain.DataTypeText,
		Ciphertext: []byte("secret"),
		Nonce:      []byte("nonce1234567"),
	})
	require.NoError(t, err)
	assert.NotEmpty(t, created.ID)

	got, err := c.GetRecord(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, created.ID, got.ID)

	list, err := c.ListRecords(ctx)
	require.NoError(t, err)
	assert.Len(t, list, 1)

	updated := got
	updated.Ciphertext = []byte("updated-secret")
	updated.BaseVersion = got.Version
	saved, err := c.UpdateRecord(ctx, updated)
	require.NoError(t, err)
	assert.Equal(t, []byte("updated-secret"), saved.Ciphertext)

	require.NoError(t, c.DeleteRecord(ctx, created.ID))
}

func TestClient_SyncPushAndPull_LiveServer(t *testing.T) {
	srv := newLiveServer(t)
	defer srv.Close()

	c, err := transport.New(transport.Options{BaseURL: srv.URL, MaxRetries: 1})
	require.NoError(t, err)
	registerAndLoginClient(t, c, "alice", "master-password")

	ctx := context.Background()
	pushResp, err := c.Push(ctx, "idem-key-1", domain.SyncPushRequest{
		Records: []domain.RecordDTO{
			{ID: "r1", Type: domain.DataTypeText, Ciphertext: []byte("ct"), Nonce: []byte("n1"), BaseVersion: 0},
		},
	})
	require.NoError(t, err)
	require.Len(t, pushResp.Results, 1)
	assert.Equal(t, domain.PushStatusApplied, pushResp.Results[0].Status)

	pullResp, err := c.Pull(ctx, 0)
	require.NoError(t, err)
	require.Len(t, pullResp.Records, 1)
	assert.Equal(t, "r1", pullResp.Records[0].ID)
}

func TestClient_AutoRefreshOn401(t *testing.T) {
	srv := newLiveServer(t)
	defer srv.Close()

	c, err := transport.New(transport.Options{BaseURL: srv.URL, MaxRetries: 1})
	require.NoError(t, err)
	registerAndLoginClient(t, c, "alice", "master-password")

	// Портим access-токен, оставляя валидный refresh-токен — эмулирует истёкший access.
	_, refresh := c.Tokens()
	c.SetTokens("expired-or-garbage-access-token", refresh)

	ctx := context.Background()
	list, err := c.ListRecords(ctx)
	require.NoError(t, err, "must transparently refresh and retry on 401")
	assert.Empty(t, list)

	newAccess, _ := c.Tokens()
	assert.NotEqual(t, "expired-or-garbage-access-token", newAccess, "access token must have been refreshed")
}

func TestClient_AutoRefresh_FailsWhenRefreshInvalid(t *testing.T) {
	srv := newLiveServer(t)
	defer srv.Close()

	c, err := transport.New(transport.Options{BaseURL: srv.URL, MaxRetries: 1})
	require.NoError(t, err)
	registerAndLoginClient(t, c, "alice", "master-password")

	c.SetTokens("garbage-access", "garbage-refresh")

	_, err = c.ListRecords(context.Background())
	assert.ErrorIs(t, err, domain.ErrUnauthorized)
}
