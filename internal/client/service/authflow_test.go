package service_test

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	clientservice "github.com/alexvictorne/voldepass/internal/client/service"
	"github.com/alexvictorne/voldepass/internal/client/storage"
	"github.com/alexvictorne/voldepass/internal/client/transport"
	serverauth "github.com/alexvictorne/voldepass/internal/server/auth"
	"github.com/alexvictorne/voldepass/internal/server/rest"
	"github.com/alexvictorne/voldepass/internal/server/service"
	"github.com/alexvictorne/voldepass/internal/server/storage/inmem"
)

// newLiveServer поднимает полноценный REST-сервер поверх in-memory зависимостей.
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
		rest.NewAuthHandlers(authSvc),
		rest.NewVaultHandlers(vaultSvc),
		rest.NewSyncHandlers(syncSvc),
		jwt,
	)
	return httptest.NewServer(router)
}

func newTransport(t *testing.T, srv *httptest.Server) *transport.Client {
	t.Helper()
	c, err := transport.New(transport.Options{BaseURL: srv.URL, MaxRetries: 1})
	require.NoError(t, err)
	return c
}

func TestAuthFlow_RegisterThenLogin(t *testing.T) {
	srv := newLiveServer(t)
	defer srv.Close()
	ctx := context.Background()

	tr := newTransport(t, srv)
	store := storage.NewStore()
	flow := clientservice.NewAuthFlow(tr, store)

	registerKey, err := flow.Register(ctx, "alice", "master-password")
	require.NoError(t, err)
	assert.Len(t, registerKey, 32)

	// Логинимся отдельным транспортом/хранилищем — как будто со второго устройства.
	tr2 := newTransport(t, srv)
	store2 := storage.NewStore()
	flow2 := clientservice.NewAuthFlow(tr2, store2)

	loginKey, err := flow2.Login(ctx, "alice", "master-password")
	require.NoError(t, err)

	// dataKey, развёрнутый при login на "другом устройстве", должен совпадать
	// с исходным dataKey, сгенерированным при регистрации.
	assert.Equal(t, registerKey, loginKey)

	access, refresh := store2.Tokens()
	assert.NotEmpty(t, access)
	assert.NotEmpty(t, refresh)
}

func TestAuthFlow_Login_WrongPassword(t *testing.T) {
	srv := newLiveServer(t)
	defer srv.Close()
	ctx := context.Background()

	tr := newTransport(t, srv)
	store := storage.NewStore()
	flow := clientservice.NewAuthFlow(tr, store)
	_, err := flow.Register(ctx, "alice", "correct-password")
	require.NoError(t, err)

	tr2 := newTransport(t, srv)
	flow2 := clientservice.NewAuthFlow(tr2, storage.NewStore())
	_, err = flow2.Login(ctx, "alice", "wrong-password")
	assert.Error(t, err)
}

func TestAuthFlow_Register_StoresProfileLocally(t *testing.T) {
	srv := newLiveServer(t)
	defer srv.Close()
	ctx := context.Background()

	tr := newTransport(t, srv)
	store := storage.NewStore()
	flow := clientservice.NewAuthFlow(tr, store)
	_, err := flow.Register(ctx, "alice", "master-password")
	require.NoError(t, err)

	snap := store.Snapshot()
	assert.NotEmpty(t, snap.KdfSalt)
	assert.NotEmpty(t, snap.WrappedDataKey)
}
