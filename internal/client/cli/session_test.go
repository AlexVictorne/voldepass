package cli

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	clientcfg "github.com/alexvictorne/voldepass/internal/client/config"
	"github.com/alexvictorne/voldepass/internal/domain"
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
		nil,
		zerolog.Nop(),
	)
	return httptest.NewServer(router)
}

func testConfig(srv *httptest.Server, storageFile string) clientcfg.Config {
	cfg := clientcfg.Default()
	cfg.ServerURL = srv.URL
	cfg.StorageFile = storageFile
	cfg.MaxRetries = 1
	return cfg
}

func TestOpenNewSession_RegistersAndReturnsWorkingBundle(t *testing.T) {
	srv := newLiveServer(t)
	defer srv.Close()
	cfg := testConfig(srv, filepath.Join(t.TempDir(), "storage.vp"))

	b, err := openNewSession(context.Background(), cfg, "alice", "master-password")
	require.NoError(t, err)
	require.NotNil(t, b.vault)

	dto, err := b.vault.Create(domain.DataTypeText, "", domain.TextPayload{Content: "hello"})
	require.NoError(t, err)
	assert.NotEmpty(t, dto.ID)
}

func TestOpenSession_LoginAfterRegister(t *testing.T) {
	srv := newLiveServer(t)
	defer srv.Close()
	cfg := testConfig(srv, filepath.Join(t.TempDir(), "storage.vp"))
	ctx := context.Background()

	_, err := openNewSession(ctx, cfg, "alice", "master-password")
	require.NoError(t, err)

	// Логинимся отдельным файлом хранилища — как "другое устройство".
	cfg2 := testConfig(srv, filepath.Join(t.TempDir(), "storage2.vp"))
	b, err := openSession(ctx, cfg2, "alice", "master-password")
	require.NoError(t, err)
	require.NotNil(t, b.vault)
}

func TestOpenSession_WrongPassword(t *testing.T) {
	srv := newLiveServer(t)
	defer srv.Close()
	cfg := testConfig(srv, filepath.Join(t.TempDir(), "storage.vp"))
	ctx := context.Background()

	_, err := openNewSession(ctx, cfg, "alice", "correct-password")
	require.NoError(t, err)

	_, err = openSession(ctx, cfg, "alice", "wrong-password")
	assert.Error(t, err)
}

func TestOpenSession_PersistsAndReloadsLocalData(t *testing.T) {
	srv := newLiveServer(t)
	defer srv.Close()
	storageFile := filepath.Join(t.TempDir(), "storage.vp")
	cfg := testConfig(srv, storageFile)
	ctx := context.Background()

	b, err := openNewSession(ctx, cfg, "alice", "master-password")
	require.NoError(t, err)
	dto, err := b.vault.Create(domain.DataTypeText, "note", domain.TextPayload{Content: "persisted"})
	require.NoError(t, err)
	require.NoError(t, b.session.Close(ctx))

	// Повторно логинимся с тем же файлом — локальные данные должны загрузиться.
	b2, err := openSession(ctx, cfg, "alice", "master-password")
	require.NoError(t, err)

	var payload domain.TextPayload
	meta, _, err := b2.vault.Get(dto.ID, &payload)
	require.NoError(t, err)
	assert.Equal(t, "note", meta)
	assert.Equal(t, "persisted", payload.Content)
}
