package service_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	clientservice "github.com/alexvictorne/voldepass/internal/client/service"
	"github.com/alexvictorne/voldepass/internal/client/storage"
	"github.com/alexvictorne/voldepass/internal/domain"
	"github.com/alexvictorne/voldepass/internal/server/service"
	"github.com/alexvictorne/voldepass/internal/server/storage/inmem"
)

// serverSyncAdapter адаптирует server-side service.SyncService к клиентскому
// syncTransport-интерфейсу без HTTP — для быстрых функциональных тестов Syncer.
type serverSyncAdapter struct {
	svc     *service.SyncService
	ownerID string
}

func (a *serverSyncAdapter) Pull(ctx context.Context, sinceVersion int64) (domain.SyncPullResponse, error) {
	return a.svc.Pull(ctx, a.ownerID, sinceVersion)
}

func (a *serverSyncAdapter) Push(ctx context.Context, idempotencyKey string, req domain.SyncPushRequest) (domain.SyncPushResponse, error) {
	return a.svc.Push(ctx, a.ownerID, idempotencyKey, req)
}

func newSyncSetup(ownerID string) (*serverSyncAdapter, *service.SyncService) {
	records := inmem.NewRecordRepository()
	idempotency := inmem.NewIdempotencyStore()
	svc := service.NewSyncService(records, idempotency)
	return &serverSyncAdapter{svc: svc, ownerID: ownerID}, svc
}

func TestSyncer_PushNewRecords(t *testing.T) {
	adapter, _ := newSyncSetup("u1")
	store := storage.NewStore()
	dataKey := newTestDataKey(t)
	vault := clientservice.NewVaultManager(store, dataKey)

	vault.Create(domain.DataTypeText, "", domain.TextPayload{Content: "hello"})

	syncer := clientservice.NewSyncer(adapter, store)
	conflicts, err := syncer.Sync(context.Background())
	require.NoError(t, err)
	assert.Empty(t, conflicts)

	dirty := store.ListDirty()
	assert.Empty(t, dirty, "record must be marked as synced after push")
}

func TestSyncer_PullFastForward(t *testing.T) {
	adapter, svc := newSyncSetup("u1")
	ctx := context.Background()

	// Симулируем изменение "с другого устройства": напрямую пушим в сервис.
	_, err := svc.Push(ctx, "u1", "other-device-key", domain.SyncPushRequest{
		Records: []domain.RecordDTO{
			{ID: "r1", Type: domain.DataTypeText, Ciphertext: []byte("ct"), Nonce: []byte("n"), BaseVersion: 0},
		},
	})
	require.NoError(t, err)

	store := storage.NewStore()
	syncer := clientservice.NewSyncer(adapter, store)
	conflicts, err := syncer.Sync(ctx)
	require.NoError(t, err)
	assert.Empty(t, conflicts)

	_, ok := store.GetRecord("r1")
	assert.True(t, ok, "record from another device must appear after pull")
}

func TestSyncer_ConflictCreatesCopyAndAcceptsServer(t *testing.T) {
	adapter, svc := newSyncSetup("u1")
	ctx := context.Background()
	dataKey := newTestDataKey(t)

	store := storage.NewStore()
	vault := clientservice.NewVaultManager(store, dataKey)
	dto, err := vault.Create(domain.DataTypeText, "", domain.TextPayload{Content: "local-v1"})
	require.NoError(t, err)

	syncer := clientservice.NewSyncer(adapter, store)
	_, err = syncer.Sync(ctx)
	require.NoError(t, err)

	// Локально меняем запись (снова Dirty), не синхронизируя.
	_, err = vault.Update(dto.ID, "", domain.TextPayload{Content: "local-v2"})
	require.NoError(t, err)

	// Одновременно "другое устройство" тоже меняет ту же запись на сервере.
	current, ok := store.GetRecord(dto.ID)
	require.True(t, ok)
	_, err = svc.Push(ctx, "u1", "other-device-key", domain.SyncPushRequest{
		Records: []domain.RecordDTO{
			{ID: dto.ID, Type: domain.DataTypeText, Ciphertext: []byte("server-ct"), Nonce: []byte("n"), BaseVersion: current.Version},
		},
	})
	require.NoError(t, err)

	conflicts, err := syncer.Sync(ctx)
	require.NoError(t, err)
	assert.Empty(t, conflicts, "conflict must be resolved within maxIterations")

	// Канонической должна остаться серверная версия.
	final, ok := store.GetRecord(dto.ID)
	require.True(t, ok)
	assert.Equal(t, []byte("server-ct"), final.Ciphertext)

	// Локальная dirty-версия должна была сохраниться как отдельная conflict-копия.
	all := store.ListRecords()
	assert.Len(t, all, 2, "expected original (server-won) record plus one conflict-copy")
}

func TestSyncer_DeleteTombstone(t *testing.T) {
	adapter, _ := newSyncSetup("u1")
	ctx := context.Background()
	dataKey := newTestDataKey(t)

	store := storage.NewStore()
	vault := clientservice.NewVaultManager(store, dataKey)
	dto, err := vault.Create(domain.DataTypeText, "", domain.TextPayload{Content: "x"})
	require.NoError(t, err)

	syncer := clientservice.NewSyncer(adapter, store)
	_, err = syncer.Sync(ctx)
	require.NoError(t, err)

	require.NoError(t, vault.Delete(dto.ID))
	_, err = syncer.Sync(ctx)
	require.NoError(t, err)

	final, ok := store.GetRecord(dto.ID)
	require.True(t, ok)
	assert.True(t, final.IsDeleted)
	assert.False(t, final.Dirty)
}

func TestSyncer_Chunking(t *testing.T) {
	adapter, _ := newSyncSetup("u1")
	ctx := context.Background()
	dataKey := newTestDataKey(t)

	store := storage.NewStore()
	vault := clientservice.NewVaultManager(store, dataKey)
	for i := 0; i < 5; i++ {
		_, err := vault.Create(domain.DataTypeText, "", domain.TextPayload{Content: "x"})
		require.NoError(t, err)
	}

	syncer := clientservice.NewSyncer(adapter, store).WithChunkSize(2)
	conflicts, err := syncer.Sync(ctx)
	require.NoError(t, err)
	assert.Empty(t, conflicts)
	assert.Empty(t, store.ListDirty(), "all chunks must be pushed")
}

func TestSyncer_IdempotentReplay_PendingBatchSurvivesRestart(t *testing.T) {
	adapter, _ := newSyncSetup("u1")
	ctx := context.Background()
	dataKey := newTestDataKey(t)

	store := storage.NewStore()
	vault := clientservice.NewVaultManager(store, dataKey)
	dto, err := vault.Create(domain.DataTypeText, "", domain.TextPayload{Content: "x"})
	require.NoError(t, err)

	// Симулируем краш после регистрации pending-батча, но до его завершения:
	// добавляем pending batch вручную (как будто предыдущий процесс успел это сделать).
	store.AddPendingPush(storage.PendingBatch{IdempotencyKey: "crash-key-1", RecordIDs: []string{dto.ID}})

	syncer := clientservice.NewSyncer(adapter, store)
	conflicts, err := syncer.Sync(ctx)
	require.NoError(t, err)
	assert.Empty(t, conflicts)
	assert.Empty(t, store.PendingPushes(), "pending batch must be cleared after replay")
	assert.Empty(t, store.ListDirty())
}

func TestSyncer_NoOpWhenNothingDirty(t *testing.T) {
	adapter, _ := newSyncSetup("u1")
	store := storage.NewStore()
	syncer := clientservice.NewSyncer(adapter, store)

	conflicts, err := syncer.Sync(context.Background())
	require.NoError(t, err)
	assert.Empty(t, conflicts)
}
