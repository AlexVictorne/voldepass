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

	_, err := vault.Create(domain.DataTypeText, "", domain.TextPayload{Content: "hello"})
	require.NoError(t, err)

	syncer := clientservice.NewSyncer(adapter, store)
	conflicts, err := syncer.Sync(context.Background())
	require.NoError(t, err)
	assert.Empty(t, conflicts)

	dirty := store.ListDirty()
	assert.Empty(t, dirty, "record must be marked as synced after push")
}

func TestSyncer_Sync_RecordsLastSyncAt(t *testing.T) {
	adapter, _ := newSyncSetup("u1")
	store := storage.NewStore()
	dataKey := newTestDataKey(t)
	vault := clientservice.NewVaultManager(store, dataKey)
	_, err := vault.Create(domain.DataTypeText, "", domain.TextPayload{Content: "hello"})
	require.NoError(t, err)

	assert.True(t, store.LastSyncAt().IsZero(), "must be zero before the first sync")

	syncer := clientservice.NewSyncer(adapter, store)
	_, err = syncer.Sync(context.Background())
	require.NoError(t, err)

	assert.False(t, store.LastSyncAt().IsZero(), "successful sync must record a timestamp")
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

// TestSyncer_Conflict_LocalWinsWhenNewer проверяет LWW в пользу локальной стороны:
// если локальное изменение сделано позже серверного (по времени), оно должно
// победить и быть отправлено на сервер, а не потеряться под серверной версией.
func TestSyncer_Conflict_LocalWinsWhenNewer(t *testing.T) {
	adapter, svc := newSyncSetup("u1")
	ctx := context.Background()
	dataKey := newTestDataKey(t)

	store := storage.NewStore()
	vault := clientservice.NewVaultManager(store, dataKey)
	dto, err := vault.Create(domain.DataTypeText, "", domain.TextPayload{Content: "v1"})
	require.NoError(t, err)

	syncer := clientservice.NewSyncer(adapter, store)
	_, err = syncer.Sync(ctx)
	require.NoError(t, err)

	// "Другое устройство" меняет запись на сервере ПЕРВЫМ (раньше нашего локального изменения).
	current, ok := store.GetRecord(dto.ID)
	require.True(t, ok)
	_, err = svc.Push(ctx, "u1", "other-device-key", domain.SyncPushRequest{
		Records: []domain.RecordDTO{
			{ID: dto.ID, Type: domain.DataTypeText, Ciphertext: []byte("stale-server-ct"), Nonce: []byte("n"), BaseVersion: current.Version},
		},
	})
	require.NoError(t, err)

	// Наше локальное изменение происходит ПОЗЖЕ серверного — должно победить.
	_, err = vault.Update(dto.ID, "", domain.TextPayload{Content: "newer-local"})
	require.NoError(t, err)
	localCiphertext, _ := store.GetRecord(dto.ID)

	conflicts, err := syncer.Sync(ctx)
	require.NoError(t, err)
	assert.Empty(t, conflicts, "local-wins record must be pushed successfully, not left in conflict")

	final, ok := store.GetRecord(dto.ID)
	require.True(t, ok)
	assert.Equal(t, localCiphertext.Ciphertext, final.Ciphertext, "newer local edit must win and be pushed as canonical")
	assert.False(t, final.Dirty, "the winning local record must be pushed, clearing Dirty")

	all := store.ListRecords()
	assert.Len(t, all, 1, "local-wins must not create a conflict-copy — nothing was lost")
}

// TestSyncer_Conflict_LocalDeleteWinsOverStaleServerUpdate проверяет delete-wins:
// локальное удаление должно победить серверное обновление безусловно, даже если
// серверное изменение по времени новее локального delete.
func TestSyncer_Conflict_LocalDeleteWinsOverStaleServerUpdate(t *testing.T) {
	adapter, svc := newSyncSetup("u1")
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

	// "Другое устройство" обновляет запись на сервере ПОСЛЕ нашего локального delete —
	// по времени сервер новее, но delete всё равно должен победить.
	current, ok := store.GetRecord(dto.ID)
	require.True(t, ok)
	_, err = svc.Push(ctx, "u1", "other-device-key", domain.SyncPushRequest{
		Records: []domain.RecordDTO{
			{ID: dto.ID, Type: domain.DataTypeText, Ciphertext: []byte("update-after-our-delete"), Nonce: []byte("n"), BaseVersion: current.Version},
		},
	})
	require.NoError(t, err)

	conflicts, err := syncer.Sync(ctx)
	require.NoError(t, err)
	assert.Empty(t, conflicts, "delete must be pushed successfully")

	final, ok := store.GetRecord(dto.ID)
	require.True(t, ok)
	assert.True(t, final.IsDeleted, "local delete must win over a newer server update")
	assert.False(t, final.Dirty)

	all := store.ListRecords()
	assert.Len(t, all, 2, "the losing server update must be preserved as a conflict-copy, not silently discarded")
}

// TestSyncer_Conflict_ServerDeleteWinsOverLocalUpdate проверяет delete-wins в обратную
// сторону: серверное удаление должно победить локальное обновление, а несинхронизированное
// локальное изменение — сохраниться conflict-копией, а не потеряться молча.
func TestSyncer_Conflict_ServerDeleteWinsOverLocalUpdate(t *testing.T) {
	adapter, svc := newSyncSetup("u1")
	ctx := context.Background()
	dataKey := newTestDataKey(t)

	store := storage.NewStore()
	vault := clientservice.NewVaultManager(store, dataKey)
	dto, err := vault.Create(domain.DataTypeText, "", domain.TextPayload{Content: "x"})
	require.NoError(t, err)

	syncer := clientservice.NewSyncer(adapter, store)
	_, err = syncer.Sync(ctx)
	require.NoError(t, err)

	// "Другое устройство" удаляет запись на сервере.
	current, ok := store.GetRecord(dto.ID)
	require.True(t, ok)
	_, err = svc.Push(ctx, "u1", "other-device-key", domain.SyncPushRequest{
		Records: []domain.RecordDTO{
			{ID: dto.ID, Type: domain.DataTypeText, BaseVersion: current.Version, IsDeleted: true},
		},
	})
	require.NoError(t, err)

	// Мы тем временем меняем запись локально, не зная об удалении.
	_, err = vault.Update(dto.ID, "", domain.TextPayload{Content: "local-update-after-remote-delete"})
	require.NoError(t, err)
	localCiphertext, _ := store.GetRecord(dto.ID)

	conflicts, err := syncer.Sync(ctx)
	require.NoError(t, err)
	assert.Empty(t, conflicts, "conflict-copy must be pushed as a new record, not left dirty forever")

	final, ok := store.GetRecord(dto.ID)
	require.True(t, ok)
	assert.True(t, final.IsDeleted, "server delete must win over a concurrent local update")

	all := store.ListRecords()
	require.Len(t, all, 2, "the losing local update must be preserved as a conflict-copy")
	for _, r := range all {
		if r.ID != dto.ID {
			assert.Equal(t, localCiphertext.Ciphertext, r.Ciphertext, "conflict-copy must preserve the local update's content")
		}
	}
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
