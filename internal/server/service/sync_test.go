package service_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/alexvictorne/voldepass/internal/domain"
	"github.com/alexvictorne/voldepass/internal/server/service"
	"github.com/alexvictorne/voldepass/internal/server/storage/inmem"
)

func newSyncService() (*service.SyncService, *service.VaultService) {
	records := inmem.NewRecordRepository()
	sync := service.NewSyncService(records, inmem.NewIdempotencyStore())
	vault := service.NewVaultService(records)
	return sync, vault
}

func TestSyncService_PullEmpty(t *testing.T) {
	sync, _ := newSyncService()
	resp, err := sync.Pull(context.Background(), "u1", 0)
	require.NoError(t, err)
	assert.Empty(t, resp.Records)
}

func TestSyncService_PushAndPull(t *testing.T) {
	sync, _ := newSyncService()
	ctx := context.Background()

	req := domain.SyncPushRequest{Records: []domain.RecordDTO{
		{ID: "r1", Type: domain.DataTypeText, Ciphertext: []byte("ct1"), Nonce: []byte("n1"), BaseVersion: 0},
	}}
	resp, err := sync.Push(ctx, "u1", "key-1", req)
	require.NoError(t, err)
	require.Len(t, resp.Results, 1)
	assert.Equal(t, domain.PushStatusApplied, resp.Results[0].Status)

	pulled, err := sync.Pull(ctx, "u1", 0)
	require.NoError(t, err)
	require.Len(t, pulled.Records, 1)
	assert.Equal(t, "r1", pulled.Records[0].ID)
}

func TestSyncService_Push_Conflict(t *testing.T) {
	sync, _ := newSyncService()
	ctx := context.Background()

	req := domain.SyncPushRequest{Records: []domain.RecordDTO{
		{ID: "r1", Ciphertext: []byte("v1"), Nonce: []byte("n1"), BaseVersion: 0},
	}}
	sync.Push(ctx, "u1", "key-1", req)

	// Повторный push с той же (устаревшей) BaseVersion → конфликт.
	req2 := domain.SyncPushRequest{Records: []domain.RecordDTO{
		{ID: "r1", Ciphertext: []byte("v2"), Nonce: []byte("n1"), BaseVersion: 0},
	}}
	resp, err := sync.Push(ctx, "u1", "key-2", req2)
	require.NoError(t, err)
	assert.Equal(t, domain.PushStatusConflict, resp.Results[0].Status)
}

func TestSyncService_Push_IdempotentReplay(t *testing.T) {
	sync, _ := newSyncService()
	ctx := context.Background()

	req := domain.SyncPushRequest{Records: []domain.RecordDTO{
		{ID: "r1", Ciphertext: []byte("v1"), Nonce: []byte("n1"), BaseVersion: 0},
	}}
	resp1, err := sync.Push(ctx, "u1", "same-key", req)
	require.NoError(t, err)

	// Повторный запрос с тем же idempotency key → тот же результат, без повторного применения.
	resp2, err := sync.Push(ctx, "u1", "same-key", req)
	require.NoError(t, err)
	assert.Equal(t, resp1, resp2)

	// Убеждаемся, что версия не увеличилась повторно.
	pulled, _ := sync.Pull(ctx, "u1", 0)
	require.Len(t, pulled.Records, 1)
	assert.Equal(t, resp1.Results[0].ServerRecord.Version, pulled.Records[0].Version)
}

func TestSyncService_Push_DeleteTombstone(t *testing.T) {
	sync, _ := newSyncService()
	ctx := context.Background()

	sync.Push(ctx, "u1", "k1", domain.SyncPushRequest{Records: []domain.RecordDTO{
		{ID: "r1", Ciphertext: []byte("v1"), Nonce: []byte("n1"), BaseVersion: 0},
	}})

	pulled, _ := sync.Pull(ctx, "u1", 0)
	currentVersion := pulled.Records[0].Version

	resp, err := sync.Push(ctx, "u1", "k2", domain.SyncPushRequest{Records: []domain.RecordDTO{
		{ID: "r1", Ciphertext: []byte("v1"), Nonce: []byte("n1"), BaseVersion: currentVersion, IsDeleted: true},
	}})
	require.NoError(t, err)
	assert.Equal(t, domain.PushStatusApplied, resp.Results[0].Status)
	assert.True(t, resp.Results[0].ServerRecord.IsDeleted)
}

func TestSyncService_PullSinceVersion(t *testing.T) {
	sync, _ := newSyncService()
	ctx := context.Background()

	resp1, _ := sync.Push(ctx, "u1", "k1", domain.SyncPushRequest{Records: []domain.RecordDTO{
		{ID: "r1", Ciphertext: []byte("a"), Nonce: []byte("n"), BaseVersion: 0},
	}})
	sync.Push(ctx, "u1", "k2", domain.SyncPushRequest{Records: []domain.RecordDTO{
		{ID: "r2", Ciphertext: []byte("b"), Nonce: []byte("n"), BaseVersion: 0},
	}})

	since := resp1.Results[0].ServerRecord.Version
	pulled, err := sync.Pull(ctx, "u1", since)
	require.NoError(t, err)
	require.Len(t, pulled.Records, 1)
	assert.Equal(t, "r2", pulled.Records[0].ID)
}
