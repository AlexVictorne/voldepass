package storage_test

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/alexvictorne/voldepass/internal/client/storage"
	"github.com/alexvictorne/voldepass/internal/domain"
)

func TestStore_PutAndGetRecord(t *testing.T) {
	s := storage.NewStore()
	rec := storage.StoredRecord{RecordDTO: domain.RecordDTO{ID: "r1", Ciphertext: []byte("ct")}}
	s.PutRecord(rec)

	got, ok := s.GetRecord("r1")
	assert.True(t, ok)
	assert.Equal(t, []byte("ct"), got.Ciphertext)
}

func TestStore_GetRecord_NotFound(t *testing.T) {
	s := storage.NewStore()
	_, ok := s.GetRecord("ghost")
	assert.False(t, ok)
}

func TestStore_DeleteRecord(t *testing.T) {
	s := storage.NewStore()
	s.PutRecord(storage.StoredRecord{RecordDTO: domain.RecordDTO{ID: "r1"}})
	s.DeleteRecord("r1")

	_, ok := s.GetRecord("r1")
	assert.False(t, ok)
}

func TestStore_ListRecords(t *testing.T) {
	s := storage.NewStore()
	s.PutRecord(storage.StoredRecord{RecordDTO: domain.RecordDTO{ID: "r1"}})
	s.PutRecord(storage.StoredRecord{RecordDTO: domain.RecordDTO{ID: "r2"}})

	all := s.ListRecords()
	assert.Len(t, all, 2)
}

func TestStore_ListDirty(t *testing.T) {
	s := storage.NewStore()
	s.PutRecord(storage.StoredRecord{RecordDTO: domain.RecordDTO{ID: "r1"}, Dirty: true})
	s.PutRecord(storage.StoredRecord{RecordDTO: domain.RecordDTO{ID: "r2"}, Dirty: false})

	dirty := s.ListDirty()
	assert.Len(t, dirty, 1)
	assert.Equal(t, "r1", dirty[0].ID)
}

func TestStore_TokensRoundTrip(t *testing.T) {
	s := storage.NewStore()
	s.SetTokens("access", "refresh")

	access, refresh := s.Tokens()
	assert.Equal(t, "access", access)
	assert.Equal(t, "refresh", refresh)
}

func TestStore_LastSyncVersion(t *testing.T) {
	s := storage.NewStore()
	assert.Equal(t, int64(0), s.LastSyncVersion())

	s.SetLastSyncVersion(42)
	assert.Equal(t, int64(42), s.LastSyncVersion())
}

func TestStore_PendingPush_AddAndClear(t *testing.T) {
	s := storage.NewStore()
	s.AddPendingPush(storage.PendingBatch{IdempotencyKey: "k1", RecordIDs: []string{"r1", "r2"}})
	s.AddPendingPush(storage.PendingBatch{IdempotencyKey: "k2", RecordIDs: []string{"r3"}})

	assert.Len(t, s.PendingPushes(), 2)

	s.ClearPendingPush("k1")
	remaining := s.PendingPushes()
	assert.Len(t, remaining, 1)
	assert.Equal(t, "k2", remaining[0].IdempotencyKey)
}

func TestStore_Snapshot_IsIndependentCopy(t *testing.T) {
	s := storage.NewStore()
	s.PutRecord(storage.StoredRecord{RecordDTO: domain.RecordDTO{ID: "r1"}})

	snap := s.Snapshot()
	s.PutRecord(storage.StoredRecord{RecordDTO: domain.RecordDTO{ID: "r2"}})

	assert.Len(t, snap.Records, 1, "snapshot must not see records added after it was taken")
}

func TestStore_ConcurrentAccess(t *testing.T) {
	s := storage.NewStore()
	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			s.PutRecord(storage.StoredRecord{RecordDTO: domain.RecordDTO{ID: "r"}})
		}(i)
		go func(i int) {
			defer wg.Done()
			s.ListRecords()
			s.Snapshot()
		}(i)
	}
	wg.Wait()
}

func TestStore_SetProfile(t *testing.T) {
	s := storage.NewStore()
	params := domain.DefaultKdfParams()
	s.SetProfile([]byte("salt"), params, []byte("wrapped"))

	snap := s.Snapshot()
	assert.Equal(t, []byte("salt"), snap.KdfSalt)
	assert.Equal(t, params, snap.KdfParams)
	assert.Equal(t, []byte("wrapped"), snap.WrappedDataKey)
}
