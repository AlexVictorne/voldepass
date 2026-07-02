package storage_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/alexvictorne/voldepass/internal/client/crypto"
	"github.com/alexvictorne/voldepass/internal/client/storage"
	"github.com/alexvictorne/voldepass/internal/domain"
)

func newTestDataKey(t *testing.T) []byte {
	t.Helper()
	key, err := crypto.GenerateDataKey()
	require.NoError(t, err)
	return key
}

func TestFileStore_SaveAndLoad_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "storage.vp")
	dataKey := newTestDataKey(t)

	fs := storage.NewFileStore(path)
	fs.PutRecord(storage.StoredRecord{RecordDTO: domain.RecordDTO{ID: "r1", Ciphertext: []byte("ct")}})
	fs.SetLastSyncVersion(42)
	require.NoError(t, fs.Save(dataKey))

	reloaded := storage.NewFileStore(path)
	require.NoError(t, reloaded.Load(dataKey))

	got, ok := reloaded.GetRecord("r1")
	require.True(t, ok)
	assert.Equal(t, []byte("ct"), got.Ciphertext)
	assert.Equal(t, int64(42), reloaded.LastSyncVersion())
}

func TestFileStore_Load_MissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nonexistent.vp")
	fs := storage.NewFileStore(path)

	err := fs.Load(newTestDataKey(t))
	require.NoError(t, err, "missing file must not be an error (first run)")
	assert.Empty(t, fs.ListRecords())
}

func TestFileStore_Load_WrongKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "storage.vp")
	fs := storage.NewFileStore(path)
	fs.PutRecord(storage.StoredRecord{RecordDTO: domain.RecordDTO{ID: "r1"}})
	require.NoError(t, fs.Save(newTestDataKey(t)))

	reloaded := storage.NewFileStore(path)
	err := reloaded.Load(newTestDataKey(t))
	assert.Error(t, err, "loading with a different key must fail")
}

func TestFileStore_Load_CorruptedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "storage.vp")
	require.NoError(t, os.WriteFile(path, []byte("not valid json"), 0o600))

	fs := storage.NewFileStore(path)
	err := fs.Load(newTestDataKey(t))
	assert.Error(t, err)
}

func TestFileStore_Save_NoLeftoverTempFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "storage.vp")
	dataKey := newTestDataKey(t)

	fs := storage.NewFileStore(path)
	fs.PutRecord(storage.StoredRecord{RecordDTO: domain.RecordDTO{ID: "r1"}})
	require.NoError(t, fs.Save(dataKey))

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1, "only the final file must remain, no leftover .tmp files")
	assert.Equal(t, "storage.vp", entries[0].Name())
}

func TestFileStore_Save_OverwritesExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "storage.vp")
	dataKey := newTestDataKey(t)

	fs := storage.NewFileStore(path)
	fs.PutRecord(storage.StoredRecord{RecordDTO: domain.RecordDTO{ID: "r1"}})
	require.NoError(t, fs.Save(dataKey))

	fs.PutRecord(storage.StoredRecord{RecordDTO: domain.RecordDTO{ID: "r2"}})
	require.NoError(t, fs.Save(dataKey))

	reloaded := storage.NewFileStore(path)
	require.NoError(t, reloaded.Load(dataKey))
	assert.Len(t, reloaded.ListRecords(), 2)
}

func TestFileStore_PreservesProfileAndTokens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "storage.vp")
	dataKey := newTestDataKey(t)

	fs := storage.NewFileStore(path)
	fs.SetProfile([]byte("salt"), domain.DefaultKdfParams(), []byte("wrapped"))
	fs.SetTokens("access", "refresh")
	require.NoError(t, fs.Save(dataKey))

	reloaded := storage.NewFileStore(path)
	require.NoError(t, reloaded.Load(dataKey))

	snap := reloaded.Snapshot()
	assert.Equal(t, []byte("salt"), snap.KdfSalt)
	assert.Equal(t, []byte("wrapped"), snap.WrappedDataKey)

	access, refresh := reloaded.Tokens()
	assert.Equal(t, "access", access)
	assert.Equal(t, "refresh", refresh)
}
