package service_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	clientservice "github.com/alexvictorne/voldepass/internal/client/service"
	"github.com/alexvictorne/voldepass/internal/client/storage"
	"github.com/alexvictorne/voldepass/internal/domain"
)

func TestSession_Close_SavesAndZeroesKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "storage.vp")
	dataKey := newTestDataKey(t)
	dataKeyCopy := append([]byte(nil), dataKey...)

	fileStore := storage.NewFileStore(path)
	fileStore.PutRecord(storage.StoredRecord{RecordDTO: domain.RecordDTO{ID: "r1", Ciphertext: []byte("ct")}})

	session := clientservice.NewSession(fileStore, dataKey, nil)
	require.NoError(t, session.Close(context.Background()))

	// Ключ должен быть обнулён после Close.
	for _, b := range session.DataKey() {
		assert.Equal(t, byte(0), b)
	}

	// Файл должен быть читаем исходным (не обнулённым) ключом.
	reloaded := storage.NewFileStore(path)
	require.NoError(t, reloaded.Load(dataKeyCopy))
	_, ok := reloaded.GetRecord("r1")
	assert.True(t, ok)
}

func TestSession_Close_WithSyncer(t *testing.T) {
	adapter, _ := newSyncSetup("u1")
	path := filepath.Join(t.TempDir(), "storage.vp")
	dataKey := newTestDataKey(t)

	fileStore := storage.NewFileStore(path)
	vault := clientservice.NewVaultManager(fileStore.Store, dataKey)
	_, err := vault.Create(domain.DataTypeText, "", domain.TextPayload{Content: "x"})
	require.NoError(t, err)

	syncer := clientservice.NewSyncer(adapter, fileStore.Store)
	session := clientservice.NewSession(fileStore, dataKey, syncer)

	require.NoError(t, session.Close(context.Background()))
	assert.Empty(t, fileStore.ListDirty(), "final sync on close must push dirty records")
}
