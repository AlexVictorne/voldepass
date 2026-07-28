package service_test

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/alexvictorne/voldepass/internal/client/crypto"
	clientservice "github.com/alexvictorne/voldepass/internal/client/service"
	"github.com/alexvictorne/voldepass/internal/client/storage"
	"github.com/alexvictorne/voldepass/internal/domain"
)

func newTestDataKey(t *testing.T) []byte {
	t.Helper()
	key, err := crypto.GenerateDataKey()
	require.NoError(t, err)
	return key
}

func newVaultManager(t *testing.T) *clientservice.VaultManager {
	t.Helper()
	dataKey := newTestDataKey(t)
	return clientservice.NewVaultManager(storage.NewStore(), dataKey)
}

func TestVaultManager_CreateAndGet(t *testing.T) {
	v := newVaultManager(t)

	payload := domain.CredentialsPayload{Login: "user@example.com", Password: "s3cr3t"}
	dto, err := v.Create(domain.DataTypeCredentials, "github", payload)
	require.NoError(t, err)
	assert.NotEmpty(t, dto.ID)
	assert.Equal(t, domain.DataTypeCredentials, dto.Type)

	var got domain.CredentialsPayload
	meta, gotDTO, err := v.Get(dto.ID, &got)
	require.NoError(t, err)
	assert.Equal(t, "github", meta)
	assert.Equal(t, payload, got)
	assert.Equal(t, dto.ID, gotDTO.ID)
}

func TestVaultManager_Create_PayloadTooLarge(t *testing.T) {
	v := newVaultManager(t)

	huge := domain.TextPayload{Content: strings.Repeat("a", 7<<20+1)}
	_, err := v.Create(domain.DataTypeText, "", huge)
	assert.ErrorIs(t, err, domain.ErrPayloadTooLarge, "must be rejected locally, before encryption/local storage/sync")
}

func TestVaultManager_Update_PayloadTooLarge(t *testing.T) {
	v := newVaultManager(t)
	dto, err := v.Create(domain.DataTypeText, "", domain.TextPayload{Content: "small"})
	require.NoError(t, err)

	huge := domain.TextPayload{Content: strings.Repeat("a", 7<<20+1)}
	_, err = v.Update(dto.ID, "", huge)
	assert.ErrorIs(t, err, domain.ErrPayloadTooLarge)
}

func TestVaultManager_Create_NoMeta(t *testing.T) {
	v := newVaultManager(t)
	dto, err := v.Create(domain.DataTypeText, "", domain.TextPayload{Content: "note"})
	require.NoError(t, err)

	var got domain.TextPayload
	meta, _, err := v.Get(dto.ID, &got)
	require.NoError(t, err)
	assert.Empty(t, meta)
	assert.Equal(t, "note", got.Content)
}

func TestVaultManager_GetMeta(t *testing.T) {
	v := newVaultManager(t)
	dto, err := v.Create(domain.DataTypeCredentials, "github", domain.CredentialsPayload{Login: "a", Password: "b"})
	require.NoError(t, err)

	meta, err := v.GetMeta(dto.ID)
	require.NoError(t, err)
	assert.Equal(t, "github", meta)
}

func TestVaultManager_GetMeta_NoMeta(t *testing.T) {
	v := newVaultManager(t)
	dto, err := v.Create(domain.DataTypeText, "", domain.TextPayload{Content: "note"})
	require.NoError(t, err)

	meta, err := v.GetMeta(dto.ID)
	require.NoError(t, err)
	assert.Empty(t, meta)
}

func TestVaultManager_GetMeta_NotFound(t *testing.T) {
	v := newVaultManager(t)
	_, err := v.GetMeta("ghost")
	assert.ErrorIs(t, err, domain.ErrNotFound)
}

func TestVaultManager_GetMeta_DoesNotRequireDecryptablePayload(t *testing.T) {
	// GetMeta не должен трогать Ciphertext вовсе — проверяем, что даже если
	// payload испорчен/нерасшифровываем, GetMeta по-прежнему отдаёт meta.
	store := storage.NewStore()
	v := clientservice.NewVaultManager(store, newTestDataKey(t))
	dto, err := v.Create(domain.DataTypeText, "label", domain.TextPayload{Content: "note"})
	require.NoError(t, err)

	rec, ok := store.GetRecord(dto.ID)
	require.True(t, ok)
	rec.Ciphertext = []byte("not-valid-ciphertext")
	rec.Nonce = make([]byte, 12) // корректная длина nonce, но заведомо не тот, что шифровал payload
	store.PutRecord(rec)

	// Payload действительно теперь не расшифровывается, чтобы убедиться, что тест не тривиален.
	_, _, err = v.Get(dto.ID, &domain.TextPayload{})
	require.Error(t, err)

	meta, err := v.GetMeta(dto.ID)
	require.NoError(t, err)
	assert.Equal(t, "label", meta)
}

func TestVaultManager_Update(t *testing.T) {
	v := newVaultManager(t)
	dto, err := v.Create(domain.DataTypeText, "note-meta", domain.TextPayload{Content: "v1"})
	require.NoError(t, err)

	updated, err := v.Update(dto.ID, "note-meta-2", domain.TextPayload{Content: "v2"})
	require.NoError(t, err)
	assert.Equal(t, dto.ID, updated.ID)

	var got domain.TextPayload
	meta, _, err := v.Get(dto.ID, &got)
	require.NoError(t, err)
	assert.Equal(t, "v2", got.Content)
	assert.Equal(t, "note-meta-2", meta)
}

// TestVaultManager_Create_SetsDirtyAt проверяет, что Create/Update/Delete проставляют
// StoredRecord.DirtyAt — Syncer использует его для LWW-разрешения конфликтов.
func TestVaultManager_Create_SetsDirtyAt(t *testing.T) {
	store := storage.NewStore()
	v := clientservice.NewVaultManager(store, newTestDataKey(t))

	before := time.Now()
	dto, err := v.Create(domain.DataTypeText, "", domain.TextPayload{Content: "x"})
	require.NoError(t, err)
	after := time.Now()

	rec, ok := store.GetRecord(dto.ID)
	require.True(t, ok)
	assert.True(t, !rec.DirtyAt.Before(before) && !rec.DirtyAt.After(after), "DirtyAt must be set to roughly now() on Create")
}

func TestVaultManager_Update_RefreshesDirtyAt(t *testing.T) {
	store := storage.NewStore()
	v := clientservice.NewVaultManager(store, newTestDataKey(t))
	dto, err := v.Create(domain.DataTypeText, "", domain.TextPayload{Content: "v1"})
	require.NoError(t, err)

	createdAt, ok := store.GetRecord(dto.ID)
	require.True(t, ok)

	time.Sleep(time.Millisecond)
	_, err = v.Update(dto.ID, "", domain.TextPayload{Content: "v2"})
	require.NoError(t, err)

	updatedAt, ok := store.GetRecord(dto.ID)
	require.True(t, ok)
	assert.True(t, updatedAt.DirtyAt.After(createdAt.DirtyAt), "Update must refresh DirtyAt to the time of the edit")
}

func TestVaultManager_Delete_SetsDirtyAt(t *testing.T) {
	store := storage.NewStore()
	v := clientservice.NewVaultManager(store, newTestDataKey(t))
	dto, err := v.Create(domain.DataTypeText, "", domain.TextPayload{Content: "x"})
	require.NoError(t, err)

	before := time.Now()
	require.NoError(t, v.Delete(dto.ID))
	after := time.Now()

	rec, ok := store.GetRecord(dto.ID)
	require.True(t, ok)
	assert.True(t, !rec.DirtyAt.Before(before) && !rec.DirtyAt.After(after), "DirtyAt must be refreshed to roughly now() on Delete")
}

func TestVaultManager_Update_NotFound(t *testing.T) {
	v := newVaultManager(t)
	_, err := v.Update("ghost", "m", domain.TextPayload{})
	assert.ErrorIs(t, err, domain.ErrNotFound)
}

func TestVaultManager_Delete_Tombstone(t *testing.T) {
	v := newVaultManager(t)
	dto, err := v.Create(domain.DataTypeText, "", domain.TextPayload{Content: "x"})
	require.NoError(t, err)

	require.NoError(t, v.Delete(dto.ID))

	list := v.List()
	assert.Empty(t, list, "deleted record must not appear in List")
}

func TestVaultManager_Delete_NotFound(t *testing.T) {
	v := newVaultManager(t)
	err := v.Delete("ghost")
	assert.ErrorIs(t, err, domain.ErrNotFound)
}

func TestVaultManager_List(t *testing.T) {
	v := newVaultManager(t)
	_, err := v.Create(domain.DataTypeText, "", domain.TextPayload{Content: "a"})
	require.NoError(t, err)
	_, err = v.Create(domain.DataTypeText, "", domain.TextPayload{Content: "b"})
	require.NoError(t, err)

	list := v.List()
	assert.Len(t, list, 2)
}

func TestVaultManager_Get_NotFound(t *testing.T) {
	v := newVaultManager(t)
	_, _, err := v.Get("ghost", nil)
	assert.ErrorIs(t, err, domain.ErrNotFound)
}

func TestVaultManager_Get_WrongDataKeyFails(t *testing.T) {
	store := storage.NewStore()
	dataKey := newTestDataKey(t)
	v := clientservice.NewVaultManager(store, dataKey)
	dto, err := v.Create(domain.DataTypeText, "", domain.TextPayload{Content: "secret"})
	require.NoError(t, err)

	otherKey := newTestDataKey(t)
	v2 := clientservice.NewVaultManager(store, otherKey)
	var got domain.TextPayload
	_, _, err = v2.Get(dto.ID, &got)
	assert.Error(t, err, "decrypting with a different dataKey must fail")
}
