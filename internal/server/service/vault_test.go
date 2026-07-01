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

func newVaultService() *service.VaultService {
	return service.NewVaultService(inmem.NewRecordRepository())
}

func TestVaultService_CreateAndGet(t *testing.T) {
	svc := newVaultService()
	ctx := context.Background()

	rec, err := svc.Create(ctx, "u1", domain.Record{Type: domain.DataTypeText, Ciphertext: []byte("ct")})
	require.NoError(t, err)
	assert.NotEmpty(t, rec.ID)
	assert.Equal(t, int64(1), rec.Version)

	got, err := svc.Get(ctx, "u1", rec.ID)
	require.NoError(t, err)
	assert.Equal(t, rec.ID, got.ID)
}

func TestVaultService_Get_WrongOwner(t *testing.T) {
	svc := newVaultService()
	ctx := context.Background()
	rec, _ := svc.Create(ctx, "u1", domain.Record{Ciphertext: []byte("ct")})

	_, err := svc.Get(ctx, "u2", rec.ID)
	assert.ErrorIs(t, err, domain.ErrNotFound)
}

func TestVaultService_Update(t *testing.T) {
	svc := newVaultService()
	ctx := context.Background()
	rec, _ := svc.Create(ctx, "u1", domain.Record{Ciphertext: []byte("v1")})

	rec.Ciphertext = []byte("v2")
	updated, err := svc.Update(ctx, "u1", rec, rec.Version)
	require.NoError(t, err)
	assert.Equal(t, []byte("v2"), updated.Ciphertext)
	assert.Greater(t, updated.Version, rec.Version-1)
}

func TestVaultService_Update_WrongOwner(t *testing.T) {
	svc := newVaultService()
	ctx := context.Background()
	rec, _ := svc.Create(ctx, "u1", domain.Record{Ciphertext: []byte("v1")})

	_, err := svc.Update(ctx, "u2", rec, rec.Version)
	assert.ErrorIs(t, err, domain.ErrUnauthorized)
}

func TestVaultService_Update_Conflict(t *testing.T) {
	svc := newVaultService()
	ctx := context.Background()
	rec, _ := svc.Create(ctx, "u1", domain.Record{Ciphertext: []byte("v1")})

	// Устаревшая baseVersion → конфликт.
	_, err := svc.Update(ctx, "u1", rec, 0)
	assert.ErrorIs(t, err, domain.ErrConflict)
}

func TestVaultService_List(t *testing.T) {
	svc := newVaultService()
	ctx := context.Background()
	r1, _ := svc.Create(ctx, "u1", domain.Record{Ciphertext: []byte("a")})
	svc.Create(ctx, "u1", domain.Record{Ciphertext: []byte("b")})
	svc.Create(ctx, "u2", domain.Record{Ciphertext: []byte("c")})

	all, err := svc.List(ctx, "u1", 0)
	require.NoError(t, err)
	assert.Len(t, all, 2, "must not see u2's records")

	since, err := svc.List(ctx, "u1", r1.Version)
	require.NoError(t, err)
	assert.Len(t, since, 1)
}

func TestVaultService_Delete(t *testing.T) {
	svc := newVaultService()
	ctx := context.Background()
	rec, _ := svc.Create(ctx, "u1", domain.Record{Ciphertext: []byte("ct")})

	require.NoError(t, svc.Delete(ctx, "u1", rec.ID))

	got, err := svc.Get(ctx, "u1", rec.ID)
	require.NoError(t, err)
	assert.True(t, got.Deleted)
}

func TestVaultService_Delete_WrongOwner(t *testing.T) {
	svc := newVaultService()
	ctx := context.Background()
	rec, _ := svc.Create(ctx, "u1", domain.Record{Ciphertext: []byte("ct")})

	err := svc.Delete(ctx, "u2", rec.ID)
	assert.ErrorIs(t, err, domain.ErrUnauthorized)
}

func TestVaultService_Get_NotFound(t *testing.T) {
	svc := newVaultService()
	_, err := svc.Get(context.Background(), "u1", "nonexistent")
	assert.ErrorIs(t, err, domain.ErrNotFound)
}
