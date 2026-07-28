package inmem_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/alexvictorne/voldepass/internal/domain"
	"github.com/alexvictorne/voldepass/internal/server/storage/inmem"
)

var ctx = context.Background()

// ── UserRepository ────────────────────────────────────────────────────────────

func TestUserRepository_CreateAndGet(t *testing.T) {
	r := inmem.NewUserRepository()
	u := domain.User{ID: "u1", Login: "alice"}
	p := domain.Profile{UserID: "u1"}

	require.NoError(t, r.Create(ctx, u, p))

	got, err := r.GetByLogin(ctx, "alice")
	require.NoError(t, err)
	assert.Equal(t, u.ID, got.ID)

	got2, err := r.GetByID(ctx, "u1")
	require.NoError(t, err)
	assert.Equal(t, u.Login, got2.Login)
}

func TestUserRepository_DuplicateLogin(t *testing.T) {
	r := inmem.NewUserRepository()
	u := domain.User{ID: "u1", Login: "alice"}
	require.NoError(t, r.Create(ctx, u, domain.Profile{UserID: "u1"}))
	err := r.Create(ctx, domain.User{ID: "u2", Login: "alice"}, domain.Profile{UserID: "u2"})
	assert.ErrorIs(t, err, domain.ErrAlreadyExists)
}

func TestUserRepository_NotFound(t *testing.T) {
	r := inmem.NewUserRepository()
	_, err := r.GetByLogin(ctx, "ghost")
	assert.ErrorIs(t, err, domain.ErrNotFound)
	_, err = r.GetByID(ctx, "x")
	assert.ErrorIs(t, err, domain.ErrNotFound)
}

func TestUserRepository_UpdateProfile(t *testing.T) {
	r := inmem.NewUserRepository()
	require.NoError(t, r.Create(ctx, domain.User{ID: "u1", Login: "alice"}, domain.Profile{UserID: "u1", ProfileVersion: 1}))

	p2 := domain.Profile{UserID: "u1", ProfileVersion: 2, KdfSalt: []byte("newsalt")}
	require.NoError(t, r.UpdateProfile(ctx, p2))

	got, err := r.GetProfile(ctx, "u1")
	require.NoError(t, err)
	assert.Equal(t, 2, got.ProfileVersion)
	assert.Equal(t, []byte("newsalt"), got.KdfSalt)
}

// ── RecordRepository ──────────────────────────────────────────────────────────

func TestRecordRepository_UpsertAndGet(t *testing.T) {
	r := inmem.NewRecordRepository()
	rec := domain.Record{ID: "r1", OwnerID: "u1", Ciphertext: []byte("ct")}

	saved, err := r.Upsert(ctx, rec, 0)
	require.NoError(t, err)
	assert.Equal(t, int64(1), saved.Version)

	got, err := r.Get(ctx, "r1", "u1")
	require.NoError(t, err)
	assert.Equal(t, saved.Version, got.Version)
}

func TestRecordRepository_OptimisticLockConflict(t *testing.T) {
	r := inmem.NewRecordRepository()
	rec := domain.Record{ID: "r1", OwnerID: "u1", Ciphertext: []byte("ct")}
	saved, _ := r.Upsert(ctx, rec, 0)

	// Повторный upsert с устаревшей baseVersion → конфликт.
	_, err := r.Upsert(ctx, rec, 0)
	assert.ErrorIs(t, err, domain.ErrConflict)

	// Корректная baseVersion → успех.
	saved2, err := r.Upsert(ctx, rec, saved.Version)
	require.NoError(t, err)
	assert.Equal(t, int64(2), saved2.Version)
}

func TestRecordRepository_ListSince(t *testing.T) {
	r := inmem.NewRecordRepository()
	r1, _ := r.Upsert(ctx, domain.Record{ID: "r1", OwnerID: "u1", Ciphertext: []byte("a")}, 0)
	r2, _ := r.Upsert(ctx, domain.Record{ID: "r2", OwnerID: "u1", Ciphertext: []byte("b")}, 0)

	all, err := r.ListSince(ctx, "u1", 0)
	require.NoError(t, err)
	assert.Len(t, all, 2)

	since1, err := r.ListSince(ctx, "u1", r1.Version)
	require.NoError(t, err)
	assert.Len(t, since1, 1)
	assert.Equal(t, r2.ID, since1[0].ID)
}

func TestRecordRepository_Delete(t *testing.T) {
	r := inmem.NewRecordRepository()
	r.Upsert(ctx, domain.Record{ID: "r1", OwnerID: "u1", Ciphertext: []byte("ct")}, 0)

	require.NoError(t, r.Delete(ctx, "r1", "u1"))

	got, err := r.Get(ctx, "r1", "u1")
	require.NoError(t, err)
	assert.True(t, got.Deleted)
}

func TestRecordRepository_GetWrongOwner(t *testing.T) {
	r := inmem.NewRecordRepository()
	r.Upsert(ctx, domain.Record{ID: "r1", OwnerID: "u1", Ciphertext: []byte("ct")}, 0)

	_, err := r.Get(ctx, "r1", "u2")
	assert.ErrorIs(t, err, domain.ErrNotFound)
}

// ── IdempotencyStore ──────────────────────────────────────────────────────────

func TestIdempotencyStore_SaveAndGet(t *testing.T) {
	s := inmem.NewIdempotencyStore()
	require.NoError(t, s.Save(ctx, "u1", "key1", []byte("result"), time.Minute))

	got, err := s.Get(ctx, "u1", "key1")
	require.NoError(t, err)
	assert.Equal(t, []byte("result"), got)
}

func TestIdempotencyStore_Expired(t *testing.T) {
	s := inmem.NewIdempotencyStore()
	require.NoError(t, s.Save(ctx, "u1", "key1", []byte("r"), -time.Second))

	_, err := s.Get(ctx, "u1", "key1")
	assert.ErrorIs(t, err, domain.ErrNotFound)
}

func TestIdempotencyStore_DeleteExpired(t *testing.T) {
	s := inmem.NewIdempotencyStore()
	require.NoError(t, s.Save(ctx, "u1", "expired", []byte("x"), -time.Second))
	require.NoError(t, s.Save(ctx, "u1", "alive", []byte("y"), time.Minute))

	require.NoError(t, s.DeleteExpired(ctx))

	_, err := s.Get(ctx, "u1", "expired")
	assert.ErrorIs(t, err, domain.ErrNotFound)
	_, err = s.Get(ctx, "u1", "alive")
	assert.NoError(t, err)
}

// ── RefreshTokenStore ─────────────────────────────────────────────────────────

func TestRefreshTokenStore_SaveAndGet(t *testing.T) {
	s := inmem.NewRefreshTokenStore()
	exp := time.Now().Add(time.Hour)
	require.NoError(t, s.Save(ctx, "u1", "hash1", exp))

	uid, revoked, gotExp, err := s.Get(ctx, "hash1")
	require.NoError(t, err)
	assert.Equal(t, "u1", uid)
	assert.False(t, revoked)
	assert.WithinDuration(t, exp, gotExp, time.Second)
}

func TestRefreshTokenStore_Rotate(t *testing.T) {
	s := inmem.NewRefreshTokenStore()
	require.NoError(t, s.Save(ctx, "u1", "old", time.Now().Add(time.Hour)))

	require.NoError(t, s.Rotate(ctx, "old", "new", "u1", time.Now().Add(time.Hour)))

	_, revoked, _, err := s.Get(ctx, "old")
	require.NoError(t, err)
	assert.True(t, revoked, "old token must be revoked after rotation")

	uid, revoked2, _, err := s.Get(ctx, "new")
	require.NoError(t, err)
	assert.Equal(t, "u1", uid)
	assert.False(t, revoked2)
}

func TestRefreshTokenStore_RevokeAll(t *testing.T) {
	s := inmem.NewRefreshTokenStore()
	require.NoError(t, s.Save(ctx, "u1", "t1", time.Now().Add(time.Hour)))
	require.NoError(t, s.Save(ctx, "u1", "t2", time.Now().Add(time.Hour)))
	require.NoError(t, s.Save(ctx, "u2", "t3", time.Now().Add(time.Hour)))

	require.NoError(t, s.RevokeAll(ctx, "u1"))

	_, r1, _, err := s.Get(ctx, "t1")
	require.NoError(t, err)
	_, r2, _, err := s.Get(ctx, "t2")
	require.NoError(t, err)
	_, r3, _, err := s.Get(ctx, "t3")
	require.NoError(t, err)
	assert.True(t, r1)
	assert.True(t, r2)
	assert.False(t, r3, "u2 token must not be revoked")
}

// ── LoginAttemptTracker ───────────────────────────────────────────────────────

func TestLoginAttemptTracker_AllowedAndBlock(t *testing.T) {
	tr := inmem.NewLoginAttemptTracker(3, time.Minute)

	for i := 0; i < 3; i++ {
		ok, _ := tr.Allowed(ctx, "alice")
		assert.True(t, ok)
		tr.Inc(ctx, "alice")
	}

	ok, err := tr.Allowed(ctx, "alice")
	require.NoError(t, err)
	assert.False(t, ok, "must be blocked after 3 attempts")
}

func TestLoginAttemptTracker_ResetAllows(t *testing.T) {
	tr := inmem.NewLoginAttemptTracker(2, time.Minute)
	tr.Inc(ctx, "alice")
	tr.Inc(ctx, "alice")

	tr.Reset(ctx, "alice")

	ok, _ := tr.Allowed(ctx, "alice")
	assert.True(t, ok, "must be allowed after reset")
}

func TestLoginAttemptTracker_WindowExpiry(t *testing.T) {
	tr := inmem.NewLoginAttemptTracker(1, time.Millisecond)
	tr.Inc(ctx, "alice")

	time.Sleep(5 * time.Millisecond)

	ok, _ := tr.Allowed(ctx, "alice")
	assert.True(t, ok, "must be allowed after window expires")
}
