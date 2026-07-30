package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alexvictorne/voldepass/internal/domain"
)

// RefreshTokenStore — postgres-реализация service.RefreshTokenStore.
type RefreshTokenStore struct {
	pool *pgxpool.Pool
}

// NewRefreshTokenStore создаёт postgres-хранилище refresh-токенов.
func NewRefreshTokenStore(pool *pgxpool.Pool) *RefreshTokenStore {
	return &RefreshTokenStore{pool: pool}
}

func (s *RefreshTokenStore) Save(ctx context.Context, userID, tokenHash string, expiresAt time.Time) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
		VALUES ($1, $2, $3)`,
		userID, tokenHash, expiresAt,
	)
	if err != nil {
		return fmt.Errorf("save refresh token: %w", err)
	}
	return nil
}

func (s *RefreshTokenStore) Get(ctx context.Context, tokenHash string) (string, bool, time.Time, error) {
	var userID string
	var revoked bool
	var expiresAt time.Time

	err := s.pool.QueryRow(ctx, `
		SELECT user_id, revoked, expires_at FROM refresh_tokens WHERE token_hash = $1`,
		tokenHash,
	).Scan(&userID, &revoked, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, time.Time{}, domain.ErrNotFound
	}
	if err != nil {
		return "", false, time.Time{}, fmt.Errorf("get refresh token: %w", err)
	}
	return userID, revoked, expiresAt, nil
}

func (s *RefreshTokenStore) Rotate(ctx context.Context, oldHash, newHash, userID string, expiresAt time.Time) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tag, err := tx.Exec(ctx, `UPDATE refresh_tokens SET revoked = true WHERE token_hash = $1`, oldHash)
	if err != nil {
		return fmt.Errorf("revoke old token: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}

	_, err = tx.Exec(ctx, `INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)`,
		userID, newHash, expiresAt,
	)
	if err != nil {
		return fmt.Errorf("insert new token: %w", err)
	}

	return tx.Commit(ctx)
}

func (s *RefreshTokenStore) RevokeAll(ctx context.Context, userID string) error {
	_, err := s.pool.Exec(ctx, `UPDATE refresh_tokens SET revoked = true WHERE user_id = $1`, userID)
	if err != nil {
		return fmt.Errorf("revoke all tokens: %w", err)
	}
	return nil
}
