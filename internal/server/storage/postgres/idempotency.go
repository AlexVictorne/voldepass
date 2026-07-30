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

// IdempotencyStore — postgres-реализация service.IdempotencyStore.
type IdempotencyStore struct {
	pool *pgxpool.Pool
}

// NewIdempotencyStore создаёт postgres-хранилище ключей идемпотентности.
func NewIdempotencyStore(pool *pgxpool.Pool) *IdempotencyStore {
	return &IdempotencyStore{pool: pool}
}

func (s *IdempotencyStore) Get(ctx context.Context, ownerID, key string) ([]byte, error) {
	var result []byte
	var createdAt time.Time

	err := s.pool.QueryRow(ctx, `
		SELECT result, created_at FROM idempotency_keys
		WHERE owner_id = $1 AND key = $2`,
		ownerID, key,
	).Scan(&result, &createdAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get idempotency key: %w", err)
	}
	return result, nil
}

func (s *IdempotencyStore) Save(ctx context.Context, ownerID, key string, result []byte, _ time.Duration) error {
	// TTL управляется через DeleteExpired по created_at; duration здесь информационная.
	_, err := s.pool.Exec(ctx, `
		INSERT INTO idempotency_keys (owner_id, key, result)
		VALUES ($1, $2, $3)
		ON CONFLICT (owner_id, key) DO UPDATE SET result = EXCLUDED.result`,
		ownerID, key, result,
	)
	if err != nil {
		return fmt.Errorf("save idempotency key: %w", err)
	}
	return nil
}

func (s *IdempotencyStore) DeleteExpired(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `
		DELETE FROM idempotency_keys WHERE created_at < now() - interval '24 hours'`,
	)
	if err != nil {
		return fmt.Errorf("delete expired idempotency keys: %w", err)
	}
	return nil
}
