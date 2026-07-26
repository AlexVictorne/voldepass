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

// RecordRepository — postgres-реализация service.RecordRepository.
type RecordRepository struct {
	pool *pgxpool.Pool
}

// NewRecordRepository создаёт postgres-репозиторий записей хранилища.
func NewRecordRepository(pool *pgxpool.Pool) *RecordRepository {
	return &RecordRepository{pool: pool}
}

func (r *RecordRepository) Upsert(ctx context.Context, rec domain.Record, baseVersion int64) (domain.Record, error) {
	var saved domain.Record

	// version = nextval(...) в обеих ветках (INSERT и UPDATE): это глобальный
	// монотонный курсор для протокола синхронизации (GET /sync?since=), а не
	// локальный счётчик изменений отдельной записи. Если бы INSERT просто
	// проставлял version=1, вторая и последующие НОВЫЕ записи получали бы тот
	// же version=1, что и первая, и не проходили бы фильтр "version > since"
	// при следующем Pull — клиент их просто не увидел бы.
	err := r.pool.QueryRow(ctx, `
		INSERT INTO records (id, owner_id, type, encrypted_meta, meta_nonce, ciphertext, nonce, version, updated_at, deleted)
		VALUES ($1, $2, $3, $4, $5, $6, $7, nextval('records_version_seq'), now(), $8)
		ON CONFLICT (id) DO UPDATE
			SET encrypted_meta = EXCLUDED.encrypted_meta,
			    meta_nonce      = EXCLUDED.meta_nonce,
			    ciphertext      = EXCLUDED.ciphertext,
			    nonce           = EXCLUDED.nonce,
			    version         = nextval('records_version_seq'),
			    updated_at      = now(),
			    deleted         = EXCLUDED.deleted
			WHERE records.version = $9
		RETURNING id, owner_id, type, encrypted_meta, meta_nonce, ciphertext, nonce, version, updated_at, deleted`,
		rec.ID, rec.OwnerID, rec.Type, rec.EncryptedMeta, rec.MetaNonce,
		rec.Ciphertext, rec.Nonce, rec.Deleted, baseVersion,
	).Scan(
		&saved.ID, &saved.OwnerID, &saved.Type,
		&saved.EncryptedMeta, &saved.MetaNonce,
		&saved.Ciphertext, &saved.Nonce,
		&saved.Version, &saved.UpdatedAt, &saved.Deleted,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		// ON CONFLICT DO UPDATE WHERE не совпало → версия устарела.
		var cur domain.Record
		if cur, err = r.Get(ctx, rec.ID, rec.OwnerID); err != nil {
			return domain.Record{}, err
		}
		return cur, domain.ErrConflict
	}
	if err != nil {
		return domain.Record{}, fmt.Errorf("upsert record: %w", err)
	}
	return saved, nil
}

func (r *RecordRepository) ListSince(ctx context.Context, ownerID string, sinceVersion int64) ([]domain.Record, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, owner_id, type, encrypted_meta, meta_nonce, ciphertext, nonce, version, updated_at, deleted
		FROM records WHERE owner_id = $1 AND version > $2
		ORDER BY version`,
		ownerID, sinceVersion,
	)
	if err != nil {
		return nil, fmt.Errorf("list records since: %w", err)
	}
	defer rows.Close()

	var result []domain.Record
	for rows.Next() {
		var rec domain.Record
		if err := rows.Scan(
			&rec.ID, &rec.OwnerID, &rec.Type,
			&rec.EncryptedMeta, &rec.MetaNonce,
			&rec.Ciphertext, &rec.Nonce,
			&rec.Version, &rec.UpdatedAt, &rec.Deleted,
		); err != nil {
			return nil, fmt.Errorf("scan record: %w", err)
		}
		result = append(result, rec)
	}
	return result, rows.Err()
}

func (r *RecordRepository) Get(ctx context.Context, id, ownerID string) (domain.Record, error) {
	var rec domain.Record
	err := r.pool.QueryRow(ctx, `
		SELECT id, owner_id, type, encrypted_meta, meta_nonce, ciphertext, nonce, version, updated_at, deleted
		FROM records WHERE id = $1 AND owner_id = $2`,
		id, ownerID,
	).Scan(
		&rec.ID, &rec.OwnerID, &rec.Type,
		&rec.EncryptedMeta, &rec.MetaNonce,
		&rec.Ciphertext, &rec.Nonce,
		&rec.Version, &rec.UpdatedAt, &rec.Deleted,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Record{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.Record{}, fmt.Errorf("get record: %w", err)
	}
	return rec, nil
}

func (r *RecordRepository) Delete(ctx context.Context, id, ownerID string) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE records SET deleted = true, version = nextval('records_version_seq'), updated_at = $1
		WHERE id = $2 AND owner_id = $3`,
		time.Now().UTC(), id, ownerID,
	)
	if err != nil {
		return fmt.Errorf("delete record: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}
