package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alexvictorne/voldepass/internal/domain"
)

// UserRepository — postgres-реализация service.UserRepository.
type UserRepository struct {
	pool *pgxpool.Pool
}

// NewUserRepository создаёт postgres-репозиторий пользователей.
func NewUserRepository(pool *pgxpool.Pool) *UserRepository {
	return &UserRepository{pool: pool}
}

func (r *UserRepository) Create(ctx context.Context, u domain.User, p domain.Profile) error {
	kdfParamsJSON, err := json.Marshal(p.KdfParams)
	if err != nil {
		return fmt.Errorf("marshal kdf_params: %w", err)
	}

	_, err = r.pool.Exec(ctx, `
		INSERT INTO users
			(id, login, auth_verifier, kdf_salt, kdf_params, wrapped_data_key, profile_version, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		u.ID, u.Login, u.AuthVerifier,
		p.KdfSalt, kdfParamsJSON, p.WrappedDataKey, p.ProfileVersion,
		u.CreatedAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return domain.ErrAlreadyExists
		}
		return fmt.Errorf("insert user: %w", err)
	}
	return nil
}

func (r *UserRepository) GetByLogin(ctx context.Context, login string) (domain.User, error) {
	return r.scanUser(ctx, `SELECT id, login, auth_verifier, created_at FROM users WHERE login = $1`, login)
}

func (r *UserRepository) GetByID(ctx context.Context, id string) (domain.User, error) {
	return r.scanUser(ctx, `SELECT id, login, auth_verifier, created_at FROM users WHERE id = $1`, id)
}

func (r *UserRepository) scanUser(ctx context.Context, query string, arg any) (domain.User, error) {
	var u domain.User
	err := r.pool.QueryRow(ctx, query, arg).Scan(&u.ID, &u.Login, &u.AuthVerifier, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.User{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.User{}, fmt.Errorf("query user: %w", err)
	}
	return u, nil
}

func (r *UserRepository) GetProfile(ctx context.Context, userID string) (domain.Profile, error) {
	var p domain.Profile
	var kdfParamsJSON []byte
	p.UserID = userID

	err := r.pool.QueryRow(ctx, `
		SELECT kdf_salt, kdf_params, wrapped_data_key, profile_version
		FROM users WHERE id = $1`, userID,
	).Scan(&p.KdfSalt, &kdfParamsJSON, &p.WrappedDataKey, &p.ProfileVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Profile{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.Profile{}, fmt.Errorf("query profile: %w", err)
	}

	if err := json.Unmarshal(kdfParamsJSON, &p.KdfParams); err != nil {
		return domain.Profile{}, fmt.Errorf("unmarshal kdf_params: %w", err)
	}
	return p, nil
}

func (r *UserRepository) UpdateProfile(ctx context.Context, p domain.Profile) error {
	kdfParamsJSON, err := json.Marshal(p.KdfParams)
	if err != nil {
		return fmt.Errorf("marshal kdf_params: %w", err)
	}

	tag, err := r.pool.Exec(ctx, `
		UPDATE users SET kdf_salt=$1, kdf_params=$2, wrapped_data_key=$3, profile_version=$4
		WHERE id=$5`,
		p.KdfSalt, kdfParamsJSON, p.WrappedDataKey, p.ProfileVersion, p.UserID,
	)
	if err != nil {
		return fmt.Errorf("update profile: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}
