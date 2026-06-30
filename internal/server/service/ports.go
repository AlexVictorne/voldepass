// Пакет service содержит бизнес-логику сервера и объявляет интерфейсы-порты
// (Ports & Adapters). Конкретные адаптеры (postgres, inmem) импортируют этот
// пакет и реализуют интерфейсы; обратная зависимость запрещена.
package service

import (
	"context"
	"time"

	"github.com/alexvictorne/voldepass/internal/domain"
)

// UserRepository — порт доступа к пользователям.
type UserRepository interface {
	// Create сохраняет нового пользователя. Возвращает ErrAlreadyExists, если логин занят.
	Create(ctx context.Context, u domain.User, p domain.Profile) error
	// GetByLogin возвращает пользователя по логину. ErrNotFound, если не найден.
	GetByLogin(ctx context.Context, login string) (domain.User, error)
	// GetByID возвращает пользователя по ID. ErrNotFound, если не найден.
	GetByID(ctx context.Context, id string) (domain.User, error)
	// GetProfile возвращает криптографический профиль пользователя.
	GetProfile(ctx context.Context, userID string) (domain.Profile, error)
	// UpdateProfile обновляет профиль (kdfSalt, wrappedDataKey, kdfParams).
	UpdateProfile(ctx context.Context, p domain.Profile) error
}

// RecordRepository — порт доступа к зашифрованным записям хранилища.
type RecordRepository interface {
	// Upsert создаёт или обновляет запись с optimistic locking по версии.
	// Если baseVersion не совпадает с текущей версией на сервере — возвращает ErrConflict.
	// Сервер проставляет UpdatedAt и инкрементирует Version.
	Upsert(ctx context.Context, r domain.Record, baseVersion int64) (domain.Record, error)
	// ListSince возвращает все записи владельца с Version > sinceVersion.
	ListSince(ctx context.Context, ownerID string, sinceVersion int64) ([]domain.Record, error)
	// Get возвращает запись по ID. ErrNotFound, если не найдена или не принадлежит ownerID.
	Get(ctx context.Context, id, ownerID string) (domain.Record, error)
	// Delete помечает запись как удалённую (tombstone). ErrNotFound, если не найдена.
	Delete(ctx context.Context, id, ownerID string) error
}

// IdempotencyStore — порт хранения ключей идемпотентности для Push-операций.
type IdempotencyStore interface {
	// Get возвращает сохранённый результат по ключу. ErrNotFound, если истёк или не существует.
	Get(ctx context.Context, ownerID, key string) ([]byte, error)
	// Save сохраняет результат под ключом с TTL.
	Save(ctx context.Context, ownerID, key string, result []byte, ttl time.Duration) error
	// DeleteExpired удаляет все записи с истёкшим TTL. Вызывается фоновой горутиной.
	DeleteExpired(ctx context.Context) error
}

// RefreshTokenStore — порт хранения refresh-токенов с поддержкой ротации.
type RefreshTokenStore interface {
	// Save сохраняет новый refresh-токен (хранится хешем).
	Save(ctx context.Context, userID, tokenHash string, expiresAt time.Time) error
	// Get возвращает userID и статус по хешу токена. ErrNotFound, если не найден.
	Get(ctx context.Context, tokenHash string) (userID string, revoked bool, expiresAt time.Time, err error)
	// Rotate инвалидирует oldHash и сохраняет newHash как новый токен.
	Rotate(ctx context.Context, oldHash, newHash, userID string, expiresAt time.Time) error
	// RevokeAll отзывает все токены пользователя (детект кражи).
	RevokeAll(ctx context.Context, userID string) error
}

// LoginAttemptTracker — порт отслеживания неудачных попыток входа для rate-limiting.
type LoginAttemptTracker interface {
	// Allowed возвращает true, если пользователь не превысил лимит попыток.
	Allowed(ctx context.Context, login string) (bool, error)
	// Inc инкрементирует счётчик неудачных попыток для логина.
	Inc(ctx context.Context, login string) error
	// Reset сбрасывает счётчик после успешного входа.
	Reset(ctx context.Context, login string) error
}
