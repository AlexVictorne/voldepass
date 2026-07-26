package domain

import "time"

// User — зарегистрированный пользователь системы.
type User struct {
	// ID — уникальный идентификатор пользователя (UUID v4).
	ID string
	// Login — уникальный логин пользователя.
	Login string
	// AuthVerifier — верификатор authKey для challenge-response аутентификации.
	// Хранится как bcrypt-независимое значение: HMAC-ключ, защищённый Argon2id.
	// Подробнее см. internal/server/auth.
	AuthVerifier []byte
	// CreatedAt — время регистрации пользователя.
	CreatedAt time.Time
}

// Profile — криптографический профиль пользователя, хранящийся на сервере.
// Необходим для синхронизации нескольких клиентов одного пользователя:
// любой авторизованный клиент получает Profile при логине и самостоятельно
// восстанавливает dataKey из мастер-пароля.
type Profile struct {
	// UserID — идентификатор пользователя, которому принадлежит профиль.
	UserID string
	// KdfSalt — случайная соль для вывода ключей через Argon2id.
	KdfSalt []byte
	// KdfParams — параметры Argon2id, использованные при создании/обновлении профиля.
	// Хранение параметров рядом с профилем позволяет усиливать KDF для новых
	// пользователей без затрагивания существующих.
	KdfParams KdfParams
	// WrappedDataKey — dataKey, зашифрованный encKey'ом (key-wrapping AES-GCM).
	// encKey никогда не покидает клиент; сервер не может расшифровать WrappedDataKey
	// без знания мастер-пароля пользователя.
	WrappedDataKey []byte
	// ProfileVersion — версия формата профиля. Используется при миграции
	// ключевого материала (например, при переходе на новые параметры KDF).
	ProfileVersion int
}

// KdfParams — параметры функции вывода ключей Argon2id.
type KdfParams struct {
	// Time — количество итераций Argon2id.
	Time uint32
	// Memory — объём памяти в KiB.
	Memory uint32
	// Threads — число параллельных потоков.
	Threads uint8
	// KeyLen — длина выводимого ключа в байтах.
	KeyLen uint32
}

// DefaultKdfParams возвращает рекомендуемые параметры Argon2id согласно
// рекомендациям OWASP (2024): минимум 19 MiB памяти, 2 итерации.
func DefaultKdfParams() KdfParams {
	return KdfParams{
		Time:    2,
		Memory:  64 * 1024, // 64 MiB
		Threads: 4,
		KeyLen:  32,
	}
}
