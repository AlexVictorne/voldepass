package domain

import "time"

// Record — основная хранимая сущность. Сервер видит только зашифрованные поля;
// открытым остаётся только Type (нужен для фильтрации и индексации).
type Record struct {
	// ID — уникальный идентификатор записи (UUID v4).
	ID string
	// OwnerID — идентификатор пользователя-владельца.
	OwnerID string
	// Type — тип данных (открытое поле).
	Type DataType
	// EncryptedMeta — зашифрованная метаинформация (метка, URL, заметки).
	// Шифруется dataKey с отдельным nonce (MetaNonce).
	EncryptedMeta []byte
	// MetaNonce — nonce для расшифровки EncryptedMeta.
	MetaNonce []byte
	// Ciphertext — зашифрованный payload (собственно данные записи).
	Ciphertext []byte
	// Nonce — nonce для расшифровки Ciphertext.
	Nonce []byte
	// Version — монотонно возрастающий счётчик версий.
	// Используется для optimistic locking при синхронизации.
	Version int64
	// UpdatedAt — время последнего изменения, проставляется сервером.
	UpdatedAt time.Time
	// Deleted — флаг tombstone: запись помечена как удалённая, но хранится
	// для корректной синхронизации между устройствами.
	Deleted bool
}
