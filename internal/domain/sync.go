package domain

import "time"

// RecordDTO — транспортное представление записи, используемое в Sync API.
// Поля Ciphertext, Nonce, EncryptedMeta, MetaNonce передаются как base64
// на уровне JSON-сериализации (обеспечивается тегами `json`).
type RecordDTO struct {
	// ID — уникальный идентификатор записи.
	ID string `json:"id"`
	// Type — тип данных (открытое поле).
	Type DataType `json:"type"`
	// EncryptedMeta — зашифрованная метаинформация.
	EncryptedMeta []byte `json:"encrypted_meta,omitempty"`
	// MetaNonce — nonce для EncryptedMeta.
	MetaNonce []byte `json:"meta_nonce,omitempty"`
	// Ciphertext — зашифрованный payload.
	Ciphertext []byte `json:"ciphertext"`
	// Nonce — nonce для Ciphertext.
	Nonce []byte `json:"nonce"`
	// BaseVersion — версия, на основе которой сделано изменение.
	// Используется сервером для optimistic locking при Push.
	// При Pull это поле игнорируется (сервер заполняет Version).
	BaseVersion int64 `json:"base_version,omitempty"`
	// Version — текущая версия записи на сервере (заполняется сервером).
	Version int64 `json:"version"`
	// UpdatedAt — время последнего изменения (проставляется сервером).
	UpdatedAt time.Time `json:"updated_at"`
	// IsDeleted — true, если запись помечена как удалённая (tombstone).
	IsDeleted bool `json:"is_deleted,omitempty"`
}

// SyncPullResponse — ответ сервера на запрос Pull (GET /api/v1/sync?since=<version>).
// Содержит все записи, изменённые после указанной версии.
type SyncPullResponse struct {
	// Records — список изменённых записей.
	Records []RecordDTO `json:"records"`
}

// SyncPushRequest — тело запроса Push (POST /api/v1/sync).
// Клиент передаёт все локально изменённые (Dirty) записи.
type SyncPushRequest struct {
	// Records — список записей для синхронизации.
	Records []RecordDTO `json:"records"`
}

// PushStatus — результат применения одной записи при Push.
type PushStatus string

const (
	// PushStatusApplied — запись успешно применена на сервере.
	PushStatusApplied PushStatus = "applied"
	// PushStatusConflict — обнаружен конфликт версий; серверная версия возвращается в ServerRecord.
	PushStatusConflict PushStatus = "conflict"
)

// PushResult — результат применения одной записи из SyncPushRequest.
type PushResult struct {
	// ID — идентификатор записи.
	ID string `json:"id"`
	// Status — applied или conflict.
	Status PushStatus `json:"status"`
	// ServerRecord — актуальная версия записи с сервера.
	// Заполняется всегда: при applied — обновлённая запись, при conflict — существующая.
	ServerRecord RecordDTO `json:"server_record"`
}

// SyncPushResponse — ответ сервера на запрос Push.
type SyncPushResponse struct {
	// Results — результат для каждой записи из запроса.
	Results []PushResult `json:"results"`
}
