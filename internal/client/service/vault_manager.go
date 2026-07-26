package service

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/alexvictorne/voldepass/internal/client/crypto"
	"github.com/alexvictorne/voldepass/internal/client/storage"
	"github.com/alexvictorne/voldepass/internal/domain"
)

// VaultManager шифрует/дешифрует записи хранилища и работает с локальным
// состоянием офлайн-first: изменения помечаются Dirty и синхронизируются
// на сервер отдельно через Syncer.
type VaultManager struct {
	store   *storage.Store
	dataKey []byte
}

// NewVaultManager создаёт менеджер хранилища с уже развёрнутым dataKey (см. AuthFlow).
func NewVaultManager(store *storage.Store, dataKey []byte) *VaultManager {
	return &VaultManager{store: store, dataKey: dataKey}
}

// Create шифрует payload и необязательную meta-строку, сохраняет новую запись локально
// как Dirty (ожидает push через Syncer).
func (v *VaultManager) Create(dataType domain.DataType, meta string, payload any) (domain.RecordDTO, error) {
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return domain.RecordDTO{}, fmt.Errorf("marshal payload: %w", err)
	}

	ciphertext, nonce, err := crypto.Encrypt(v.dataKey, plaintext)
	if err != nil {
		return domain.RecordDTO{}, fmt.Errorf("encrypt payload: %w", err)
	}

	var encMeta, metaNonce []byte
	if meta != "" {
		encMeta, metaNonce, err = crypto.Encrypt(v.dataKey, []byte(meta))
		if err != nil {
			return domain.RecordDTO{}, fmt.Errorf("encrypt meta: %w", err)
		}
	}

	dto := domain.RecordDTO{
		ID:            uuid.NewString(),
		Type:          dataType,
		EncryptedMeta: encMeta,
		MetaNonce:     metaNonce,
		Ciphertext:    ciphertext,
		Nonce:         nonce,
	}
	v.store.PutRecord(storage.StoredRecord{RecordDTO: dto, Dirty: true})
	return dto, nil
}

// Update перешифровывает payload/meta существующей записи и помечает её Dirty.
// BaseVersion устанавливается в текущую известную серверную версию для optimistic locking при push.
func (v *VaultManager) Update(id string, meta string, payload any) (domain.RecordDTO, error) {
	existing, ok := v.store.GetRecord(id)
	if !ok {
		return domain.RecordDTO{}, fmt.Errorf("%w: record %s", domain.ErrNotFound, id)
	}

	plaintext, err := json.Marshal(payload)
	if err != nil {
		return domain.RecordDTO{}, fmt.Errorf("marshal payload: %w", err)
	}
	ciphertext, nonce, err := crypto.Encrypt(v.dataKey, plaintext)
	if err != nil {
		return domain.RecordDTO{}, fmt.Errorf("encrypt payload: %w", err)
	}

	var encMeta, metaNonce []byte
	if meta != "" {
		encMeta, metaNonce, err = crypto.Encrypt(v.dataKey, []byte(meta))
		if err != nil {
			return domain.RecordDTO{}, fmt.Errorf("encrypt meta: %w", err)
		}
	}

	dto := existing.RecordDTO
	dto.EncryptedMeta = encMeta
	dto.MetaNonce = metaNonce
	dto.Ciphertext = ciphertext
	dto.Nonce = nonce
	dto.BaseVersion = existing.Version

	v.store.PutRecord(storage.StoredRecord{RecordDTO: dto, Dirty: true})
	return dto, nil
}

// Delete помечает запись как tombstone (IsDeleted=true) и Dirty для последующего push.
// Запись не удаляется физически из локального хранилища до подтверждения сервером,
// чтобы Syncer мог отправить delete как обычное изменение.
func (v *VaultManager) Delete(id string) error {
	existing, ok := v.store.GetRecord(id)
	if !ok {
		return fmt.Errorf("%w: record %s", domain.ErrNotFound, id)
	}
	existing.IsDeleted = true
	existing.BaseVersion = existing.Version
	existing.Dirty = true
	v.store.PutRecord(existing)
	return nil
}

// Get возвращает расшифрованные meta и payload записи по ID.
// target — указатель на структуру нужного типа payload (например, *domain.CredentialsPayload).
func (v *VaultManager) Get(id string, target any) (meta string, dto domain.RecordDTO, err error) {
	rec, ok := v.store.GetRecord(id)
	if !ok {
		return "", domain.RecordDTO{}, fmt.Errorf("%w: record %s", domain.ErrNotFound, id)
	}

	plaintext, err := crypto.Decrypt(v.dataKey, rec.Ciphertext, rec.Nonce)
	if err != nil {
		return "", domain.RecordDTO{}, fmt.Errorf("decrypt payload: %w", err)
	}
	if target != nil {
		if err := json.Unmarshal(plaintext, target); err != nil {
			return "", domain.RecordDTO{}, fmt.Errorf("unmarshal payload: %w", err)
		}
	}

	if len(rec.EncryptedMeta) > 0 {
		metaBytes, err := crypto.Decrypt(v.dataKey, rec.EncryptedMeta, rec.MetaNonce)
		if err != nil {
			return "", domain.RecordDTO{}, fmt.Errorf("decrypt meta: %w", err)
		}
		meta = string(metaBytes)
	}

	return meta, rec.RecordDTO, nil
}

// Import добавляет уже зашифрованные тем же dataKey записи (например, из
// ExportBundle) в локальное хранилище и помечает их Dirty для последующей
// отправки на сервер — импортированные данные могли не существовать на сервере.
func (v *VaultManager) Import(records []domain.RecordDTO) {
	for _, dto := range records {
		dto.BaseVersion = dto.Version
		v.store.PutRecord(storage.StoredRecord{RecordDTO: dto, Dirty: true})
	}
}

// LastSyncAt возвращает время последней успешной синхронизации, персистированное
// в локальном хранилище (нулевое значение — синхронизация ещё не выполнялась).
func (v *VaultManager) LastSyncAt() time.Time {
	return v.store.LastSyncAt()
}

// List возвращает все локальные записи, не помеченные как удалённые.
func (v *VaultManager) List() []domain.RecordDTO {
	all := v.store.ListRecords()
	result := make([]domain.RecordDTO, 0, len(all))
	for _, r := range all {
		if !r.IsDeleted {
			result = append(result, r.RecordDTO)
		}
	}
	return result
}
