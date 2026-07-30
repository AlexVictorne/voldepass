package storage

import (
	"sync"
	"time"

	"github.com/alexvictorne/voldepass/internal/domain"
)

// currentFormatVersion — версия формата файла локального хранилища.
// Меняется при несовместимых изменениях схемы State; см. migrate() в file.go.
const currentFormatVersion = 1

// StoredRecord — запись локального хранилища с метаданными синхронизации.
type StoredRecord struct {
	domain.RecordDTO
	// Dirty — true, если запись изменена локально и ещё не отправлена на сервер.
	Dirty bool `json:"dirty"`
	// DirtyAt — локальное время последнего несинхронизированного изменения (создание/
	// правка/удаление). Используется Syncer для LWW-разрешения конфликтов: сравнивается
	// с серверным RecordDTO.UpdatedAt, а не с клиентскими часами других устройств —
	// сравнение всегда происходит на одном устройстве (это устройство vs серверное время).
	DirtyAt time.Time `json:"dirty_at,omitempty"`
}

// PendingBatch — незавершённый push-батч, персистируемый до получения ACK от сервера.
// Позволяет переиспользовать тот же IdempotencyKey после рестарта клиента.
type PendingBatch struct {
	IdempotencyKey string   `json:"idempotency_key"`
	RecordIDs      []string `json:"record_ids"`
}

// State — полное содержимое локального хранилища клиента.
type State struct {
	// Version — версия формата данной структуры (для миграций).
	Version int `json:"version"`
	// KdfSalt — соль KDF из профиля пользователя.
	KdfSalt []byte `json:"kdf_salt"`
	// KdfParams — параметры Argon2id из профиля пользователя.
	KdfParams domain.KdfParams `json:"kdf_params"`
	// WrappedDataKey — dataKey, обёрнутый encKey (см. internal/client/crypto).
	WrappedDataKey []byte `json:"wrapped_data_key"`
	// AuthToken — текущий access-токен сессии.
	AuthToken string `json:"auth_token"`
	// RefreshToken — текущий refresh-токен сессии.
	RefreshToken string `json:"refresh_token"`
	// LastSyncVersion — курсор последней успешной синхронизации (глобальная версия сервера).
	LastSyncVersion int64 `json:"last_sync_version"`
	// LastSyncAt — время последней успешной синхронизации (для отображения в UI, не участвует в протоколе).
	LastSyncAt time.Time `json:"last_sync_at"`
	// Records — локальные записи, индексированные по ID.
	Records map[string]StoredRecord `json:"records"`
	// PendingPush — незавершённые push-батчи, ожидающие подтверждения сервера.
	PendingPush []PendingBatch `json:"pending_push"`
}

// newEmptyState создаёт пустое состояние текущей версии формата.
func newEmptyState() State {
	return State{
		Version: currentFormatVersion,
		Records: make(map[string]StoredRecord),
	}
}

// Store — потокобезопасная обёртка над State для конкурентного доступа
// (в TUI возможны фоновые операции: live-TOTP, автосинхронизация).
type Store struct {
	mu    sync.RWMutex
	state State
}

// NewStore создаёт пустое in-memory хранилище (без персиста в файл).
// Используется в тестах и как основа для FileStore.
func NewStore() *Store {
	return &Store{state: newEmptyState()}
}

// newStoreFromState создаёт Store с заданным начальным состоянием (например, загруженным из файла).
func newStoreFromState(s State) *Store {
	if s.Records == nil {
		s.Records = make(map[string]StoredRecord)
	}
	return &Store{state: s}
}

// Snapshot возвращает копию текущего состояния для сериализации.
func (s *Store) Snapshot() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return copyState(s.state)
}

// copyState делает поверхностную копию State с глубоким копированием карты Records.
func copyState(s State) State {
	recordsCopy := make(map[string]StoredRecord, len(s.Records))
	for k, v := range s.Records {
		recordsCopy[k] = v
	}
	pendingCopy := make([]PendingBatch, len(s.PendingPush))
	copy(pendingCopy, s.PendingPush)

	return State{
		Version:         s.Version,
		KdfSalt:         s.KdfSalt,
		KdfParams:       s.KdfParams,
		WrappedDataKey:  s.WrappedDataKey,
		AuthToken:       s.AuthToken,
		RefreshToken:    s.RefreshToken,
		LastSyncVersion: s.LastSyncVersion,
		LastSyncAt:      s.LastSyncAt,
		Records:         recordsCopy,
		PendingPush:     pendingCopy,
	}
}

// SetProfile сохраняет криптографический профиль и токены сессии.
func (s *Store) SetProfile(kdfSalt []byte, kdfParams domain.KdfParams, wrappedDataKey []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.KdfSalt = kdfSalt
	s.state.KdfParams = kdfParams
	s.state.WrappedDataKey = wrappedDataKey
}

// SetTokens сохраняет текущие access/refresh токены сессии.
func (s *Store) SetTokens(accessToken, refreshToken string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.AuthToken = accessToken
	s.state.RefreshToken = refreshToken
}

// Tokens возвращает текущие access/refresh токены сессии.
func (s *Store) Tokens() (accessToken, refreshToken string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.AuthToken, s.state.RefreshToken
}

// GetRecord возвращает запись по ID и флаг существования.
func (s *Store) GetRecord(id string) (StoredRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.state.Records[id]
	return r, ok
}

// PutRecord сохраняет или обновляет запись.
func (s *Store) PutRecord(r StoredRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Records[r.ID] = r
}

// DeleteRecord удаляет запись из локального хранилища (не tombstone — физическое удаление
// локальной записи; tombstone-семантика для sync реализуется через StoredRecord.IsDeleted).
func (s *Store) DeleteRecord(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.state.Records, id)
}

// ListRecords возвращает все локальные записи.
func (s *Store) ListRecords() []StoredRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]StoredRecord, 0, len(s.state.Records))
	for _, r := range s.state.Records {
		result = append(result, r)
	}
	return result
}

// ListDirty возвращает все записи с несинхронизированными локальными изменениями.
func (s *Store) ListDirty() []StoredRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []StoredRecord
	for _, r := range s.state.Records {
		if r.Dirty {
			result = append(result, r)
		}
	}
	return result
}

// LastSyncVersion возвращает курсор последней успешной синхронизации.
func (s *Store) LastSyncVersion() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.LastSyncVersion
}

// SetLastSyncVersion обновляет курсор последней успешной синхронизации.
func (s *Store) SetLastSyncVersion(v int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.LastSyncVersion = v
}

// LastSyncAt возвращает время последней успешной синхронизации (нулевое значение — ни разу не синхронизировано).
func (s *Store) LastSyncAt() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.LastSyncAt
}

// SetLastSyncAt обновляет время последней успешной синхронизации.
func (s *Store) SetLastSyncAt(t time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.LastSyncAt = t
}

// AddPendingPush сохраняет незавершённый push-батч (до получения ACK от сервера).
func (s *Store) AddPendingPush(b PendingBatch) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.PendingPush = append(s.state.PendingPush, b)
}

// ClearPendingPush удаляет батч по IdempotencyKey после получения ACK.
func (s *Store) ClearPendingPush(idempotencyKey string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	filtered := s.state.PendingPush[:0]
	for _, b := range s.state.PendingPush {
		if b.IdempotencyKey != idempotencyKey {
			filtered = append(filtered, b)
		}
	}
	s.state.PendingPush = filtered
}

// PendingPushes возвращает все незавершённые push-батчи.
func (s *Store) PendingPushes() []PendingBatch {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]PendingBatch, len(s.state.PendingPush))
	copy(result, s.state.PendingPush)
	return result
}
