package service

import (
	"context"
	"fmt"

	"github.com/alexvictorne/voldepass/internal/client/storage"
)

// Session объединяет файловое хранилище и dataKey текущей сессии пользователя
// и отвечает за graceful shutdown: сброс состояния на диск и зануление ключа.
type Session struct {
	store   *storage.FileStore
	dataKey []byte
	syncer  *Syncer
}

// NewSession создаёт сессию поверх файлового хранилища и развёрнутого dataKey.
// syncer может быть nil, если финальная синхронизация при закрытии не требуется
// (например, в CLI-командах, не подразумевающих фоновую синхронизацию).
func NewSession(store *storage.FileStore, dataKey []byte, syncer *Syncer) *Session {
	return &Session{store: store, dataKey: dataKey, syncer: syncer}
}

// DataKey возвращает текущий dataKey сессии для использования VaultManager.
func (s *Session) DataKey() []byte {
	return s.dataKey
}

// ClearTokens очищает сохранённые access/refresh токены (локальный logout).
// После этого следующий вход потребует полного challenge-response.
func (s *Session) ClearTokens() {
	s.store.SetTokens("", "")
}

// Close выполняет graceful shutdown: дожидается финальной синхронизации в пределах
// дедлайна ctx (при наличии syncer), сбрасывает in-memory состояние в зашифрованный
// файл и явно зануляет dataKey в памяти (best-effort — Go GC не гарантирует
// отсутствие копий в других местах кучи/стека; полноценная защита памяти вне scope).
func (s *Session) Close(ctx context.Context) error {
	defer zeroBytes(s.dataKey)

	if s.syncer != nil {
		if _, err := s.syncer.Sync(ctx); err != nil {
			// Не блокируем закрытие сессии из-за сетевой ошибки: локальное состояние
			// всё равно должно быть сохранено, следующий запуск досинхронизирует.
			if saveErr := s.store.Save(s.dataKey); saveErr != nil {
				return fmt.Errorf("close session: sync failed (%v), save failed: %w", err, saveErr)
			}
			return fmt.Errorf("close session: final sync failed: %w", err)
		}
	}

	if err := s.store.Save(s.dataKey); err != nil {
		return fmt.Errorf("close session: save storage: %w", err)
	}
	return nil
}

// CloseWithoutSync сохраняет состояние и зануляет dataKey, пропуская финальную
// синхронизацию. Используется, например, после logout — когда токены уже очищены
// и сетевой запрос заведомо провалится аутентификацией.
func (s *Session) CloseWithoutSync() error {
	defer zeroBytes(s.dataKey)
	if err := s.store.Save(s.dataKey); err != nil {
		return fmt.Errorf("close session: save storage: %w", err)
	}
	return nil
}

// zeroBytes перезаписывает буфер нулями.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
