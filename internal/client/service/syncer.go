package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/alexvictorne/voldepass/internal/client/storage"
	"github.com/alexvictorne/voldepass/internal/domain"
)

// defaultChunkSize — количество записей в одном push-запросе по умолчанию.
const defaultChunkSize = 100

// defaultMaxIterations — предел итераций цикла pull→push→pull для сходимости
// при конфликтах, защита от бесконечного цикла.
const defaultMaxIterations = 5

// syncTransport — минимальный интерфейс transport.Client, требуемый Syncer.
type syncTransport interface {
	Pull(ctx context.Context, sinceVersion int64) (domain.SyncPullResponse, error)
	Push(ctx context.Context, idempotencyKey string, req domain.SyncPushRequest) (domain.SyncPushResponse, error)
}

// Syncer реализует алгоритм синхронизации: Pull (fast-forward/конфликт) →
// разрешение конфликтов (delete-wins для tombstone-случаев, иначе LWW по
// серверному UpdatedAt + conflict-копия проигравшей стороны) → Push (idempotent,
// chunked) → повтор при остаточных конфликтах до сходимости.
type Syncer struct {
	transport     syncTransport
	store         *storage.Store
	chunkSize     int
	maxIterations int
}

// NewSyncer создаёт Syncer с параметрами чанкинга и предела итераций по умолчанию.
func NewSyncer(t syncTransport, store *storage.Store) *Syncer {
	return &Syncer{
		transport:     t,
		store:         store,
		chunkSize:     defaultChunkSize,
		maxIterations: defaultMaxIterations,
	}
}

// WithChunkSize переопределяет размер чанка push-запроса (используется в тестах).
func (s *Syncer) WithChunkSize(n int) *Syncer {
	s.chunkSize = n
	return s
}

// WithMaxIterations переопределяет предел итераций цикла сходимости (используется в тестах).
func (s *Syncer) WithMaxIterations(n int) *Syncer {
	s.maxIterations = n
	return s
}

// Sync выполняет полный цикл синхронизации: сначала дозавершает незавершённые
// push-батчи с прошлого запуска (переиспользуя их idempotency key), затем
// повторяет pull→push до сходимости или исчерпания maxIterations.
// Возвращает записи, оставшиеся в конфликте после исчерпания попыток.
func (s *Syncer) Sync(ctx context.Context) ([]domain.RecordDTO, error) {
	conflicts, err := s.sync(ctx)
	if err != nil {
		return nil, err
	}
	// Время фиксируется при любом успешном завершении цикла, включая случай,
	// когда остались неразрешённые конфликты — сама синхронизация (pull+push) прошла.
	s.store.SetLastSyncAt(time.Now())
	return conflicts, nil
}

func (s *Syncer) sync(ctx context.Context) ([]domain.RecordDTO, error) {
	if err := s.replayPending(ctx); err != nil {
		return nil, fmt.Errorf("sync: replay pending push: %w", err)
	}

	for i := 0; i < s.maxIterations; i++ {
		if err := s.pull(ctx); err != nil {
			return nil, fmt.Errorf("sync: pull: %w", err)
		}

		dirty := s.store.ListDirty()
		if len(dirty) == 0 {
			return nil, nil
		}

		hadConflicts, err := s.pushAll(ctx, dirty)
		if err != nil {
			return nil, fmt.Errorf("sync: push: %w", err)
		}
		if !hadConflicts {
			return nil, nil
		}
	}

	return s.remainingConflicts(), nil
}

// pull запрашивает изменения с сервера начиная с LastSyncVersion и мержит их
// в локальное состояние: fast-forward для не-Dirty записей, разрешение конфликта
// для Dirty (см. resolveConflict).
func (s *Syncer) pull(ctx context.Context) error {
	resp, err := s.transport.Pull(ctx, s.store.LastSyncVersion())
	if err != nil {
		return err
	}

	maxVersion := s.store.LastSyncVersion()
	for _, incoming := range resp.Records {
		local, exists := s.store.GetRecord(incoming.ID)

		if exists && local.Dirty {
			s.resolveConflict(local, incoming)
		} else {
			s.store.PutRecord(storage.StoredRecord{RecordDTO: incoming, Dirty: false})
		}

		if incoming.Version > maxVersion {
			maxVersion = incoming.Version
		}
	}
	s.store.SetLastSyncVersion(maxVersion)
	return nil
}

// resolveConflict разрешает конфликт между локально изменённой (Dirty) записью и
// одновременно изменённой на сервере — согласно стратегии:
//  1. Delete-wins: если ровно одна из сторон — tombstone (delete), она побеждает
//     безусловно, независимо от времени изменения (устаревший update не должен
//     воскрешать удалённую запись, и наоборот — обновление после чужого delete не
//     должно тихо потеряться, поэтому проигравшая сторона сохраняется conflict-копией).
//  2. Иначе (оба update, либо оба delete — тривиально совпадают) — LWW по серверному
//     RecordDTO.UpdatedAt против локального времени изменения (DirtyAt): кто позже,
//     тот и канон. Проигравшая локальная версия сохраняется conflict-копией только
//     когда побеждает сервер; если побеждает локальная — она остаётся Dirty и будет
//     дослана на следующем push (BaseVersion при этом обновляется до серверной
//     версии, иначе push отклонится сервером как основанный на устаревшей версии).
func (s *Syncer) resolveConflict(local storage.StoredRecord, incoming domain.RecordDTO) {
	switch {
	case local.IsDeleted && !incoming.IsDeleted:
		// Локальный delete побеждает, но серверный update не должен пропасть бесследно —
		// сохраняем его отдельной (dirty) записью, чтобы он тоже дошёл до сервера при push.
		s.saveConflictCopyFromDTO(incoming)
		local.BaseVersion = incoming.Version
		s.store.PutRecord(local)
	case !local.IsDeleted && incoming.IsDeleted:
		s.saveConflictCopy(local)
		s.store.PutRecord(storage.StoredRecord{RecordDTO: incoming, Dirty: false})
	case incoming.UpdatedAt.After(local.DirtyAt):
		s.saveConflictCopy(local)
		s.store.PutRecord(storage.StoredRecord{RecordDTO: incoming, Dirty: false})
	default:
		local.BaseVersion = incoming.Version
		s.store.PutRecord(local)
	}
}

// saveConflictCopy сохраняет проигравшую локальную dirty-версию отдельной записью
// (новый ID, BaseVersion сброшен — уйдёт как create при следующем push), чтобы
// данные пользователя не терялись при разрешении конфликта не в её пользу.
func (s *Syncer) saveConflictCopy(local storage.StoredRecord) {
	conflictCopy := local
	conflictCopy.ID = uuid.NewString()
	conflictCopy.BaseVersion = 0
	s.store.PutRecord(conflictCopy)
}

// saveConflictCopyFromDTO — как saveConflictCopy, но для проигравшей серверной
// записи (а не локальной): помечается Dirty, чтобы уйти на сервер как новая
// запись при следующем push, а не остаться только в локальном кэше.
func (s *Syncer) saveConflictCopyFromDTO(dto domain.RecordDTO) {
	dto.ID = uuid.NewString()
	dto.BaseVersion = 0
	s.store.PutRecord(storage.StoredRecord{RecordDTO: dto, Dirty: true, DirtyAt: time.Now()})
}

// pushAll отправляет dirty-записи чанками с персистентным idempotency key на чанк.
// Возвращает true, если хотя бы один чанк содержал конфликт (требуется повторный pull→push).
func (s *Syncer) pushAll(ctx context.Context, dirty []storage.StoredRecord) (hadConflicts bool, err error) {
	for _, chunk := range chunkRecords(dirty, s.chunkSize) {
		idempotencyKey := uuid.NewString()
		ids := recordIDs(chunk)
		s.store.AddPendingPush(storage.PendingBatch{IdempotencyKey: idempotencyKey, RecordIDs: ids})

		req := domain.SyncPushRequest{Records: make([]domain.RecordDTO, len(chunk))}
		for i, r := range chunk {
			req.Records[i] = r.RecordDTO
		}

		resp, err := s.transport.Push(ctx, idempotencyKey, req)
		if err != nil {
			return false, err
		}

		if s.applyPushResults(resp) {
			hadConflicts = true
		}
		s.store.ClearPendingPush(idempotencyKey)
	}
	return hadConflicts, nil
}

// applyPushResults применяет результаты push к локальному хранилищу.
// Также продвигает LastSyncVersion до максимальной применённой версии — иначе
// следующий Pull заново вытянет только что запушенные записи как "чужие"
// изменения и создаст ложный конфликт с уже неактуальной локальной dirty-копией.
// Возвращает true, если среди результатов были конфликты.
func (s *Syncer) applyPushResults(resp domain.SyncPushResponse) (hadConflicts bool) {
	maxVersion := s.store.LastSyncVersion()
	for _, result := range resp.Results {
		if result.Status == domain.PushStatusApplied {
			s.store.PutRecord(storage.StoredRecord{RecordDTO: result.ServerRecord, Dirty: false})
			if result.ServerRecord.Version > maxVersion {
				maxVersion = result.ServerRecord.Version
			}
		} else {
			hadConflicts = true
		}
	}
	s.store.SetLastSyncVersion(maxVersion)
	return hadConflicts
}

// replayPending дозавершает push-батчи, персистированные до крэша/рестарта клиента,
// переиспользуя тот же idempotency key — сервер вернёт сохранённый результат без
// повторного применения upsert.
func (s *Syncer) replayPending(ctx context.Context) error {
	for _, batch := range s.store.PendingPushes() {
		req := domain.SyncPushRequest{}
		for _, id := range batch.RecordIDs {
			if rec, ok := s.store.GetRecord(id); ok {
				req.Records = append(req.Records, rec.RecordDTO)
			}
		}
		if len(req.Records) == 0 {
			s.store.ClearPendingPush(batch.IdempotencyKey)
			continue
		}

		resp, err := s.transport.Push(ctx, batch.IdempotencyKey, req)
		if err != nil {
			return err
		}
		s.applyPushResults(resp)
		s.store.ClearPendingPush(batch.IdempotencyKey)
	}
	return nil
}

// remainingConflicts возвращает записи, всё ещё помеченные Dirty после исчерпания
// попыток сходимости — их разрешение отдаётся на откуп пользователю.
func (s *Syncer) remainingConflicts() []domain.RecordDTO {
	dirty := s.store.ListDirty()
	result := make([]domain.RecordDTO, len(dirty))
	for i, r := range dirty {
		result[i] = r.RecordDTO
	}
	return result
}

// chunkRecords разбивает записи на чанки не более size элементов (>=1).
func chunkRecords(records []storage.StoredRecord, size int) [][]storage.StoredRecord {
	if size <= 0 {
		size = defaultChunkSize
	}
	var chunks [][]storage.StoredRecord
	for i := 0; i < len(records); i += size {
		end := i + size
		if end > len(records) {
			end = len(records)
		}
		chunks = append(chunks, records[i:end])
	}
	return chunks
}

// recordIDs извлекает ID из списка StoredRecord.
func recordIDs(records []storage.StoredRecord) []string {
	ids := make([]string, len(records))
	for i, r := range records {
		ids[i] = r.ID
	}
	return ids
}
