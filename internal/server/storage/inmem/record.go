package inmem

import (
	"context"
	"sync"
	"time"

	"github.com/alexvictorne/voldepass/internal/domain"
)

// RecordRepository — in-memory реализация service.RecordRepository.
// Версии монотонно растут через глобальный счётчик репозитория, как в postgres-sequence,
// что позволяет корректно работать ListSince: каждый upsert получает уникальную версию.
type RecordRepository struct {
	mu      sync.RWMutex
	records map[string]domain.Record // ключ — record ID
	seq     int64                    // глобальный монотонный счётчик версий
}

// NewRecordRepository создаёт пустое in-memory хранилище записей.
func NewRecordRepository() *RecordRepository {
	return &RecordRepository{
		records: make(map[string]domain.Record),
	}
}

func (r *RecordRepository) Upsert(_ context.Context, rec domain.Record, baseVersion int64) (domain.Record, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	existing, exists := r.records[rec.ID]
	if exists && existing.Version != baseVersion {
		return existing, domain.ErrConflict
	}

	r.seq++
	rec.Version = r.seq
	rec.UpdatedAt = time.Now().UTC()
	r.records[rec.ID] = rec
	return rec, nil
}

func (r *RecordRepository) ListSince(_ context.Context, ownerID string, sinceVersion int64) ([]domain.Record, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []domain.Record
	for _, rec := range r.records {
		if rec.OwnerID == ownerID && rec.Version > sinceVersion {
			result = append(result, rec)
		}
	}
	return result, nil
}

func (r *RecordRepository) Get(_ context.Context, id, ownerID string) (domain.Record, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rec, ok := r.records[id]
	if !ok || rec.OwnerID != ownerID {
		return domain.Record{}, domain.ErrNotFound
	}
	return rec, nil
}

func (r *RecordRepository) Delete(_ context.Context, id, ownerID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	rec, ok := r.records[id]
	if !ok || rec.OwnerID != ownerID {
		return domain.ErrNotFound
	}
	r.seq++
	rec.Deleted = true
	rec.Version = r.seq
	rec.UpdatedAt = time.Now().UTC()
	r.records[id] = rec
	return nil
}
