package inmem

import (
	"context"
	"sync"
	"time"

	"github.com/alexvictorne/voldepass/internal/domain"
)

type idempotencyEntry struct {
	result    []byte
	expiresAt time.Time
}

// IdempotencyStore — in-memory реализация service.IdempotencyStore.
type IdempotencyStore struct {
	mu      sync.Mutex
	entries map[string]idempotencyEntry // ключ — ownerID + ":" + key
}

// NewIdempotencyStore создаёт пустое in-memory хранилище ключей идемпотентности.
func NewIdempotencyStore() *IdempotencyStore {
	return &IdempotencyStore{
		entries: make(map[string]idempotencyEntry),
	}
}

func (s *IdempotencyStore) Get(_ context.Context, ownerID, key string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.entries[ownerID+":"+key]
	if !ok || time.Now().After(e.expiresAt) {
		delete(s.entries, ownerID+":"+key)
		return nil, domain.ErrNotFound
	}
	return e.result, nil
}

func (s *IdempotencyStore) Save(_ context.Context, ownerID, key string, result []byte, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.entries[ownerID+":"+key] = idempotencyEntry{
		result:    result,
		expiresAt: time.Now().Add(ttl),
	}
	return nil
}

func (s *IdempotencyStore) DeleteExpired(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for k, e := range s.entries {
		if now.After(e.expiresAt) {
			delete(s.entries, k)
		}
	}
	return nil
}
