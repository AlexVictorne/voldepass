package inmem

import (
	"context"
	"sync"
	"time"

	"github.com/alexvictorne/voldepass/internal/domain"
)

type tokenEntry struct {
	userID    string
	expiresAt time.Time
	revoked   bool
}

// RefreshTokenStore — in-memory реализация service.RefreshTokenStore.
type RefreshTokenStore struct {
	mu     sync.Mutex
	tokens map[string]tokenEntry // ключ — token_hash
}

// NewRefreshTokenStore создаёт пустое in-memory хранилище refresh-токенов.
func NewRefreshTokenStore() *RefreshTokenStore {
	return &RefreshTokenStore{
		tokens: make(map[string]tokenEntry),
	}
}

func (s *RefreshTokenStore) Save(_ context.Context, userID, tokenHash string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.tokens[tokenHash] = tokenEntry{userID: userID, expiresAt: expiresAt}
	return nil
}

func (s *RefreshTokenStore) Get(_ context.Context, tokenHash string) (userID string, revoked bool, expiresAt time.Time, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.tokens[tokenHash]
	if !ok {
		return "", false, time.Time{}, domain.ErrNotFound
	}
	return e.userID, e.revoked, e.expiresAt, nil
}

func (s *RefreshTokenStore) Rotate(_ context.Context, oldHash, newHash, userID string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.tokens[oldHash]
	if !ok {
		return domain.ErrNotFound
	}
	e.revoked = true
	s.tokens[oldHash] = e

	s.tokens[newHash] = tokenEntry{userID: userID, expiresAt: expiresAt}
	return nil
}

func (s *RefreshTokenStore) RevokeAll(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for hash, e := range s.tokens {
		if e.userID == userID {
			e.revoked = true
			s.tokens[hash] = e
		}
	}
	return nil
}
