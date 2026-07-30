package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"sync"
	"time"
)

// challengeEntry хранит nonce и время его истечения.
type challengeEntry struct {
	nonce     string
	expiresAt time.Time
}

// ChallengeStore генерирует и хранит одноразовые serverNonce для challenge-response.
// Каждый nonce может быть использован ровно один раз (погашение после чтения).
type ChallengeStore struct {
	mu         sync.Mutex
	challenges map[string]challengeEntry // ключ — login
	ttl        time.Duration
}

// NewChallengeStore создаёт хранилище challenge с заданным TTL nonce.
func NewChallengeStore(ttl time.Duration) *ChallengeStore {
	return &ChallengeStore{
		challenges: make(map[string]challengeEntry),
		ttl:        ttl,
	}
}

// Issue генерирует новый serverNonce для логина и сохраняет его с TTL.
// Перезаписывает предыдущий challenge для того же логина.
func (s *ChallengeStore) Issue(login string) (nonce string, err error) {
	raw := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	nonce = hex.EncodeToString(raw)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.challenges[login] = challengeEntry{
		nonce:     nonce,
		expiresAt: time.Now().Add(s.ttl),
	}
	return nonce, nil
}

// Consume возвращает nonce для логина и немедленно его удаляет (одноразовое использование).
// Возвращает ошибку, если challenge не существует или истёк TTL.
func (s *ChallengeStore) Consume(login string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.challenges[login]
	if !ok {
		return "", fmt.Errorf("no challenge for login %q", login)
	}
	delete(s.challenges, login)

	if time.Now().After(e.expiresAt) {
		return "", fmt.Errorf("challenge expired for login %q", login)
	}
	return e.nonce, nil
}
