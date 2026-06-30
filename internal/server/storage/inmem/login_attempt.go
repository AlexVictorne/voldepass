package inmem

import (
	"context"
	"sync"
	"time"
)

type attemptEntry struct {
	count     int
	windowEnd time.Time
}

// LoginAttemptTracker — in-memory реализация service.LoginAttemptTracker.
// Скользящее окно: при превышении maxAttempts в течение window вход блокируется.
type LoginAttemptTracker struct {
	mu          sync.Mutex
	attempts    map[string]attemptEntry
	maxAttempts int
	window      time.Duration
}

// NewLoginAttemptTracker создаёт трекер с заданным лимитом и окном блокировки.
func NewLoginAttemptTracker(maxAttempts int, window time.Duration) *LoginAttemptTracker {
	return &LoginAttemptTracker{
		attempts:    make(map[string]attemptEntry),
		maxAttempts: maxAttempts,
		window:      window,
	}
}

func (t *LoginAttemptTracker) Allowed(_ context.Context, login string) (bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	e, ok := t.attempts[login]
	if !ok || time.Now().After(e.windowEnd) {
		return true, nil
	}
	return e.count < t.maxAttempts, nil
}

func (t *LoginAttemptTracker) Inc(_ context.Context, login string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	e, ok := t.attempts[login]
	if !ok || time.Now().After(e.windowEnd) {
		e = attemptEntry{count: 0, windowEnd: time.Now().Add(t.window)}
	}
	e.count++
	t.attempts[login] = e
	return nil
}

func (t *LoginAttemptTracker) Reset(_ context.Context, login string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	delete(t.attempts, login)
	return nil
}
