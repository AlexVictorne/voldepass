// Пакет inmem содержит in-memory реализации портов хранилища для использования в тестах.
// Все реализации потокобезопасны (sync.RWMutex).
package inmem

import (
	"context"
	"sync"

	"github.com/alexvictorne/voldepass/internal/domain"
)

// UserRepository — in-memory реализация service.UserRepository.
type UserRepository struct {
	mu       sync.RWMutex
	byID     map[string]domain.User
	byLogin  map[string]domain.User
	profiles map[string]domain.Profile
}

// NewUserRepository создаёт пустое in-memory хранилище пользователей.
func NewUserRepository() *UserRepository {
	return &UserRepository{
		byID:     make(map[string]domain.User),
		byLogin:  make(map[string]domain.User),
		profiles: make(map[string]domain.Profile),
	}
}

func (r *UserRepository) Create(_ context.Context, u domain.User, p domain.Profile) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.byLogin[u.Login]; exists {
		return domain.ErrAlreadyExists
	}
	r.byID[u.ID] = u
	r.byLogin[u.Login] = u
	r.profiles[u.ID] = p
	return nil
}

func (r *UserRepository) GetByLogin(_ context.Context, login string) (domain.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	u, ok := r.byLogin[login]
	if !ok {
		return domain.User{}, domain.ErrNotFound
	}
	return u, nil
}

func (r *UserRepository) GetByID(_ context.Context, id string) (domain.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	u, ok := r.byID[id]
	if !ok {
		return domain.User{}, domain.ErrNotFound
	}
	return u, nil
}

func (r *UserRepository) GetProfile(_ context.Context, userID string) (domain.Profile, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	p, ok := r.profiles[userID]
	if !ok {
		return domain.Profile{}, domain.ErrNotFound
	}
	return p, nil
}

func (r *UserRepository) UpdateProfile(_ context.Context, p domain.Profile) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.byID[p.UserID]; !ok {
		return domain.ErrNotFound
	}
	r.profiles[p.UserID] = p
	return nil
}
