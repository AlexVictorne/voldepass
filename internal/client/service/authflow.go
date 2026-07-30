package service

import (
	"context"
	"fmt"

	"github.com/alexvictorne/voldepass/internal/client/crypto"
	"github.com/alexvictorne/voldepass/internal/client/storage"
	"github.com/alexvictorne/voldepass/internal/client/transport"
	"github.com/alexvictorne/voldepass/internal/domain"
)

// authTransport — минимальный интерфейс transport.Client, требуемый AuthFlow.
type authTransport interface {
	Register(ctx context.Context, login string, authVerifier []byte, profile domain.Profile) error
	Challenge(ctx context.Context, login string) (transport.ChallengeResult, error)
	Login(ctx context.Context, login string, authMsg []byte) error
	Tokens() (accessToken, refreshToken string)
}

// AuthFlow реализует регистрацию и вход: деривацию ключей из мастер-пароля
// и key-wrapping dataKey. encKey существует только на время вызова и не сохраняется.
type AuthFlow struct {
	transport authTransport
	store     *storage.Store
}

// NewAuthFlow создаёт AuthFlow поверх транспорта и локального хранилища.
func NewAuthFlow(t authTransport, store *storage.Store) *AuthFlow {
	return &AuthFlow{transport: t, store: store}
}

// Register создаёт нового пользователя: генерирует соль и dataKey, оборачивает
// dataKey ключом encKey (выведенным из мастер-пароля) и отправляет профиль на сервер.
// Возвращает dataKey для немедленного использования VaultManager без повторного login.
func (a *AuthFlow) Register(ctx context.Context, login, masterPassword string) (dataKey []byte, err error) {
	salt, err := crypto.GenerateSalt()
	if err != nil {
		return nil, fmt.Errorf("register: %w", err)
	}
	params := domain.DefaultKdfParams()
	authKey, encKey := crypto.DeriveKeys(masterPassword, salt, params)

	dataKey, err = crypto.GenerateDataKey()
	if err != nil {
		return nil, fmt.Errorf("register: %w", err)
	}
	wrapped, err := crypto.WrapKey(encKey, dataKey)
	if err != nil {
		return nil, fmt.Errorf("register: %w", err)
	}

	profile := domain.Profile{
		KdfSalt:        salt,
		KdfParams:      params,
		WrappedDataKey: wrapped,
		ProfileVersion: 1,
	}
	if err := a.transport.Register(ctx, login, authKey, profile); err != nil {
		return nil, fmt.Errorf("register: %w", err)
	}

	a.store.SetProfile(salt, params, wrapped)
	return dataKey, nil
}

// Login выполняет двухфазный challenge-response вход и разворачивает dataKey
// из профиля, полученного от сервера. Сохраняет полученные токены в локальное хранилище.
func (a *AuthFlow) Login(ctx context.Context, login, masterPassword string) (dataKey []byte, err error) {
	chall, err := a.transport.Challenge(ctx, login)
	if err != nil {
		return nil, fmt.Errorf("login: %w", err)
	}

	authKey, encKey := crypto.DeriveKeys(masterPassword, chall.Profile.KdfSalt, chall.Profile.KdfParams)
	authMsg := crypto.AuthMessage(authKey, []byte(chall.ServerNonce))

	if err := a.transport.Login(ctx, login, authMsg); err != nil {
		return nil, fmt.Errorf("login: %w", err)
	}

	dataKey, err = crypto.UnwrapKey(encKey, chall.Profile.WrappedDataKey)
	if err != nil {
		return nil, fmt.Errorf("login: unwrap data key: %w", err)
	}

	a.store.SetProfile(chall.Profile.KdfSalt, chall.Profile.KdfParams, chall.Profile.WrappedDataKey)
	access, refresh := a.transport.Tokens()
	a.store.SetTokens(access, refresh)

	return dataKey, nil
}
