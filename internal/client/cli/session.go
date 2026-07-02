// Пакет cli реализует команды cobra для клиента Voldepass.
//
// Основная логика вынесена в тестируемые функции, не зависящие от cobra/stdin
// (openSession, openNewSession и функции runXxx в других файлах пакета);
// cobra-команды — тонкие обёртки, которые парсят флаги, запрашивают пароль
// и вызывают эти функции.
package cli

import (
	"context"
	"fmt"

	clientcfg "github.com/alexvictorne/voldepass/internal/client/config"
	"github.com/alexvictorne/voldepass/internal/client/service"
	"github.com/alexvictorne/voldepass/internal/client/storage"
	"github.com/alexvictorne/voldepass/internal/client/transport"
)

// bundle объединяет всё, что нужно командам для работы с сессией пользователя.
type bundle struct {
	session *service.Session
	vault   *service.VaultManager
	syncer  *service.Syncer
}

// newTransport создаёт transport.Client из конфигурации клиента.
func newTransport(cfg clientcfg.Config) (*transport.Client, error) {
	return transport.New(transport.Options{
		BaseURL:           cfg.ServerURL,
		MaxRetries:        cfg.MaxRetries,
		PinnedFingerprint: cfg.TLSPinnedFingerprint,
	})
}

// openSession логинит пользователя (challenge-response через сервер), разворачивает
// dataKey и подгружает локальный кэш из зашифрованного файла (если он существует).
func openSession(ctx context.Context, cfg clientcfg.Config, login, password string) (*bundle, error) {
	tr, err := newTransport(cfg)
	if err != nil {
		return nil, fmt.Errorf("open session: %w", err)
	}

	fileStore := storage.NewFileStore(cfg.StorageFile)
	auth := service.NewAuthFlow(tr, fileStore.Store)

	dataKey, err := auth.Login(ctx, login, password)
	if err != nil {
		return nil, fmt.Errorf("open session: %w", err)
	}

	if err := fileStore.Load(dataKey); err != nil {
		return nil, fmt.Errorf("open session: load local storage: %w", err)
	}

	vault := service.NewVaultManager(fileStore.Store, dataKey)
	syncer := service.NewSyncer(tr, fileStore.Store)
	session := service.NewSession(fileStore, dataKey, syncer)

	return &bundle{session: session, vault: vault, syncer: syncer}, nil
}

// openNewSession регистрирует нового пользователя и возвращает готовую к работе сессию
// с пустым локальным хранилищем.
func openNewSession(ctx context.Context, cfg clientcfg.Config, login, password string) (*bundle, error) {
	tr, err := newTransport(cfg)
	if err != nil {
		return nil, fmt.Errorf("open new session: %w", err)
	}

	fileStore := storage.NewFileStore(cfg.StorageFile)
	auth := service.NewAuthFlow(tr, fileStore.Store)

	if _, err := auth.Register(ctx, login, password); err != nil {
		return nil, fmt.Errorf("open new session: %w", err)
	}

	// Register не аутентифицирует сессию (сервер не выдаёт токены при регистрации),
	// поэтому сразу логинимся, чтобы Syncer мог обращаться к защищённым эндпоинтам.
	dataKey, err := auth.Login(ctx, login, password)
	if err != nil {
		return nil, fmt.Errorf("open new session: login after register: %w", err)
	}

	vault := service.NewVaultManager(fileStore.Store, dataKey)
	syncer := service.NewSyncer(tr, fileStore.Store)
	session := service.NewSession(fileStore, dataKey, syncer)

	return &bundle{session: session, vault: vault, syncer: syncer}, nil
}
