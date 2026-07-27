package tui

import (
	"context"
	"fmt"

	clientcfg "github.com/alexvictorne/voldepass/internal/client/config"
	"github.com/alexvictorne/voldepass/internal/client/service"
	"github.com/alexvictorne/voldepass/internal/client/storage"
	"github.com/alexvictorne/voldepass/internal/client/transport"
)

// sessionOpener — сигнатура функции логина; поле Model.openSession для подмены в тестах.
type sessionOpener func(ctx context.Context, cfg clientcfg.Config, login, password string) (*service.Session, *service.VaultManager, *service.Syncer, error)

// defaultOpenSession логинится через сервер (challenge-response) и подгружает
// локальный кэш из зашифрованного файла — та же логика, что и в internal/client/cli.
func defaultOpenSession(ctx context.Context, cfg clientcfg.Config, login, password string) (*service.Session, *service.VaultManager, *service.Syncer, error) {
	tr, err := transport.New(transport.Options{
		BaseURL:           cfg.ServerURL,
		MaxRetries:        cfg.MaxRetries,
		PinnedFingerprint: cfg.TLSPinnedFingerprint,
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open session: %w", err)
	}

	fileStore := storage.NewFileStore(cfg.StorageFile)
	auth := service.NewAuthFlow(tr, fileStore.Store)

	dataKey, err := auth.Login(ctx, login, password)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open session: %w", err)
	}
	if err := fileStore.Load(dataKey); err != nil {
		return nil, nil, nil, fmt.Errorf("open session: load local storage: %w", err)
	}

	vault := service.NewVaultManager(fileStore.Store, dataKey)
	syncer := service.NewSyncer(tr, fileStore.Store)
	session := service.NewSession(fileStore, dataKey, syncer)

	return session, vault, syncer, nil
}
