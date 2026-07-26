// Пакет app собирает зависимости сервера (config → storage → services → router)
// и управляет их жизненным циклом: запуском, фоновыми задачами, graceful shutdown.
package app

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/alexvictorne/voldepass/internal/server/auth"
	"github.com/alexvictorne/voldepass/internal/server/config"
	"github.com/alexvictorne/voldepass/internal/server/rest"
	"github.com/alexvictorne/voldepass/internal/server/service"
	"github.com/alexvictorne/voldepass/internal/server/storage/inmem"
	"github.com/alexvictorne/voldepass/internal/server/storage/postgres"
)

// App объединяет HTTP-сервер и фоновые задачи Voldepass.
type App struct {
	cfg        config.Config
	log        zerolog.Logger
	pool       *pgxpool.Pool
	httpServer *http.Server

	idempotencyStore service.IdempotencyStore
}

// New собирает приложение: применяет миграции, поднимает пул соединений,
// конструирует сервисы и HTTP-роутер.
func New(ctx context.Context, cfg config.Config, log zerolog.Logger) (*App, error) {
	if err := postgres.RunMigrations(cfg.DatabaseURL); err != nil {
		return nil, fmt.Errorf("run migrations: %w", err)
	}

	pool, err := postgres.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("connect to postgres: %w", err)
	}

	users := postgres.NewUserRepository(pool)
	records := postgres.NewRecordRepository(pool)
	idempotency := postgres.NewIdempotencyStore(pool)
	refreshTokens := postgres.NewRefreshTokenStore(pool)

	jwt := auth.NewJWTManager([]byte(cfg.JWTSecret), cfg.AccessTokenTTL.Duration)
	challenges := auth.NewChallengeStore(cfg.ChallengeTTL.Duration)
	refreshSvc := auth.NewRefreshTokenService(refreshTokens, cfg.RefreshTokenTTL.Duration)
	// In-memory трекер попыток входа: при рестарте сервера счётчики сбрасываются,
	// что консервативно (не усиливает защиту от распределённой атаки, но и не
	// блокирует легитимных пользователей после деплоя).
	attempts := inmem.NewLoginAttemptTracker(cfg.LoginMaxAttempts, cfg.LoginWindow.Duration)

	authSvc := service.NewAuthService(users, challenges, jwt, refreshSvc, attempts)
	vaultSvc := service.NewVaultService(records)
	syncSvc := service.NewSyncService(records, idempotency)

	router := rest.NewRouter(
		rest.NewAuthHandlers(authSvc),
		rest.NewVaultHandlers(vaultSvc),
		rest.NewSyncHandlers(syncSvc),
		jwt,
		cfg.CORSAllowedOrigins,
	)

	return &App{
		cfg:              cfg,
		log:              log,
		pool:             pool,
		idempotencyStore: idempotency,
		httpServer: &http.Server{
			Addr:              cfg.Address,
			Handler:           router,
			ReadHeaderTimeout: 10 * time.Second,
		},
	}, nil
}

// Run запускает HTTP-сервер и фоновую очистку идемпотентности.
// Блокируется до отмены ctx, затем выполняет graceful shutdown.
func (a *App) Run(ctx context.Context) error {
	cleanupDone := make(chan struct{})
	go func() {
		defer close(cleanupDone)
		a.runIdempotencyCleanup(ctx)
	}()

	serveErr := make(chan error, 1)
	go func() {
		a.log.Info().Str("address", a.cfg.Address).Msg("starting HTTP server")
		var err error
		if a.cfg.TLSEnabled {
			err = a.httpServer.ListenAndServeTLS(a.cfg.TLSCertFile, a.cfg.TLSKeyFile)
		} else {
			err = a.httpServer.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			serveErr <- err
		}
		close(serveErr)
	}()

	select {
	case <-ctx.Done():
	case err := <-serveErr:
		if err != nil {
			return fmt.Errorf("http server: %w", err)
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := a.httpServer.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown http server: %w", err)
	}

	<-cleanupDone
	a.pool.Close()
	return nil
}

// runIdempotencyCleanup периодически удаляет истёкшие ключи идемпотентности.
func (a *App) runIdempotencyCleanup(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := a.idempotencyStore.DeleteExpired(ctx); err != nil {
				a.log.Error().Err(err).Msg("idempotency cleanup failed")
			}
		}
	}
}
