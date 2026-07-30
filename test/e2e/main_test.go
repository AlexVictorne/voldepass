//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"os"
	"testing"

	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/alexvictorne/voldepass/internal/server/storage/postgres"
)

// testDSN — строка подключения к PostgreSQL, поднятому в TestMain, используется
// TestE2E_FullLifecycle_RealProcesses для запуска настоящего сервера.
var testDSN string

func TestMain(m *testing.M) {
	ctx := context.Background()

	container, err := tcpostgres.Run(ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("voldepass"),
		tcpostgres.WithUsername("voldepass"),
		tcpostgres.WithPassword("voldepass"),
		tcpostgres.BasicWaitStrategies(),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to start postgres container:", err)
		os.Exit(1)
	}
	defer container.Terminate(ctx) //nolint:errcheck

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to get connection string:", err)
		os.Exit(1)
	}
	testDSN = dsn

	// Миграции применяются один раз здесь; сам сервер (см. app.New) тоже
	// применяет миграции при старте, но идемпотентно — повторный прогон безопасен.
	if err := postgres.RunMigrations(testDSN); err != nil {
		fmt.Fprintln(os.Stderr, "failed to run migrations:", err)
		os.Exit(1)
	}

	os.Exit(m.Run())
}
