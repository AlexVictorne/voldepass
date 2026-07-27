//go:build integration

package integration

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/alexvictorne/voldepass/internal/server/storage/postgres"
)

// dsn и pool — общие для всех тестов пакета; поднимаются один раз в TestMain.
var (
	testDSN  string
	testPool *pgxpool.Pool
)

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

	if err := postgres.RunMigrations(testDSN); err != nil {
		fmt.Fprintln(os.Stderr, "failed to run migrations:", err)
		os.Exit(1)
	}

	pool, err := postgres.NewPool(ctx, testDSN)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to connect to postgres:", err)
		os.Exit(1)
	}
	testPool = pool
	defer testPool.Close()

	os.Exit(m.Run())
}
