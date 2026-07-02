// Пакет main является точкой входа HTTP-сервера Voldepass.
//
// Версия и дата сборки задаются через -ldflags при компиляции:
//
//	go build -ldflags "-X main.version=1.0.0 -X main.buildDate=2024-01-01" ./cmd/server
//
//	@title			Voldepass API
//	@version		1.0
//	@description	Zero-knowledge password manager server API. The server only ever handles
//	@description	ciphertext: encryption/decryption happens exclusively on the client.
//
//	@license.name	MIT
//
//	@BasePath	/api/v1
//
//	@securityDefinitions.apikey	BearerAuth
//	@in							header
//	@name						Authorization
//	@description				Access token issued by /login, sent as "Bearer <token>".
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/rs/zerolog"

	"github.com/alexvictorne/voldepass/internal/server/app"
	"github.com/alexvictorne/voldepass/internal/server/config"
)

// version задаётся компилятором через -ldflags "-X main.version=..."
var version = "dev"

// buildDate задаётся компилятором через -ldflags "-X main.buildDate=..."
var buildDate = "unknown"

func main() {
	cfg, err := config.Load(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	log := newLogger(cfg.LogLevel)
	log.Info().Str("version", version).Str("build_date", buildDate).Msg("starting voldepass-server")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	a, err := app.New(ctx, cfg, log)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialize app")
	}

	if err := a.Run(ctx); err != nil {
		log.Fatal().Err(err).Msg("server exited with error")
	}
}

// newLogger создаёт zerolog-логгер с заданным уровнем (debug, info, warn, error).
func newLogger(level string) zerolog.Logger {
	parsed, err := zerolog.ParseLevel(level)
	if err != nil {
		parsed = zerolog.InfoLevel
	}
	return zerolog.New(os.Stdout).Level(parsed).With().Timestamp().Logger()
}
