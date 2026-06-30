// Пакет main является точкой входа HTTP-сервера Voldepass.
//
// Версия и дата сборки задаются через -ldflags при компиляции:
//
//	go build -ldflags "-X main.version=1.0.0 -X main.buildDate=2024-01-01" ./cmd/server
package main

import (
	"fmt"
	"os"

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

	_ = cfg
	fmt.Printf("voldepass-server version=%s buildDate=%s\n", version, buildDate)
}
