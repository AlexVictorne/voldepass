// Пакет main является точкой входа CLI/TUI-клиента Voldepass.
//
// Версия и дата сборки задаются через -ldflags при компиляции:
//
//	go build -ldflags "-X main.version=1.0.0 -X main.buildDate=2024-01-01" ./cmd/client
package main

import (
	"fmt"
	"os"

	"github.com/alexvictorne/voldepass/internal/client/cli"
)

// version задаётся компилятором через -ldflags "-X main.version=..."
var version = "dev"

// buildDate задаётся компилятором через -ldflags "-X main.buildDate=..."
var buildDate = "unknown"

func main() {
	root, err := cli.NewRootCmd(version, buildDate)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
