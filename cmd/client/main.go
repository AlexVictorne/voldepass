// Пакет main является точкой входа CLI/TUI-клиента Voldepass.
//
// Версия и дата сборки задаются через -ldflags при компиляции:
//
//	go build -ldflags "-X main.version=1.0.0 -X main.buildDate=2024-01-01" ./cmd/client
package main

import (
	"fmt"
	"os"
)

// version задаётся компилятором через -ldflags "-X main.version=..."
var version = "dev"

// buildDate задаётся компилятором через -ldflags "-X main.buildDate=..."
var buildDate = "unknown"

func main() {
	// Заглушка до появления cobra-команд в Слое 9.
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Printf("voldepass-client version=%s buildDate=%s\n", version, buildDate)
		return
	}
	fmt.Println("voldepass-client: use 'version' subcommand for build info")
}
