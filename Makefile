## Makefile проекта Voldepass
##
## Использование:
##   make <target>
##
## Основные цели:
##   all             — lint + test + cover
##   build           — собрать оба бинаря
##   gen             — кодогенерация (swag, mockery, stringer)
##   lint            — статический анализ
##   test            — юнит-тесты + функциональные (-race)
##   test-slow   	 — медленные TUI-тесты, зависящие от реального времени (tag slow)
##   test-integration — интеграционные тесты (требует Docker)
##   test-e2e        — smoke / e2e тесты
##   test-all        — все уровни
##   cover           — отчёт о покрытии
##   ci              — lint + test + test-integration (режим CI)
##   up / down       — запустить / остановить PostgreSQL через docker-compose
##   migrate-up      — применить миграции
##   migrate-down    — откатить последнюю миграцию
##   clean           — удалить артефакты

.DEFAULT_GOAL := all

# ─── Параметры сборки ────────────────────────────────────────────────────────
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS    := -ldflags "-X main.version=$(VERSION) -X main.buildDate=$(BUILD_DATE)"

MODULE := github.com/alexvictorne/voldepass
BIN    := ./bin

# ─── Кросс-компиляция клиента ────────────────────────────────────────────────
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

# ─── БД ──────────────────────────────────────────────────────────────────────
DATABASE_URL ?= postgres://voldepass:voldepass@localhost:5432/voldepass?sslmode=disable

.PHONY: all build build-server build-client build-all-platforms \
        gen lint test test-slow test-integration test-e2e test-all cover ci \
        up down migrate-up migrate-down clean

## all: lint + test + покрытие
all: lint test cover

## build: собрать сервер и клиент для текущей платформы
build: build-server build-client

build-server:
	go build $(LDFLAGS) -o $(BIN)/voldepass-server ./cmd/server

build-client:
	go build $(LDFLAGS) -o $(BIN)/voldepass-client ./cmd/client

## build-all-platforms: кросс-компиляция клиента под все целевые платформы
build-all-platforms:
	@for platform in $(PLATFORMS); do \
		GOOS=$$(echo $$platform | cut -d/ -f1); \
		GOARCH=$$(echo $$platform | cut -d/ -f2); \
		OUTPUT=$(BIN)/voldepass-client-$$GOOS-$$GOARCH; \
		if [ "$$GOOS" = "windows" ]; then OUTPUT=$$OUTPUT.exe; fi; \
		echo "building $$OUTPUT"; \
		GOOS=$$GOOS GOARCH=$$GOARCH go build $(LDFLAGS) -o $$OUTPUT ./cmd/client || exit 1; \
	done

## gen: кодогенерация (swag, mockery, stringer)
gen:
	go generate ./...
	go run github.com/swaggo/swag/cmd/swag@v1.16.4 init -g cmd/server/main.go -o api/openapi --parseInternal --parseDependency

## lint: статический анализ (golangci-lint, go vet, govulncheck, go mod verify)
lint:
	golangci-lint run ./...
	go vet ./...
	go mod verify
	@which govulncheck > /dev/null 2>&1 && govulncheck ./... || echo "govulncheck not installed, skipping"

## test: юнит-тесты и функциональные тесты с race-detector и coverprofile
test:
	go test -v -count=1 -race -coverprofile=coverage.out ./internal/... ./cmd/...

## test-slow: медленные TUI-тесты, зависящие от реального времени (tea.Tick),
## изолированы под build tag slow, чтобы не замедлять обычный `make test`
test-slow:
	go test -v -count=1 -tags=slow -race ./internal/client/tui/...

## test-integration: интеграционные тесты (требует Docker)
test-integration:
	go test -v -count=1 -tags=integration -race ./test/integration/...

## test-e2e: smoke/e2e тесты
test-e2e:
	go test -v -count=1 -tags=e2e -race ./test/e2e/...

## test-all: все уровни тестирования
test-all: lint test test-slow test-integration test-e2e
	@echo "all tests passed"

## cover: отчёт о покрытии (требует предварительного запуска make test)
cover:
	@go tool cover -func=coverage.out | grep "^total:" | awk '{print "total coverage: " $$3}'
	@TOTAL=$$(go tool cover -func=coverage.out | grep "^total:" | awk '{gsub(/%/,""); print $$3}'); \
	if [ $$(echo "$$TOTAL < 70" | bc -l) -eq 1 ]; then \
		echo "coverage $$TOTAL% is below required 70%"; exit 1; \
	fi
	go tool cover -html=coverage.out -o coverage.html

## ci: режим CI — lint + test + test-slow + test-integration + test-e2e
ci: lint test cover test-slow test-integration test-e2e

## up: запустить PostgreSQL через docker-compose
up:
	docker compose up -d
	@echo "waiting for postgres to be ready..."
	@until docker compose exec postgres pg_isready -U voldepass > /dev/null 2>&1; do sleep 1; done
	@echo "postgres is ready"

## down: остановить PostgreSQL
down:
	docker compose down

## migrate-up: применить все доступные миграции
migrate-up:
	migrate -database "$(DATABASE_URL)" -path ./internal/server/storage/postgres/migrations up

## migrate-down: откатить последнюю миграцию
migrate-down:
	migrate -database "$(DATABASE_URL)" -path ./internal/server/storage/postgres/migrations down 1

## clean: удалить артефакты сборки и покрытия
clean:
	rm -rf $(BIN) coverage.out coverage.html
