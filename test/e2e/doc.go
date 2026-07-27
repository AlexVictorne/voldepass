//go:build e2e

// Пакет e2e содержит smoke-тесты (сборка бинарей и базовая проверка их запуска)
// и один полноценный e2e-сценарий с реальными процессами сервера/клиента и
// проверкой graceful shutdown по SIGTERM (см. full_lifecycle_test.go).
package e2e
