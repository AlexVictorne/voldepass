//go:build e2e

package e2e

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildBinary собирает указанный пакет cmd/... во временную директорию с ldflags
// version/buildDate и возвращает путь к получившемуся исполняемому файлу.
func buildBinary(t *testing.T, pkg, name string) string {
	t.Helper()

	dir := t.TempDir()
	binPath := filepath.Join(dir, name)
	if runtime.GOOS == "windows" {
		binPath += ".exe"
	}

	ldflags := "-X main.version=test-version -X main.buildDate=test-date"
	cmd := exec.Command("go", "build", "-ldflags", ldflags, "-o", binPath, pkg)
	cmd.Dir = repoRoot(t)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	require.NoError(t, cmd.Run(), "build failed: %s", stderr.String())

	return binPath
}

// repoRoot определяет корень репозитория относительно текущего рабочего каталога
// go test (test/e2e), чтобы `go build ./cmd/...` резолвился корректно.
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	require.NoError(t, err)
	return filepath.Join(wd, "..", "..")
}

func TestSmoke_ServerBinaryBuildsAndPrintsVersion(t *testing.T) {
	bin := buildBinary(t, "./cmd/server", "voldepass-server")

	// У сервера нет "version"-сабкоманды (это HTTP-демон), но бинарь должен
	// как минимум запуститься и напечатать версию/дату на старте перед тем,
	// как попытаться поднять соединение с БД и упасть (ожидаемо в smoke-окружении
	// без реальной БД). Здесь просто проверяем, что бинарь исполняемый и стартует.
	cmd := exec.Command(bin, "-database-url", "postgres://invalid:invalid@127.0.0.1:1/invalid")
	out, _ := cmd.CombinedOutput()
	assert.Contains(t, string(out), "test-version", "server must print injected version on startup")
}

func TestSmoke_ClientBinaryVersion(t *testing.T) {
	bin := buildBinary(t, "./cmd/client", "voldepass-client")

	cmd := exec.Command(bin, "version")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "output: %s", out)
	assert.Contains(t, string(out), "version=test-version")
	assert.Contains(t, string(out), "buildDate=test-date")
}

func TestSmoke_ClientBinaryGenerate(t *testing.T) {
	bin := buildBinary(t, "./cmd/client", "voldepass-client")

	cmd := exec.Command(bin, "generate", "--length", "16")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "output: %s", out)
	assert.Len(t, trimNewline(string(out)), 16)
}

func trimNewline(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
