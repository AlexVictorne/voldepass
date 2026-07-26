//go:build e2e

package e2e

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// freePort резервирует свободный TCP-порт на localhost для сервера теста.
// Между освобождением и запуском сервера остаётся небольшое окно гонки —
// приемлемо для теста, тот же приём используют другие e2e-гарнёсы.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// waitForServer поллит baseURL, пока сервер не начнёт отвечать (или не истечёт timeout).
func waitForServer(t *testing.T, baseURL string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(baseURL + "/swagger/index.html") //nolint:noctx // тестовый polling-цикл, не production-код
		if err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("server at %s did not become ready within %s", baseURL, timeout)
}

// runClient запускает voldepass-client с заданными аргументами, передавая password
// на stdin (как это делает readPassword для непривязанного к терминалу stdin),
// и возвращает объединённый stdout+stderr.
func runClient(t *testing.T, clientBin string, password string, args ...string) string {
	t.Helper()
	cmd := exec.Command(clientBin, args...)
	cmd.Stdin = strings.NewReader(password + "\n")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "client %v failed: %s", args, out)
	return string(out)
}

// TestE2E_FullLifecycle_RealProcesses — единственный «настоящий» e2e-тест: реальный
// сервер и реальный клиент как отдельные OS-процессы, общающиеся по сети, плюс
// проверка graceful shutdown по SIGTERM. Остальные тесты пакета — smoke (сборка/версия);
// этот проверяет то, что smoke принципиально не может: сетевое взаимодействие
// скомпилированных бинарей и обработку сигналов реальным процессом сервера.
func TestE2E_FullLifecycle_RealProcesses(t *testing.T) {
	serverBin := buildBinary(t, "./cmd/server", "voldepass-server")
	clientBin := buildBinary(t, "./cmd/client", "voldepass-client")

	addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	baseURL := "http://" + addr

	serverCmd := exec.Command(serverBin,
		"-address", addr,
		"-database-url", testDSN,
		"-jwt-secret", "e2e-full-lifecycle-test-secret-32b",
	)
	var serverOut bytes.Buffer
	serverCmd.Stdout = &serverOut
	serverCmd.Stderr = &serverOut
	require.NoError(t, serverCmd.Start(), "failed to start server process")

	// Graceful shutdown: посылаем SIGTERM и ждём естественного завершения процесса
	// (не форсированного kill), в пределах разумного таймаута (app.go даёт себе 10s).
	t.Cleanup(func() {
		_ = serverCmd.Process.Signal(syscall.SIGTERM)

		done := make(chan error, 1)
		go func() { done <- serverCmd.Wait() }()

		select {
		case err := <-done:
			assert.NoError(t, err, "server must exit cleanly on SIGTERM, output:\n%s", serverOut.String())
		case <-time.After(8 * time.Second):
			_ = serverCmd.Process.Kill()
			t.Errorf("server did not shut down within 8s of SIGTERM, output:\n%s", serverOut.String())
		}
	})

	waitForServer(t, baseURL, 10*time.Second)

	login := "e2e-" + uuid.NewString()
	password := "e2e-master-password"
	storageFile := filepath.Join(t.TempDir(), "vault.enc")

	commonArgs := []string{"--login", login, "--server-url", baseURL, "--storage-file", storageFile}

	regOut := runClient(t, clientBin, password, append([]string{"register"}, commonArgs...)...)
	assert.Contains(t, regOut, "registered", "register output: %s", regOut)

	addArgs := append([]string{"add", "--type", "text", "--content", "hello from e2e", "--meta", "e2e-note"}, commonArgs...)
	addOut := runClient(t, clientBin, password, addArgs...)
	assert.Contains(t, addOut, "created record", "add output: %s", addOut)

	listOut := runClient(t, clientBin, password, append([]string{"list"}, commonArgs...)...)
	assert.Contains(t, listOut, "e2e-note", "list must show the record's meta label, output: %s", listOut)
	assert.Contains(t, listOut, "text", "list must show the record's type, output: %s", listOut)

	getOut := runClient(t, clientBin, password, append([]string{"get", "--id", extractRecordID(t, addOut)}, commonArgs...)...)
	assert.Contains(t, getOut, "hello from e2e", "get must decrypt the payload round-trip, output: %s", getOut)
}

// extractRecordID парсит "created record <id>" из вывода команды add.
func extractRecordID(t *testing.T, addOutput string) string {
	t.Helper()
	const prefix = "created record "
	idx := strings.Index(addOutput, prefix)
	require.NotEqual(t, -1, idx, "could not find record ID in add output: %s", addOutput)
	rest := addOutput[idx+len(prefix):]
	return strings.TrimSpace(strings.SplitN(rest, "\n", 2)[0])
}
