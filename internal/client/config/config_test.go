package config_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/alexvictorne/voldepass/internal/client/config"
)

func writeJSON(t *testing.T, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	require.NoError(t, err)
	f := filepath.Join(t.TempDir(), "config.json")
	require.NoError(t, os.WriteFile(f, data, 0o600))
	return f
}

func TestLoad_Defaults(t *testing.T) {
	clearEnv(t)

	cfg, err := config.Load(nil)
	require.NoError(t, err)

	def := config.Default()
	assert.Equal(t, def, cfg)
}

func TestLoad_JSONFile(t *testing.T) {
	clearEnv(t)

	path := writeJSON(t, map[string]any{
		"server_url": "https://example.com:9090",
		"log_level":  "debug",
	})

	cfg, err := config.Load([]string{"-config", path})
	require.NoError(t, err)

	assert.Equal(t, "https://example.com:9090", cfg.ServerURL)
	assert.Equal(t, "debug", cfg.LogLevel)
	assert.Equal(t, config.Default().MaxRetries, cfg.MaxRetries)
}

func TestLoad_EnvOverridesJSON(t *testing.T) {
	clearEnv(t)

	path := writeJSON(t, map[string]any{
		"server_url": "https://json.example.com",
		"log_level":  "debug",
	})
	t.Setenv("VOLDEPASS_CLIENT_SERVER_URL", "https://env.example.com")

	cfg, err := config.Load([]string{"-config", path})
	require.NoError(t, err)

	assert.Equal(t, "https://env.example.com", cfg.ServerURL)
	assert.Equal(t, "debug", cfg.LogLevel)
}

func TestLoad_FlagOverridesEnv(t *testing.T) {
	clearEnv(t)

	t.Setenv("VOLDEPASS_CLIENT_SERVER_URL", "https://env.example.com")

	cfg, err := config.Load([]string{"-server-url", "https://flag.example.com"})
	require.NoError(t, err)

	assert.Equal(t, "https://flag.example.com", cfg.ServerURL)
}

func TestLoad_AllSourcesPriority(t *testing.T) {
	clearEnv(t)

	path := writeJSON(t, map[string]any{"request_timeout": "5s"})
	t.Setenv("VOLDEPASS_CLIENT_REQUEST_TIMEOUT", "10s")

	cfg, err := config.Load([]string{"-config", path, "-request-timeout", "20s"})
	require.NoError(t, err)

	assert.Equal(t, 20*time.Second, cfg.RequestTimeout.Duration)
}

func TestLoad_InvalidJSON(t *testing.T) {
	clearEnv(t)

	f := filepath.Join(t.TempDir(), "bad.json")
	require.NoError(t, os.WriteFile(f, []byte("{not json}"), 0o600))

	_, err := config.Load([]string{"-config", f})
	assert.ErrorContains(t, err, "parse config file")
}

func TestLoad_MissingJSONFile(t *testing.T) {
	clearEnv(t)

	_, err := config.Load([]string{"-config", "/nonexistent/path/config.json"})
	assert.ErrorContains(t, err, "read config file")
}

func TestLoad_MaxRetriesAndTLSFlags(t *testing.T) {
	clearEnv(t)

	cfg, err := config.Load([]string{
		"-max-retries", "7",
		"-tls-ca-cert", "/path/ca.pem",
		"-tls-pinned-fingerprint", "abc123",
	})
	require.NoError(t, err)

	assert.Equal(t, 7, cfg.MaxRetries)
	assert.Equal(t, "/path/ca.pem", cfg.TLSCACert)
	assert.Equal(t, "abc123", cfg.TLSPinnedFingerprint)
}

// clearEnv удаляет все VOLDEPASS* переменные окружения на время теста.
func clearEnv(t *testing.T) {
	t.Helper()
	for _, kv := range os.Environ() {
		for i := 0; i < len(kv); i++ {
			if kv[i] == '=' {
				key := kv[:i]
				if len(key) >= 9 && key[:9] == "VOLDEPASS" {
					t.Setenv(key, "")
					os.Unsetenv(key)
				}
				break
			}
		}
	}
}
