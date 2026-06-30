package config_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/alexvictorne/voldepass/internal/server/config"
)

// writeJSON записывает cfg в временный файл и возвращает его путь.
func writeJSON(t *testing.T, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	require.NoError(t, err)
	f := filepath.Join(t.TempDir(), "config.json")
	require.NoError(t, os.WriteFile(f, data, 0o600))
	return f
}

// TestLoad_Defaults проверяет, что без каких-либо источников возвращаются
// значения по умолчанию.
func TestLoad_Defaults(t *testing.T) {
	// Очищаем окружение, чтобы не было случайных VOLDEPASS_* переменных.
	clearEnv(t)

	cfg, err := config.Load(nil)
	require.NoError(t, err)

	def := config.Default()
	assert.Equal(t, def, cfg)
}

// TestLoad_JSONFile проверяет, что значения из JSON-файла перекрывают defaults.
func TestLoad_JSONFile(t *testing.T) {
	clearEnv(t)

	path := writeJSON(t, map[string]any{
		"address":   ":9090",
		"log_level": "debug",
	})

	cfg, err := config.Load([]string{"-config", path})
	require.NoError(t, err)

	assert.Equal(t, ":9090", cfg.Address)
	assert.Equal(t, "debug", cfg.LogLevel)
	// Поля, не указанные в файле, остаются дефолтными.
	assert.Equal(t, config.Default().AccessTokenTTL.Duration, cfg.AccessTokenTTL.Duration)
}

// TestLoad_EnvOverridesJSON проверяет, что переменные окружения перекрывают JSON-файл.
func TestLoad_EnvOverridesJSON(t *testing.T) {
	clearEnv(t)

	path := writeJSON(t, map[string]any{
		"address":   ":9090",
		"log_level": "debug",
	})

	t.Setenv("VOLDEPASS_ADDRESS", ":7777")

	cfg, err := config.Load([]string{"-config", path})
	require.NoError(t, err)

	// Переменная окружения должна победить JSON.
	assert.Equal(t, ":7777", cfg.Address)
	// Поле из JSON без env-переопределения остаётся.
	assert.Equal(t, "debug", cfg.LogLevel)
}

// TestLoad_FlagOverridesEnv проверяет, что флаг командной строки перекрывает
// переменную окружения.
func TestLoad_FlagOverridesEnv(t *testing.T) {
	clearEnv(t)

	t.Setenv("VOLDEPASS_ADDRESS", ":7777")

	cfg, err := config.Load([]string{"-address", ":6666"})
	require.NoError(t, err)

	// Флаг должен победить env.
	assert.Equal(t, ":6666", cfg.Address)
}

// TestLoad_AllSourcesPriority проверяет полный приоритет: default < json < env < flag.
func TestLoad_AllSourcesPriority(t *testing.T) {
	clearEnv(t)

	// JSON устанавливает TTL в 5 минут.
	path := writeJSON(t, map[string]any{
		"access_token_ttl": "5m",
	})
	// Env перекрывает до 10 минут.
	t.Setenv("VOLDEPASS_ACCESS_TOKEN_TTL", "10m")

	// Флаг перекрывает до 20 минут.
	cfg, err := config.Load([]string{"-config", path, "-access-token-ttl", "20m"})
	require.NoError(t, err)

	assert.Equal(t, 20*time.Minute, cfg.AccessTokenTTL.Duration)
}

// TestLoad_InvalidJSON проверяет, что битый JSON-файл возвращает ошибку.
func TestLoad_InvalidJSON(t *testing.T) {
	clearEnv(t)

	f := filepath.Join(t.TempDir(), "bad.json")
	require.NoError(t, os.WriteFile(f, []byte("{not json}"), 0o600))

	_, err := config.Load([]string{"-config", f})
	assert.ErrorContains(t, err, "parse config file")
}

// clearEnv удаляет все VOLDEPASS_* переменные окружения на время теста.
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
