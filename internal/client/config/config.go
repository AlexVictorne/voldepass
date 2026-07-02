// Пакет config определяет конфигурацию CLI/TUI-клиента Voldepass.
//
// Источники применяются в том же порядке, что и у сервера:
//
//	defaults  →  JSON-файл (-config)  →  переменные окружения  →  флаги командной строки
package config

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/caarlos0/env/v11"
)

// Duration — обёртка над time.Duration с поддержкой JSON-сериализации строками
// вида "30s" (стандартный time.Duration умеет только наносекунды как число).
type Duration struct{ time.Duration }

// UnmarshalJSON реализует json.Unmarshaler для Duration.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		var n int64
		if err2 := json.Unmarshal(b, &n); err2 != nil {
			return err
		}
		d.Duration = time.Duration(n)
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("parse duration %q: %w", s, err)
	}
	d.Duration = v
	return nil
}

// MarshalJSON реализует json.Marshaler для Duration.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.Duration.String())
}

// UnmarshalText реализует encoding.TextUnmarshaler для Duration (для caarlos0/env).
func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return fmt.Errorf("parse duration %q: %w", string(b), err)
	}
	d.Duration = v
	return nil
}

// Config содержит все настраиваемые параметры клиента.
type Config struct {
	// ServerURL — базовый URL сервера Voldepass (например, https://localhost:8080).
	ServerURL string `json:"server_url" env:"VOLDEPASS_CLIENT_SERVER_URL"`
	// StorageFile — путь к локальному зашифрованному файлу хранилища.
	StorageFile string `json:"storage_file" env:"VOLDEPASS_CLIENT_STORAGE_FILE"`
	// TLSCACert — путь к CA-сертификату для проверки сервера (опционально).
	TLSCACert string `json:"tls_ca_cert" env:"VOLDEPASS_CLIENT_TLS_CA_CERT"`
	// TLSPinnedFingerprint — SHA-256 fingerprint сертификата сервера для pinning'а (опционально).
	TLSPinnedFingerprint string `json:"tls_pinned_fingerprint" env:"VOLDEPASS_CLIENT_TLS_PINNED_FINGERPRINT"`
	// RequestTimeout — таймаут на отдельный HTTP-запрос к серверу.
	RequestTimeout Duration `json:"request_timeout" env:"VOLDEPASS_CLIENT_REQUEST_TIMEOUT"`
	// MaxRetries — максимальное число повторных попыток при временных ошибках.
	MaxRetries int `json:"max_retries" env:"VOLDEPASS_CLIENT_MAX_RETRIES"`
	// LogLevel — уровень zerolog (debug, info, warn, error).
	LogLevel string `json:"log_level" env:"VOLDEPASS_CLIENT_LOG_LEVEL"`
}

// Default возвращает Config с разумными значениями по умолчанию.
func Default() Config {
	return Config{
		ServerURL:      "http://localhost:8080",
		StorageFile:    defaultStorageFile(),
		RequestTimeout: Duration{30 * time.Second},
		MaxRetries:     3,
		LogLevel:       "info",
	}
}

// Load собирает конфигурацию клиента из всех источников.
// args — аргументы командной строки (обычно os.Args[1:]).
func Load(args []string) (Config, error) {
	cfg := Default()

	configPath := preParseConfigPath(args)
	if configPath != "" {
		if err := applyJSONFile(&cfg, configPath); err != nil {
			return Config{}, err
		}
	}

	if err := env.Parse(&cfg); err != nil {
		return Config{}, fmt.Errorf("parse environment: %w", err)
	}

	if err := applyFlags(&cfg, args); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

// defaultStorageFile возвращает платформенный путь к файлу хранилища по умолчанию.
// Используется $XDG_DATA_HOME на Linux, ~/Library/Application Support на macOS,
// %APPDATA% на Windows, и просто ~/.voldepass как запасной вариант.
func defaultStorageFile() string {
	if dir := os.Getenv("XDG_DATA_HOME"); dir != "" {
		return filepath.Join(dir, "voldepass", "storage.vp")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".voldepass", "storage.vp")
	}
	return "storage.vp"
}

// preParseConfigPath извлекает значение -config без влияния на основной flag.FlagSet.
func preParseConfigPath(args []string) string {
	fs := flag.NewFlagSet("preparse", flag.ContinueOnError)
	fs.SetOutput(os.NewFile(0, os.DevNull))
	path := fs.String("config", "", "")
	_ = fs.Parse(args)
	return *path
}

// applyJSONFile накладывает значения из JSON-файла конфигурации на cfg.
func applyJSONFile(cfg *Config, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config file %q: %w", path, err)
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return fmt.Errorf("parse config file %q: %w", path, err)
	}
	return nil
}

// applyFlags накладывает флаги командной строки на cfg.
func applyFlags(cfg *Config, args []string) error {
	fs := flag.NewFlagSet("voldepass-client", flag.ContinueOnError)
	fs.String("config", "", "path to a JSON configuration file")

	fs.StringVar(&cfg.ServerURL, "server-url", cfg.ServerURL, "Voldepass server base URL")
	fs.StringVar(&cfg.StorageFile, "storage-file", cfg.StorageFile, "path to local encrypted storage file")
	fs.StringVar(&cfg.TLSCACert, "tls-ca-cert", cfg.TLSCACert, "path to CA certificate for server verification")
	fs.StringVar(&cfg.TLSPinnedFingerprint, "tls-pinned-fingerprint", cfg.TLSPinnedFingerprint, "SHA-256 fingerprint of the server certificate for pinning")
	fs.DurationVar(&cfg.RequestTimeout.Duration, "request-timeout", cfg.RequestTimeout.Duration, "HTTP request timeout")
	fs.IntVar(&cfg.MaxRetries, "max-retries", cfg.MaxRetries, "maximum number of request retries")
	fs.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "log level (debug, info, warn, error)")

	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("parse flags: %w", err)
	}
	return nil
}
