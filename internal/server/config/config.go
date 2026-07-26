// Пакет config определяет конфигурацию сервера Voldepass и загрузчик,
// собирающий её из нескольких источников.
//
// Источники применяются в порядке возрастания приоритета:
//
//	defaults  →  JSON-файл (-config)  →  переменные окружения  →  флаги командной строки
//
// Каждый следующий источник перекрывает значения предыдущего: флаг всегда
// выигрывает у переменной окружения, которая выигрывает у JSON-файла.
package config

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/caarlos0/env/v11"
)

// Duration — обёртка над time.Duration с поддержкой JSON-сериализации строками
// вида "15m", "30s" и т.п. (стандартный time.Duration этого не умеет).
type Duration struct{ time.Duration }

// UnmarshalJSON реализует json.Unmarshaler для Duration.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		// Пробуем как число (наносекунды) для обратной совместимости.
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
	return json.Marshal(d.String())
}

// UnmarshalText реализует encoding.TextUnmarshaler для Duration.
// Это позволяет caarlos0/env и другим библиотекам разбирать строки вида "15m".
func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return fmt.Errorf("parse duration %q: %w", string(b), err)
	}
	d.Duration = v
	return nil
}

// Config содержит все настраиваемые параметры сервера.
//
// Теги `json` используются при чтении необязательного JSON-файла конфигурации,
// теги `env` — при наложении переменных окружения.
type Config struct {
	// Address — адрес host:port, на котором слушает HTTP-сервер.
	Address string `json:"address" env:"VOLDEPASS_ADDRESS"`
	// DatabaseURL — строка подключения к PostgreSQL в формате pgx.
	DatabaseURL string `json:"database_url" env:"VOLDEPASS_DATABASE_URL"`
	// JWTSecret подписывает и верифицирует access-токены. Обязателен в продакшене.
	JWTSecret string `json:"jwt_secret" env:"VOLDEPASS_JWT_SECRET"`
	// AccessTokenTTL — время жизни короткоживущего access-токена.
	AccessTokenTTL Duration `json:"access_token_ttl" env:"VOLDEPASS_ACCESS_TOKEN_TTL"`
	// RefreshTokenTTL — время жизни долгоживущего refresh-токена.
	RefreshTokenTTL Duration `json:"refresh_token_ttl" env:"VOLDEPASS_REFRESH_TOKEN_TTL"`
	// ChallengeTTL — время жизни одноразового serverNonce при логине.
	ChallengeTTL Duration `json:"challenge_ttl" env:"VOLDEPASS_CHALLENGE_TTL"`
	// IdempotencyTTL — время хранения результатов push-операций для идемпотентности.
	IdempotencyTTL Duration `json:"idempotency_ttl" env:"VOLDEPASS_IDEMPOTENCY_TTL"`
	// LoginMaxAttempts — количество неудачных попыток логина, разрешённых за одно окно.
	LoginMaxAttempts int `json:"login_max_attempts" env:"VOLDEPASS_LOGIN_MAX_ATTEMPTS"`
	// LoginWindow — скользящее окно rate-limiting при логине.
	LoginWindow Duration `json:"login_window" env:"VOLDEPASS_LOGIN_WINDOW"`
	// TLSEnabled включает HTTPS. При true требуются TLSCertFile и TLSKeyFile.
	TLSEnabled bool `json:"tls_enabled" env:"VOLDEPASS_TLS_ENABLED"`
	// TLSCertFile — путь к PEM-сертификату сервера.
	TLSCertFile string `json:"tls_cert_file" env:"VOLDEPASS_TLS_CERT_FILE"`
	// TLSKeyFile — путь к PEM-приватному ключу сервера.
	TLSKeyFile string `json:"tls_key_file" env:"VOLDEPASS_TLS_KEY_FILE"`
	// LogLevel — уровень zerolog (debug, info, warn, error).
	LogLevel string `json:"log_level" env:"VOLDEPASS_LOG_LEVEL"`
}

// dur — вспомогательная функция для инициализации Duration из time.Duration.
func dur(d time.Duration) Duration { return Duration{d} }

// Default возвращает Config с разумными значениями по умолчанию для разработки.
func Default() Config {
	// DatabaseURL below is a local dev default matching docker-compose.yml, not a real secret.
	return Config{ //nolint:gosec
		Address:          ":8080",
		DatabaseURL:      "postgres://voldepass:voldepass@localhost:5432/voldepass?sslmode=disable",
		JWTSecret:        "",
		AccessTokenTTL:   dur(15 * time.Minute),
		RefreshTokenTTL:  dur(30 * 24 * time.Hour),
		ChallengeTTL:     dur(2 * time.Minute),
		IdempotencyTTL:   dur(24 * time.Hour),
		LoginMaxAttempts: 5,
		LoginWindow:      dur(15 * time.Minute),
		TLSEnabled:       false,
		LogLevel:         "info",
	}
}

// Load собирает конфигурацию сервера из всех источников, используя args как
// аргументы командной строки (обычно os.Args[1:]). Безопасно вызывать в тестах
// с синтетическим срезом аргументов и контролируемым окружением.
func Load(args []string) (Config, error) {
	cfg := Default()

	// Предварительно разбираем только -config, чтобы загрузить JSON-файл до
	// обработки остальных флагов.
	configPath := preParseConfigPath(args)
	if configPath != "" {
		if err := applyJSONFile(&cfg, configPath); err != nil {
			return Config{}, err
		}
	}

	// Переменные окружения перекрывают JSON-файл.
	if err := env.Parse(&cfg); err != nil {
		return Config{}, fmt.Errorf("parse environment: %w", err)
	}

	// Флаги командной строки перекрывают всё остальное. По умолчанию для каждого
	// флага берётся текущее значение cfg, поэтому непереданный флаг не меняет
	// конфигурацию, а переданный — перекрывает.
	if err := applyFlags(&cfg, args); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

// preParseConfigPath извлекает значение -config без влияния на основной flag.FlagSet.
// Неизвестные флаги игнорируются — они будут разобраны позднее.
func preParseConfigPath(args []string) string {
	fs := flag.NewFlagSet("preparse", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
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

// applyFlags накладывает флаги командной строки на cfg. Значения по умолчанию
// каждого флага берутся из текущего cfg, чтобы непереданный флаг не сбрасывал
// уже установленное значение.
func applyFlags(cfg *Config, args []string) error {
	fs := flag.NewFlagSet("voldepass-server", flag.ContinueOnError)
	fs.String("config", "", "path to a JSON configuration file")

	fs.StringVar(&cfg.Address, "address", cfg.Address, "host:port to listen on")
	fs.StringVar(&cfg.DatabaseURL, "database-url", cfg.DatabaseURL, "PostgreSQL DSN")
	fs.StringVar(&cfg.JWTSecret, "jwt-secret", cfg.JWTSecret, "secret used to sign access tokens")
	fs.DurationVar(&cfg.AccessTokenTTL.Duration, "access-token-ttl", cfg.AccessTokenTTL.Duration, "access token lifetime")
	fs.DurationVar(&cfg.RefreshTokenTTL.Duration, "refresh-token-ttl", cfg.RefreshTokenTTL.Duration, "refresh token lifetime")
	fs.DurationVar(&cfg.ChallengeTTL.Duration, "challenge-ttl", cfg.ChallengeTTL.Duration, "login challenge nonce lifetime")
	fs.DurationVar(&cfg.IdempotencyTTL.Duration, "idempotency-ttl", cfg.IdempotencyTTL.Duration, "idempotency record retention period")
	fs.IntVar(&cfg.LoginMaxAttempts, "login-max-attempts", cfg.LoginMaxAttempts, "failed login attempts allowed per window")
	fs.DurationVar(&cfg.LoginWindow.Duration, "login-window", cfg.LoginWindow.Duration, "login rate-limit sliding window")
	fs.BoolVar(&cfg.TLSEnabled, "tls-enabled", cfg.TLSEnabled, "enable HTTPS")
	fs.StringVar(&cfg.TLSCertFile, "tls-cert-file", cfg.TLSCertFile, "path to TLS certificate file")
	fs.StringVar(&cfg.TLSKeyFile, "tls-key-file", cfg.TLSKeyFile, "path to TLS private key file")
	fs.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "log level (debug, info, warn, error)")

	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("parse flags: %w", err)
	}
	return nil
}
