// Пакет transport реализует HTTP-клиент Voldepass поверх go-retryablehttp:
// двухфазный login, автоматический рефреш access-токена, X-API-Version,
// опциональный certificate pinning.
package transport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/hashicorp/go-retryablehttp"

	"github.com/alexvictorne/voldepass/internal/domain"
)

// Options настраивает создание Client.
type Options struct {
	// BaseURL — адрес сервера, например "https://voldepass.example.com".
	BaseURL string
	// MaxRetries — число повторов при сетевых ошибках/5xx.
	MaxRetries int
	// PinnedFingerprint — hex SHA-256 отпечаток публичного ключа сертификата сервера.
	// Пусто — pinning отключён (используется системный пул доверенных CA).
	PinnedFingerprint string
}

// Client — типизированная обёртка над retryablehttp.Client для Voldepass API.
type Client struct {
	http         *retryablehttp.Client
	baseURL      string
	accessToken  string
	refreshToken string
}

// New создаёт Client с настроенным TLS (опционально с pinning) и ретраями.
func New(opts Options) (*Client, error) {
	httpClient := retryablehttp.NewClient()
	httpClient.RetryMax = opts.MaxRetries
	httpClient.Logger = nil // подавляем встроенное логирование retryablehttp

	if opts.PinnedFingerprint != "" {
		transport, err := pinnedTransport(opts.PinnedFingerprint)
		if err != nil {
			return nil, fmt.Errorf("configure certificate pinning: %w", err)
		}
		httpClient.HTTPClient.Transport = transport
	}

	return &Client{
		http:    httpClient,
		baseURL: opts.BaseURL,
	}, nil
}

// pinnedTransport создаёт http.Transport, проверяющий отпечаток сертификата сервера
// через VerifyPeerCertificate вместо стандартной цепочки доверия.
func pinnedTransport(hexFingerprint string) (*http.Transport, error) {
	return &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // проверка выполняется вручную ниже через pinning
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				for _, raw := range rawCerts {
					sum := sha256.Sum256(raw)
					if fmt.Sprintf("%x", sum) == hexFingerprint {
						return nil
					}
				}
				return fmt.Errorf("certificate pinning: no certificate matched fingerprint %s", hexFingerprint)
			},
		},
	}, nil
}

// SetTokens устанавливает access и refresh токены текущей сессии.
func (c *Client) SetTokens(accessToken, refreshToken string) {
	c.accessToken = accessToken
	c.refreshToken = refreshToken
}

// Tokens возвращает текущие access и refresh токены.
func (c *Client) Tokens() (accessToken, refreshToken string) {
	return c.accessToken, c.refreshToken
}

// apiError — ошибка, обёрнутая с сохранением HTTP-статуса для доменного маппинга.
type apiError struct {
	status int
	body   string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("api error: status=%d body=%s", e.status, e.body)
}

// mapStatusToDomainErr маппит HTTP-статус ответа сервера в доменную ошибку клиента.
func mapStatusToDomainErr(status int, body string) error {
	switch status {
	case http.StatusNotFound:
		return fmt.Errorf("%w: %s", domain.ErrNotFound, body)
	case http.StatusConflict:
		return fmt.Errorf("%w: %s", domain.ErrConflict, body)
	case http.StatusUnauthorized:
		return fmt.Errorf("%w: %s", domain.ErrUnauthorized, body)
	case http.StatusTooManyRequests:
		return fmt.Errorf("%w: %s", domain.ErrRateLimited, body)
	case http.StatusBadRequest:
		return fmt.Errorf("%w: %s", domain.ErrInvalidArgument, body)
	case http.StatusUpgradeRequired:
		return fmt.Errorf("incompatible API version, upgrade required: %s", body)
	default:
		return &apiError{status: status, body: body}
	}
}

// doJSON выполняет HTTP-запрос с JSON-телом и декодирует JSON-ответ в out (если не nil).
// authenticated добавляет заголовок Authorization с текущим access-токеном.
func (c *Client) doJSON(ctx context.Context, method, path string, in, out any, authenticated bool, extraHeaders map[string]string) (*http.Response, error) {
	var body io.Reader
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return nil, fmt.Errorf("marshal request body: %w", err)
		}
		body = bytes.NewReader(data)
	}

	req, err := retryablehttp.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Version", domain.APIVersion)
	if authenticated {
		req.Header.Set("Authorization", "Bearer "+c.accessToken)
	}
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode >= 400 {
		return resp, mapStatusToDomainErr(resp.StatusCode, string(respBody))
	}

	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return resp, fmt.Errorf("unmarshal response body: %w", err)
		}
	}
	return resp, nil
}

// doAuthenticatedJSON выполняет аутентифицированный запрос; при 401 прозрачно
// обновляет access-токен через Refresh и повторяет запрос один раз.
// Если Refresh тоже проваливается — возвращает ErrUnauthorized (нужен полный login).
func (c *Client) doAuthenticatedJSON(ctx context.Context, method, path string, in, out any, extraHeaders map[string]string) error {
	_, err := c.doJSON(ctx, method, path, in, out, true, extraHeaders)
	if err == nil {
		return nil
	}
	if !errors.Is(err, domain.ErrUnauthorized) {
		return err
	}

	if refreshErr := c.Refresh(ctx); refreshErr != nil {
		return fmt.Errorf("%w: session expired and refresh failed: %v", domain.ErrUnauthorized, refreshErr)
	}

	if _, err := c.doJSON(ctx, method, path, in, out, true, extraHeaders); err != nil {
		return err
	}
	return nil
}
