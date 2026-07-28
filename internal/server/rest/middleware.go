package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/alexvictorne/voldepass/internal/domain"
	"github.com/alexvictorne/voldepass/internal/server/service"
)

type ctxKey int

// ctxKeyUserID — ключ контекста для userID, извлечённого JWT-middleware.
const ctxKeyUserID ctxKey = iota

// jwtParser — минимальный интерфейс, нужный AuthMiddleware для проверки access-токена.
type jwtParser interface {
	Parse(tokenStr string) (userID string, err error)
}

// AuthMiddleware проверяет Bearer-токен из заголовка Authorization и кладёт userID в контекст.
func AuthMiddleware(jwt jwtParser, log zerolog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			token, ok := strings.CutPrefix(header, "Bearer ")
			if !ok || token == "" {
				writeError(log, w, domain.ErrUnauthorized)
				return
			}

			userID, err := jwt.Parse(token)
			if err != nil {
				writeError(log, w, domain.ErrUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), ctxKeyUserID, userID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequestLogger возвращает middleware, логирующее каждый запрос одной структурной
// записью (method, path, status, размер ответа, длительность, request ID) через
// zerolog. Тело запроса/ответа не логируется — только чужие приватные данные.
func RequestLogger(log zerolog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

			next.ServeHTTP(ww, r)

			log.Info().
				Str("method", r.Method).
				Str("path", r.URL.Path).
				Int("status", ww.Status()).
				Int("bytes", ww.BytesWritten()).
				Dur("duration", time.Since(start)).
				Str("request_id", middleware.GetReqID(r.Context())).
				Msg("http request")
		})
	}
}

// maxLoginRequestBodyBytes ограничивает тело запроса, которое LoginRateLimit читает
// в память целиком для извлечения "login" — без этого лимита клиент мог бы отправить
// произвольно большое тело и заставить сервер вычитать его целиком до валидации.
const maxLoginRequestBodyBytes = 1 << 20 // 1 MiB — с большим запасом на реальный login-запрос

// Лимиты тела запроса для остальных JSON-эндпоинтов — без них json.NewDecoder вычитывает
// r.Body в память целиком, произвольного размера, до какой-либо валидации содержимого
// (см. README, раздел "Лимиты размера запроса").
const (
	// maxAuthRequestBodyBytes — Register/Challenge/Refresh не требуют авторизации, поэтому
	// доступны анонимно; их payload — только KDF-параметры и ключевой материал фиксированного
	// небольшого размера (verifier/salt/wrapped key — десятки байт), 64 KiB — щедрый запас.
	maxAuthRequestBodyBytes = 64 << 10 // 64 KiB

	// maxRecordRequestBodyBytes — тело одной записи (Create/Update). Основная часть —
	// ciphertext; для типа Binary это может быть небольшое вложение (файл/картинка),
	// поэтому лимит заметно выше, чем для auth-эндпоинтов.
	maxRecordRequestBodyBytes = 10 << 20 // 10 MiB

	// maxSyncPushRequestBodyBytes — пачка записей за один push (клиент по умолчанию шлёт
	// чанками по 100 записей, см. defaultChunkSize в client/service/syncer.go), поэтому
	// лимит батча выше, чем для одной записи, но всё ещё ограничен.
	maxSyncPushRequestBodyBytes = 50 << 20 // 50 MiB
)

// LoginRateLimit возвращает middleware, отклоняющее запрос 429-м до вызова хендлера,
// если LoginAttemptTracker.Allowed говорит, что логин уже превысил лимит попыток —
// это позволяет отсечь превышающие лимит запросы максимально рано, ещё до разбора
// challenge-response верификации в AuthService.Login. Инкремент/сброс счётчика по
// результату верификации остаётся в AuthService (только он знает, удался ли вход) —
// здесь только чтение уже накопленного состояния.
//
// Тело запроса читается один раз для извлечения "login" и восстанавливается для
// хендлера. Если тело не парсится как JSON с полем login — не блокируем: невалидное
// тело так и так будет отклонено самим хендлером (400), а не молча пропущено.
func LoginRateLimit(tracker service.LoginAttemptTracker, log zerolog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxLoginRequestBodyBytes)
			body, err := io.ReadAll(r.Body)
			if err != nil {
				writeDecodeError(log, w, err)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))

			var req struct {
				Login string `json:"login"`
			}
			if err := json.Unmarshal(body, &req); err != nil || req.Login == "" {
				next.ServeHTTP(w, r)
				return
			}

			allowed, err := tracker.Allowed(r.Context(), req.Login)
			if err != nil {
				writeError(log, w, fmt.Errorf("check login rate limit: %w", err))
				return
			}
			if !allowed {
				writeError(log, w, domain.ErrRateLimited)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// userIDFromContext извлекает userID, положенный AuthMiddleware.
func userIDFromContext(ctx context.Context) (string, error) {
	userID, ok := ctx.Value(ctxKeyUserID).(string)
	if !ok || userID == "" {
		return "", domain.ErrUnauthorized
	}
	return userID, nil
}

// apiVersionMajor извлекает major-компонент версии из строки вида "1.2.3".
func apiVersionMajor(v string) string {
	parts := strings.SplitN(v, ".", 2)
	return parts[0]
}

// CheckAPIVersion проверяет заголовок X-API-Version против domain.APIVersion.
// При несовпадении major-версии возвращает 426 Upgrade Required.
// Заголовок необязателен: клиенты без него (напр. старые версии) не блокируются.
func CheckAPIVersion(next http.Handler) http.Handler {
	serverMajor := apiVersionMajor(domain.APIVersion)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientVersion := r.Header.Get("X-API-Version")
		if clientVersion == "" {
			next.ServeHTTP(w, r)
			return
		}
		if apiVersionMajor(clientVersion) != serverMajor {
			w.Header().Set("X-API-Version", domain.APIVersion)
			writeJSON(w, http.StatusUpgradeRequired, errorResponse{
				Error: "incompatible API version: server supports " + domain.APIVersion,
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// parseSinceVersion парсит query-параметр since как int64 (0 по умолчанию).
func parseSinceVersion(r *http.Request) (int64, error) {
	raw := r.URL.Query().Get("since")
	if raw == "" {
		return 0, nil
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, domain.ErrInvalidArgument
	}
	return v, nil
}

// validateRecordID проверяет, что id — валидный UUID (записи/пользователи/refresh-токены
// хранятся в Postgres как колонки типа UUID). Без этой проверки на границе транспорта
// невалидный id доходит до репозитория и падает с "сырой" ошибкой формата от драйвера БД,
// которая маппится в 500 вместо ожидаемого 400.
func validateRecordID(id string) error {
	if _, err := uuid.Parse(id); err != nil {
		return fmt.Errorf("%w: id must be a valid UUID", domain.ErrInvalidArgument)
	}
	return nil
}

// maxShortDBStringLength — верхняя граница для строковых полей, хранимых как VARCHAR(200)
// (users.login, idempotency_keys.key — см. migrations/000001_init.up.sql). Без проверки на
// границе транспорта слишком длинное значение долетает до Postgres и падает с "сырой"
// ошибкой формата колонки вместо аккуратного 400.
const maxShortDBStringLength = 200

// validateShortString проверяет, что value не превышает maxShortDBStringLength байт.
func validateShortString(field, value string) error {
	if len(value) > maxShortDBStringLength {
		return fmt.Errorf("%w: %s must be at most %d bytes", domain.ErrInvalidArgument, field, maxShortDBStringLength)
	}
	return nil
}
