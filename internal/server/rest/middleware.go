package rest

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/alexvictorne/voldepass/internal/domain"
)

type ctxKey int

// ctxKeyUserID — ключ контекста для userID, извлечённого JWT-middleware.
const ctxKeyUserID ctxKey = iota

// jwtParser — минимальный интерфейс, нужный AuthMiddleware для проверки access-токена.
type jwtParser interface {
	Parse(tokenStr string) (userID string, err error)
}

// AuthMiddleware проверяет Bearer-токен из заголовка Authorization и кладёт userID в контекст.
func AuthMiddleware(jwt jwtParser) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			token, ok := strings.CutPrefix(header, "Bearer ")
			if !ok || token == "" {
				writeError(w, domain.ErrUnauthorized)
				return
			}

			userID, err := jwt.Parse(token)
			if err != nil {
				writeError(w, domain.ErrUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), ctxKeyUserID, userID)
			next.ServeHTTP(w, r.WithContext(ctx))
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
