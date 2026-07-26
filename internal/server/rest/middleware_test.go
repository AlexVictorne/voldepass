package rest

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/alexvictorne/voldepass/internal/domain"
	"github.com/alexvictorne/voldepass/internal/server/auth"
	"github.com/alexvictorne/voldepass/internal/server/storage/inmem"
)

func TestAuthMiddleware_ValidToken(t *testing.T) {
	jwt := auth.NewJWTManager([]byte("secret-32-bytes-long-enough-pad"), time.Minute)
	token, _ := jwt.Issue("user-1")

	var gotUserID string
	handler := AuthMiddleware(jwt)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUserID, _ = userIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "user-1", gotUserID)
}

func TestAuthMiddleware_MissingHeader(t *testing.T) {
	jwt := auth.NewJWTManager([]byte("secret-32-bytes-long-enough-pad"), time.Minute)
	handler := AuthMiddleware(jwt)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestAuthMiddleware_InvalidToken(t *testing.T) {
	jwt := auth.NewJWTManager([]byte("secret-32-bytes-long-enough-pad"), time.Minute)
	handler := AuthMiddleware(jwt)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer garbage")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestCheckAPIVersion_Compatible(t *testing.T) {
	handler := CheckAPIVersion(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-API-Version", domain.APIVersion)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestCheckAPIVersion_Missing(t *testing.T) {
	handler := CheckAPIVersion(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code, "missing header must not block request")
}

func TestCheckAPIVersion_IncompatibleMajor(t *testing.T) {
	handler := CheckAPIVersion(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-API-Version", "99.0.0")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUpgradeRequired, rec.Code)
}

func TestLoginRateLimit_AllowsUntilLimitExceeded(t *testing.T) {
	tracker := inmem.NewLoginAttemptTracker(2, time.Minute)
	var calls int
	handler := LoginRateLimit(tracker)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))

	body := []byte(`{"login":"alice","auth_msg":"AAAA"}`)

	// В пределах лимита (2 попытки) хендлер должен вызываться — Allowed() сам по себе
	// не расходует лимит, только Inc() при неудачной попытке в AuthService.
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/login", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	}
	assert.Equal(t, 5, calls, "Allowed() alone must not block repeated requests without Inc()")

	// Исчерпываем лимит через Inc(), как это делает AuthService при неудачном входе.
	require.NoError(t, tracker.Inc(t.Context(), "alice"))
	require.NoError(t, tracker.Inc(t.Context(), "alice"))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/login", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.Equal(t, 5, calls, "handler must not be called once the limit is exceeded")
}

func TestLoginRateLimit_RestoresBodyForHandler(t *testing.T) {
	tracker := inmem.NewLoginAttemptTracker(5, time.Minute)
	var gotBody string
	handler := LoginRateLimit(tracker)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
	}))

	body := `{"login":"bob","auth_msg":"AAAA"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/login", bytes.NewReader([]byte(body)))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, body, gotBody, "request body read by the middleware must still reach the handler")
}

func TestLoginRateLimit_InvalidJSONPassesThroughToHandler(t *testing.T) {
	tracker := inmem.NewLoginAttemptTracker(5, time.Minute)
	var called bool
	handler := LoginRateLimit(tracker)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusBadRequest)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/login", bytes.NewReader([]byte("not json")))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.True(t, called, "malformed body must be left for the handler to reject, not silently swallowed")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestRequestLogger_LogsMethodPathStatus(t *testing.T) {
	var buf bytes.Buffer
	log := zerolog.New(&buf)

	handler := middleware.RequestID(RequestLogger(log)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("short body"))
	})))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/records", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var entry map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &entry))
	assert.Equal(t, http.MethodPost, entry["method"])
	assert.Equal(t, "/api/v1/records", entry["path"])
	assert.Equal(t, float64(http.StatusTeapot), entry["status"])
	assert.Equal(t, float64(len("short body")), entry["bytes"])
	assert.NotEmpty(t, entry["request_id"], "request ID from middleware.RequestID must be present in the log line")
	assert.Contains(t, entry, "duration")
}

func TestRequestLogger_DoesNotBlockOrAlterResponse(t *testing.T) {
	log := zerolog.Nop()
	handler := RequestLogger(log)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("body"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusCreated, rec.Code)
	assert.Equal(t, "body", rec.Body.String())
}

func TestParseSinceVersion_Default(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	v, err := parseSinceVersion(req)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), v)
}

func TestParseSinceVersion_Valid(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/?since=42", nil)
	v, err := parseSinceVersion(req)
	assert.NoError(t, err)
	assert.Equal(t, int64(42), v)
}

func TestParseSinceVersion_Invalid(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/?since=abc", nil)
	_, err := parseSinceVersion(req)
	assert.ErrorIs(t, err, domain.ErrInvalidArgument)
}

func TestWriteError_StatusMapping(t *testing.T) {
	cases := []struct {
		err    error
		status int
	}{
		{domain.ErrNotFound, http.StatusNotFound},
		{domain.ErrConflict, http.StatusConflict},
		{domain.ErrUnauthorized, http.StatusUnauthorized},
		{domain.ErrAlreadyExists, http.StatusConflict},
		{domain.ErrRateLimited, http.StatusTooManyRequests},
		{domain.ErrInvalidArgument, http.StatusBadRequest},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		writeError(rec, tc.err)
		assert.Equal(t, tc.status, rec.Code, "for error %v", tc.err)
	}
}
