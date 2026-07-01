package rest

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/alexvictorne/voldepass/internal/domain"
	"github.com/alexvictorne/voldepass/internal/server/auth"
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
