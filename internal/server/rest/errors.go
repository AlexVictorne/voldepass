package rest

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/alexvictorne/voldepass/internal/domain"
)

// errorResponse — тело JSON-ответа при ошибке.
type errorResponse struct {
	Error string `json:"error"`
}

// writeError маппит доменную ошибку в HTTP-статус и пишет JSON-тело.
func writeError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, domain.ErrNotFound):
		status = http.StatusNotFound
	case errors.Is(err, domain.ErrConflict):
		status = http.StatusConflict
	case errors.Is(err, domain.ErrUnauthorized):
		status = http.StatusUnauthorized
	case errors.Is(err, domain.ErrAlreadyExists):
		status = http.StatusConflict
	case errors.Is(err, domain.ErrRateLimited):
		status = http.StatusTooManyRequests
	case errors.Is(err, domain.ErrInvalidArgument):
		status = http.StatusBadRequest
	}

	writeJSON(w, status, errorResponse{Error: err.Error()})
}

// writeJSON пишет статус и JSON-тело в ответ.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
