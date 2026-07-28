package rest

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/rs/zerolog"

	"github.com/alexvictorne/voldepass/internal/domain"
)

// errorResponse — тело JSON-ответа при ошибке.
type errorResponse struct {
	Error string `json:"error"`
}

// writeError маппит доменную ошибку в HTTP-статус и пишет JSON-тело. Ошибки,
// приводящие к 5xx (внутренние, не размеченные ни одним доменным sentinel),
// дополнительно логируются — иначе оператор видит в RequestLogger только
// "status": 500 и не знает, что именно сломалось на сервере. 4xx — штатные
// (валидация, авторизация и т.п.) и логированием только засоряли бы лог.
func writeError(log zerolog.Logger, w http.ResponseWriter, err error) {
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

	// 5xx — незамаппленная внутренняя ошибка (БД, внутренние пути и т.п.), её текст
	// не должен уходить клиенту: это раскрывает внутреннее устройство сервера.
	// Полный err уже залогирован ниже; клиенту — только нейтральный http.StatusText.
	msg := err.Error()
	if status >= http.StatusInternalServerError {
		log.Error().Err(err).Msg("internal server error")
		msg = http.StatusText(status)
	}

	writeJSON(w, status, errorResponse{Error: msg})
}

// writeJSON пишет статус и JSON-тело в ответ.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
