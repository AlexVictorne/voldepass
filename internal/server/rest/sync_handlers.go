package rest

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/rs/zerolog"

	"github.com/alexvictorne/voldepass/internal/domain"
)

// syncService — интерфейс, требуемый SyncHandlers. Реализуется service.SyncService.
type syncService interface {
	Pull(ctx context.Context, ownerID string, sinceVersion int64) (domain.SyncPullResponse, error)
	Push(ctx context.Context, ownerID, idempotencyKey string, req domain.SyncPushRequest) (domain.SyncPushResponse, error)
}

// SyncHandlers — HTTP-хендлеры синхронизации записей (Pull/Push).
type SyncHandlers struct {
	svc syncService
	log zerolog.Logger
}

// NewSyncHandlers создаёт хендлеры синхронизации поверх сервиса.
func NewSyncHandlers(svc syncService, log zerolog.Logger) *SyncHandlers {
	return &SyncHandlers{svc: svc, log: log}
}

// Pull godoc
//
//	@Summary		Pull changed records since a version
//	@Description	Returns every record owned by the authenticated user with version > since.
//	@Description	The client tracks the max version seen and passes it as `since` on the next call.
//	@Tags			sync
//	@Security		BearerAuth
//	@Produce		json
//	@Param			since	query		int	false	"Last known version (0 = full pull)"
//	@Success		200		{object}	domain.SyncPullResponse
//	@Failure		400		{object}	errorResponse
//	@Failure		401		{object}	errorResponse
//	@Router			/sync [get]
func (h *SyncHandlers) Pull(w http.ResponseWriter, r *http.Request) {
	ownerID, err := userIDFromContext(r.Context())
	if err != nil {
		writeError(h.log, w, err)
		return
	}

	since, err := parseSinceVersion(r)
	if err != nil {
		writeError(h.log, w, err)
		return
	}

	resp, err := h.svc.Pull(r.Context(), ownerID, since)
	if err != nil {
		writeError(h.log, w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// Push godoc
//
//	@Summary		Push a batch of locally changed records
//	@Description	Applies each record with optimistic locking on base_version. Requires an
//	@Description	Idempotency-Key header; retrying a push with the same key returns the
//	@Description	previously computed result instead of re-applying the batch. Records whose
//	@Description	base_version is stale come back with status "conflict" and the current
//	@Description	server record so the client can re-pull and merge.
//	@Tags			sync
//	@Security		BearerAuth
//	@Accept			json
//	@Produce		json
//	@Param			Idempotency-Key	header		string					true	"Client-generated idempotency key for this batch"
//	@Param			request			body		domain.SyncPushRequest	true	"Batch of changed records"
//	@Success		200				{object}	domain.SyncPushResponse
//	@Failure		400				{object}	errorResponse	"missing Idempotency-Key or malformed body"
//	@Failure		401				{object}	errorResponse
//	@Router			/sync [post]
func (h *SyncHandlers) Push(w http.ResponseWriter, r *http.Request) {
	ownerID, err := userIDFromContext(r.Context())
	if err != nil {
		writeError(h.log, w, err)
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		writeError(h.log, w, domain.ErrInvalidArgument)
		return
	}
	if err := validateShortString("Idempotency-Key", idempotencyKey); err != nil {
		writeError(h.log, w, err)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxSyncPushRequestBodyBytes)

	var req domain.SyncPushRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(h.log, w, domain.ErrInvalidArgument)
		return
	}

	for _, rec := range req.Records {
		if err := validateRecordID(rec.ID); err != nil {
			writeError(h.log, w, err)
			return
		}
		if !rec.Type.Valid() {
			writeError(h.log, w, domain.ErrInvalidArgument)
			return
		}
	}

	resp, err := h.svc.Push(r.Context(), ownerID, idempotencyKey, req)
	if err != nil {
		writeError(h.log, w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}
