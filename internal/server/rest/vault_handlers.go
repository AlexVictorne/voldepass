package rest

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/alexvictorne/voldepass/internal/domain"
)

// vaultService — интерфейс, требуемый VaultHandlers. Реализуется service.VaultService.
type vaultService interface {
	Create(ctx context.Context, ownerID string, rec domain.Record) (domain.Record, error)
	Update(ctx context.Context, ownerID string, rec domain.Record, baseVersion int64) (domain.Record, error)
	Get(ctx context.Context, ownerID, id string) (domain.Record, error)
	List(ctx context.Context, ownerID string, sinceVersion int64) ([]domain.Record, error)
	Delete(ctx context.Context, ownerID, id string) error
}

// VaultHandlers — HTTP-хендлеры CRUD-операций над записями.
type VaultHandlers struct {
	svc vaultService
}

// NewVaultHandlers создаёт хендлеры хранилища записей поверх сервиса.
func NewVaultHandlers(svc vaultService) *VaultHandlers {
	return &VaultHandlers{svc: svc}
}

type recordRequest struct {
	Type          domain.DataType `json:"type"`
	EncryptedMeta []byte          `json:"encrypted_meta,omitempty"`
	MetaNonce     []byte          `json:"meta_nonce,omitempty"`
	Ciphertext    []byte          `json:"ciphertext"`
	Nonce         []byte          `json:"nonce"`
	BaseVersion   int64           `json:"base_version,omitempty"`
}

// recordToResponse конвертирует запись в RecordDTO — единый JSON-контракт,
// общий с Sync API (см. sync_handlers.go), чтобы клиент использовал одну модель.
func recordToResponse(r domain.Record) domain.RecordDTO {
	return domain.RecordDTO{
		ID:            r.ID,
		Type:          r.Type,
		EncryptedMeta: r.EncryptedMeta,
		MetaNonce:     r.MetaNonce,
		Ciphertext:    r.Ciphertext,
		Nonce:         r.Nonce,
		Version:       r.Version,
		UpdatedAt:     r.UpdatedAt,
		IsDeleted:     r.Deleted,
	}
}

// Create обрабатывает POST /api/v1/records.
func (h *VaultHandlers) Create(w http.ResponseWriter, r *http.Request) {
	ownerID, err := userIDFromContext(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}

	var req recordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, domain.ErrInvalidArgument)
		return
	}

	rec, err := h.svc.Create(r.Context(), ownerID, domain.Record{
		Type:          req.Type,
		EncryptedMeta: req.EncryptedMeta,
		MetaNonce:     req.MetaNonce,
		Ciphertext:    req.Ciphertext,
		Nonce:         req.Nonce,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, recordToResponse(rec))
}

// Get обрабатывает GET /api/v1/records/{id}.
func (h *VaultHandlers) Get(w http.ResponseWriter, r *http.Request) {
	ownerID, err := userIDFromContext(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}

	id := chi.URLParam(r, "id")
	rec, err := h.svc.Get(r.Context(), ownerID, id)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, recordToResponse(rec))
}

// List обрабатывает GET /api/v1/records.
func (h *VaultHandlers) List(w http.ResponseWriter, r *http.Request) {
	ownerID, err := userIDFromContext(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}

	since, err := parseSinceVersion(r)
	if err != nil {
		writeError(w, err)
		return
	}

	recs, err := h.svc.List(r.Context(), ownerID, since)
	if err != nil {
		writeError(w, err)
		return
	}

	resp := make([]domain.RecordDTO, len(recs))
	for i, rec := range recs {
		resp[i] = recordToResponse(rec)
	}
	writeJSON(w, http.StatusOK, resp)
}

// Update обрабатывает PUT /api/v1/records/{id}.
func (h *VaultHandlers) Update(w http.ResponseWriter, r *http.Request) {
	ownerID, err := userIDFromContext(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}

	id := chi.URLParam(r, "id")
	var req recordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, domain.ErrInvalidArgument)
		return
	}

	rec, err := h.svc.Update(r.Context(), ownerID, domain.Record{
		ID:            id,
		Type:          req.Type,
		EncryptedMeta: req.EncryptedMeta,
		MetaNonce:     req.MetaNonce,
		Ciphertext:    req.Ciphertext,
		Nonce:         req.Nonce,
	}, req.BaseVersion)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, recordToResponse(rec))
}

// Delete обрабатывает DELETE /api/v1/records/{id}.
func (h *VaultHandlers) Delete(w http.ResponseWriter, r *http.Request) {
	ownerID, err := userIDFromContext(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}

	id := chi.URLParam(r, "id")
	if err := h.svc.Delete(r.Context(), ownerID, id); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
