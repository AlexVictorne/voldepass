package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/alexvictorne/voldepass/internal/domain"
)

// idempotencyTTL — время жизни сохранённого результата Push-операции.
const idempotencyTTL = 24 * time.Hour

// SyncService реализует Pull/Push синхронизации записей между клиентом и сервером.
type SyncService struct {
	records     RecordRepository
	idempotency IdempotencyStore
}

// NewSyncService создаёт сервис синхронизации.
func NewSyncService(records RecordRepository, idempotency IdempotencyStore) *SyncService {
	return &SyncService{records: records, idempotency: idempotency}
}

// Pull возвращает все записи владельца, изменённые после sinceVersion.
func (s *SyncService) Pull(ctx context.Context, ownerID string, sinceVersion int64) (domain.SyncPullResponse, error) {
	recs, err := s.records.ListSince(ctx, ownerID, sinceVersion)
	if err != nil {
		return domain.SyncPullResponse{}, fmt.Errorf("pull: %w", err)
	}

	dtos := make([]domain.RecordDTO, len(recs))
	for i, r := range recs {
		dtos[i] = recordToDTO(r)
	}
	return domain.SyncPullResponse{Records: dtos}, nil
}

// Push применяет пачку записей клиента с optimistic locking.
// Повторный вызов с тем же idempotencyKey возвращает сохранённый результат без повторного применения.
func (s *SyncService) Push(ctx context.Context, ownerID, idempotencyKey string, req domain.SyncPushRequest) (domain.SyncPushResponse, error) {
	if cached, err := s.idempotency.Get(ctx, ownerID, idempotencyKey); err == nil {
		var resp domain.SyncPushResponse
		if err := json.Unmarshal(cached, &resp); err != nil {
			return domain.SyncPushResponse{}, fmt.Errorf("push: unmarshal cached result: %w", err)
		}
		return resp, nil
	} else if !errors.Is(err, domain.ErrNotFound) {
		return domain.SyncPushResponse{}, fmt.Errorf("push: check idempotency: %w", err)
	}

	results := make([]domain.PushResult, len(req.Records))
	for i, dto := range req.Records {
		rec := dtoToRecord(dto, ownerID)

		saved, err := s.records.Upsert(ctx, rec, dto.BaseVersion)
		switch {
		case errors.Is(err, domain.ErrConflict):
			results[i] = domain.PushResult{
				ID:           dto.ID,
				Status:       domain.PushStatusConflict,
				ServerRecord: recordToDTO(saved),
			}
		case err != nil:
			return domain.SyncPushResponse{}, fmt.Errorf("push: upsert record %s: %w", dto.ID, err)
		default:
			results[i] = domain.PushResult{
				ID:           dto.ID,
				Status:       domain.PushStatusApplied,
				ServerRecord: recordToDTO(saved),
			}
		}
	}

	resp := domain.SyncPushResponse{Results: results}

	encoded, err := json.Marshal(resp)
	if err != nil {
		return domain.SyncPushResponse{}, fmt.Errorf("push: marshal result: %w", err)
	}
	if err := s.idempotency.Save(ctx, ownerID, idempotencyKey, encoded, idempotencyTTL); err != nil {
		return domain.SyncPushResponse{}, fmt.Errorf("push: save idempotency result: %w", err)
	}

	return resp, nil
}

func recordToDTO(r domain.Record) domain.RecordDTO {
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

func dtoToRecord(dto domain.RecordDTO, ownerID string) domain.Record {
	return domain.Record{
		ID:            dto.ID,
		OwnerID:       ownerID,
		Type:          dto.Type,
		EncryptedMeta: dto.EncryptedMeta,
		MetaNonce:     dto.MetaNonce,
		Ciphertext:    dto.Ciphertext,
		Nonce:         dto.Nonce,
		Deleted:       dto.IsDeleted,
	}
}
