package service

import (
	"context"
	"fmt"

	"github.com/alexvictorne/voldepass/internal/domain"
)

// VaultService реализует CRUD-операции над зашифрованными записями с проверкой владельца.
type VaultService struct {
	records RecordRepository
}

// NewVaultService создаёт сервис хранилища записей.
func NewVaultService(records RecordRepository) *VaultService {
	return &VaultService{records: records}
}

// Create сохраняет новую запись, принадлежащую ownerID.
func (s *VaultService) Create(ctx context.Context, ownerID string, rec domain.Record) (domain.Record, error) {
	rec.ID = newID()
	rec.OwnerID = ownerID
	saved, err := s.records.Upsert(ctx, rec, 0)
	if err != nil {
		return domain.Record{}, fmt.Errorf("create record: %w", err)
	}
	return saved, nil
}

// Update обновляет существующую запись с optimistic locking по baseVersion.
// Возвращает ErrUnauthorized, если запись принадлежит другому владельцу.
func (s *VaultService) Update(ctx context.Context, ownerID string, rec domain.Record, baseVersion int64) (domain.Record, error) {
	if err := s.checkOwner(ctx, rec.ID, ownerID); err != nil {
		return domain.Record{}, err
	}
	rec.OwnerID = ownerID
	saved, err := s.records.Upsert(ctx, rec, baseVersion)
	if err != nil {
		return domain.Record{}, fmt.Errorf("update record: %w", err)
	}
	return saved, nil
}

// Get возвращает запись по ID, если она принадлежит ownerID.
func (s *VaultService) Get(ctx context.Context, ownerID, id string) (domain.Record, error) {
	rec, err := s.records.Get(ctx, id, ownerID)
	if err != nil {
		return domain.Record{}, fmt.Errorf("get record: %w", err)
	}
	return rec, nil
}

// List возвращает все записи владельца, изменённые после sinceVersion.
func (s *VaultService) List(ctx context.Context, ownerID string, sinceVersion int64) ([]domain.Record, error) {
	recs, err := s.records.ListSince(ctx, ownerID, sinceVersion)
	if err != nil {
		return nil, fmt.Errorf("list records: %w", err)
	}
	return recs, nil
}

// Delete помечает запись как удалённую (tombstone), если она принадлежит ownerID.
func (s *VaultService) Delete(ctx context.Context, ownerID, id string) error {
	if err := s.checkOwner(ctx, id, ownerID); err != nil {
		return err
	}
	if err := s.records.Delete(ctx, id, ownerID); err != nil {
		return fmt.Errorf("delete record: %w", err)
	}
	return nil
}

// checkOwner проверяет, что запись принадлежит ownerID, до применения мутации.
func (s *VaultService) checkOwner(ctx context.Context, id, ownerID string) error {
	_, err := s.records.Get(ctx, id, ownerID)
	if err != nil {
		return fmt.Errorf("%w", domain.ErrUnauthorized)
	}
	return nil
}
