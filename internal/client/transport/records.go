package transport

import (
	"context"
	"fmt"

	"github.com/alexvictorne/voldepass/internal/domain"
)

// CreateRecord создаёт новую запись на сервере.
func (c *Client) CreateRecord(ctx context.Context, rec domain.RecordDTO) (domain.RecordDTO, error) {
	var out domain.RecordDTO
	if err := c.doAuthenticatedJSON(ctx, "POST", "/api/v1/records", rec, &out, nil); err != nil {
		return domain.RecordDTO{}, fmt.Errorf("create record: %w", err)
	}
	return out, nil
}

// GetRecord возвращает запись по ID.
func (c *Client) GetRecord(ctx context.Context, id string) (domain.RecordDTO, error) {
	var out domain.RecordDTO
	if err := c.doAuthenticatedJSON(ctx, "GET", "/api/v1/records/"+id, nil, &out, nil); err != nil {
		return domain.RecordDTO{}, fmt.Errorf("get record: %w", err)
	}
	return out, nil
}

// ListRecords возвращает все записи владельца.
func (c *Client) ListRecords(ctx context.Context) ([]domain.RecordDTO, error) {
	var out []domain.RecordDTO
	if err := c.doAuthenticatedJSON(ctx, "GET", "/api/v1/records", nil, &out, nil); err != nil {
		return nil, fmt.Errorf("list records: %w", err)
	}
	return out, nil
}

// UpdateRecord обновляет запись с optimistic locking по BaseVersion.
func (c *Client) UpdateRecord(ctx context.Context, rec domain.RecordDTO) (domain.RecordDTO, error) {
	var out domain.RecordDTO
	if err := c.doAuthenticatedJSON(ctx, "PUT", "/api/v1/records/"+rec.ID, rec, &out, nil); err != nil {
		return domain.RecordDTO{}, fmt.Errorf("update record: %w", err)
	}
	return out, nil
}

// DeleteRecord помечает запись как удалённую (tombstone).
func (c *Client) DeleteRecord(ctx context.Context, id string) error {
	if err := c.doAuthenticatedJSON(ctx, "DELETE", "/api/v1/records/"+id, nil, nil, nil); err != nil {
		return fmt.Errorf("delete record: %w", err)
	}
	return nil
}
