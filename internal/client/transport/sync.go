package transport

import (
	"context"
	"fmt"

	"github.com/alexvictorne/voldepass/internal/domain"
)

// Pull запрашивает все записи владельца, изменённые после sinceVersion.
func (c *Client) Pull(ctx context.Context, sinceVersion int64) (domain.SyncPullResponse, error) {
	path := fmt.Sprintf("/api/v1/sync?since=%d", sinceVersion)
	var out domain.SyncPullResponse
	if err := c.doAuthenticatedJSON(ctx, "GET", path, nil, &out, nil); err != nil {
		return domain.SyncPullResponse{}, fmt.Errorf("pull: %w", err)
	}
	return out, nil
}

// Push отправляет пачку изменённых записей с ключом идемпотентности.
// idempotencyKey должен персистироваться на стороне вызывающего до получения ACK,
// чтобы повтор после сбоя/рестарта переиспользовал тот же ключ (см. Syncer, Слой 8).
func (c *Client) Push(ctx context.Context, idempotencyKey string, req domain.SyncPushRequest) (domain.SyncPushResponse, error) {
	var out domain.SyncPushResponse
	headers := map[string]string{"Idempotency-Key": idempotencyKey}
	if err := c.doAuthenticatedJSON(ctx, "POST", "/api/v1/sync", req, &out, headers); err != nil {
		return domain.SyncPushResponse{}, fmt.Errorf("push: %w", err)
	}
	return out, nil
}
