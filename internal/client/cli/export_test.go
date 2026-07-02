package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/alexvictorne/voldepass/internal/domain"
)

func TestExportImport_RoundTrip(t *testing.T) {
	srv := newLiveServer(t)
	defer srv.Close()
	ctx := context.Background()
	cfg := testConfig(srv, filepath.Join(t.TempDir(), "storage.vp"))
	require.NoError(t, runRegister(ctx, cfg, "alice", "master-password", &bytes.Buffer{}))
	require.NoError(t, runAdd(ctx, cfg, "alice", "master-password", domain.DataTypeText,
		payloadFlags{content: "backup-me"}, &bytes.Buffer{}))

	bundlePath := filepath.Join(t.TempDir(), "backup.vpenc")
	var exportOut bytes.Buffer
	require.NoError(t, runExport(ctx, cfg, "alice", "master-password", bundlePath, &exportOut))
	assert.Contains(t, exportOut.String(), "exported 1 record")

	// Импортируем в чистое хранилище того же аккаунта.
	cfg2 := testConfig(srv, filepath.Join(t.TempDir(), "storage2.vp"))
	var importOut bytes.Buffer
	require.NoError(t, runImport(ctx, cfg2, "alice", "master-password", bundlePath, &importOut))
	assert.Contains(t, importOut.String(), "imported 1 record")

	var listOut bytes.Buffer
	require.NoError(t, runList(ctx, cfg2, "alice", "master-password", &listOut))
	assert.NotEmpty(t, listOut.String())
}

func TestImport_WrongAccountPasswordFails(t *testing.T) {
	srv := newLiveServer(t)
	defer srv.Close()
	ctx := context.Background()
	cfg := testConfig(srv, filepath.Join(t.TempDir(), "storage.vp"))
	require.NoError(t, runRegister(ctx, cfg, "alice", "alice-password", &bytes.Buffer{}))
	require.NoError(t, runAdd(ctx, cfg, "alice", "alice-password", domain.DataTypeText,
		payloadFlags{content: "x"}, &bytes.Buffer{}))

	bundlePath := filepath.Join(t.TempDir(), "backup.vpenc")
	require.NoError(t, runExport(ctx, cfg, "alice", "alice-password", bundlePath, &bytes.Buffer{}))

	// Другой аккаунт с другим dataKey не может импортировать чужой бандл.
	cfg2 := testConfig(srv, filepath.Join(t.TempDir(), "storage2.vp"))
	require.NoError(t, runRegister(ctx, cfg2, "bob", "bob-password", &bytes.Buffer{}))
	err := runImport(ctx, cfg2, "bob", "bob-password", bundlePath, &bytes.Buffer{})
	assert.Error(t, err)
}
