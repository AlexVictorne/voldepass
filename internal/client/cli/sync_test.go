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

func TestRunSync_NoDirtyRecords(t *testing.T) {
	srv := newLiveServer(t)
	defer srv.Close()
	cfg := testConfig(srv, filepath.Join(t.TempDir(), "storage.vp"))
	ctx := context.Background()
	require.NoError(t, runRegister(ctx, cfg, "alice", "master-password", &bytes.Buffer{}))

	var out bytes.Buffer
	require.NoError(t, runSync(ctx, cfg, "alice", "master-password", &out))
	assert.Contains(t, out.String(), "sync completed")
}

func TestRunSync_PropagatesAcrossDevices(t *testing.T) {
	srv := newLiveServer(t)
	defer srv.Close()
	ctx := context.Background()

	cfg1 := testConfig(srv, filepath.Join(t.TempDir(), "storage1.vp"))
	require.NoError(t, runRegister(ctx, cfg1, "alice", "master-password", &bytes.Buffer{}))
	require.NoError(t, runAdd(ctx, cfg1, "alice", "master-password", domain.DataTypeText,
		payloadFlags{content: "shared-note"}, &bytes.Buffer{}))

	cfg2 := testConfig(srv, filepath.Join(t.TempDir(), "storage2.vp"))
	var out bytes.Buffer
	require.NoError(t, runSync(ctx, cfg2, "alice", "master-password", &out))

	var listOut bytes.Buffer
	require.NoError(t, runList(ctx, cfg2, "alice", "master-password", &listOut))
	assert.NotEmpty(t, listOut.String(), "record created on another device must be visible after sync")
}
