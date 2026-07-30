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

func TestRunOTPGet(t *testing.T) {
	srv := newLiveServer(t)
	defer srv.Close()
	cfg := testConfig(srv, filepath.Join(t.TempDir(), "storage.vp"))
	ctx := context.Background()
	require.NoError(t, runRegister(ctx, cfg, "alice", "master-password", &bytes.Buffer{}))

	var addOut bytes.Buffer
	f := payloadFlags{
		secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", algorithm: "SHA1", digits: 6, period: 30,
	}
	require.NoError(t, runAdd(ctx, cfg, "alice", "master-password", domain.DataTypeOTP, f, &addOut))
	id := extractRecordID(t, addOut.String())

	var out bytes.Buffer
	require.NoError(t, runOTPGet(ctx, cfg, "alice", "master-password", id, &out))
	assert.Len(t, out.String(), 7, "6 digits + newline")
}

func TestRunOTPGet_NotFound(t *testing.T) {
	srv := newLiveServer(t)
	defer srv.Close()
	cfg := testConfig(srv, filepath.Join(t.TempDir(), "storage.vp"))
	ctx := context.Background()
	require.NoError(t, runRegister(ctx, cfg, "alice", "master-password", &bytes.Buffer{}))

	err := runOTPGet(ctx, cfg, "alice", "master-password", "ghost", &bytes.Buffer{})
	assert.Error(t, err)
}
