package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunLogin_Success(t *testing.T) {
	srv := newLiveServer(t)
	defer srv.Close()
	regCfg := testConfig(srv, filepath.Join(t.TempDir(), "storage.vp"))
	require.NoError(t, runRegister(context.Background(), regCfg, "alice", "master-password", &bytes.Buffer{}))

	loginCfg := testConfig(srv, filepath.Join(t.TempDir(), "storage2.vp"))
	var out bytes.Buffer
	err := runLogin(context.Background(), loginCfg, "alice", "master-password", &out)
	require.NoError(t, err)
	assert.Contains(t, out.String(), `logged in as "alice"`)
}

func TestRunLogin_WrongPassword(t *testing.T) {
	srv := newLiveServer(t)
	defer srv.Close()
	regCfg := testConfig(srv, filepath.Join(t.TempDir(), "storage.vp"))
	require.NoError(t, runRegister(context.Background(), regCfg, "alice", "correct-password", &bytes.Buffer{}))

	var out bytes.Buffer
	err := runLogin(context.Background(), regCfg, "alice", "wrong-password", &out)
	assert.Error(t, err)
}

func TestRunLogout_ClearsTokens(t *testing.T) {
	srv := newLiveServer(t)
	defer srv.Close()
	cfg := testConfig(srv, filepath.Join(t.TempDir(), "storage.vp"))
	require.NoError(t, runRegister(context.Background(), cfg, "alice", "master-password", &bytes.Buffer{}))

	var out bytes.Buffer
	err := runLogout(context.Background(), cfg, "alice", "master-password", &out)
	require.NoError(t, err)
	assert.Contains(t, out.String(), `logged out "alice"`)
}
