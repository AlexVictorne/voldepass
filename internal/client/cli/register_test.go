package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunRegister_Success(t *testing.T) {
	srv := newLiveServer(t)
	defer srv.Close()
	cfg := testConfig(srv, filepath.Join(t.TempDir(), "storage.vp"))
	var out bytes.Buffer

	err := runRegister(context.Background(), cfg, "alice", "Correct#Horse7Battery", &out)
	require.NoError(t, err)
	assert.Contains(t, out.String(), `registered "alice"`)
}

func TestRunRegister_WeakPasswordWarns(t *testing.T) {
	srv := newLiveServer(t)
	defer srv.Close()
	cfg := testConfig(srv, filepath.Join(t.TempDir(), "storage.vp"))
	var out bytes.Buffer

	err := runRegister(context.Background(), cfg, "bob", "password", &out)
	require.NoError(t, err, "weak password must warn, not block")
	assert.Contains(t, out.String(), "warning:")
}

func TestRunRegister_DuplicateLogin(t *testing.T) {
	srv := newLiveServer(t)
	defer srv.Close()
	cfg := testConfig(srv, filepath.Join(t.TempDir(), "storage.vp"))
	var out bytes.Buffer

	require.NoError(t, runRegister(context.Background(), cfg, "alice", "Correct#Horse7Battery", &out))
	err := runRegister(context.Background(), cfg, "alice", "Correct#Horse7Battery", &out)
	assert.Error(t, err)
}
