package cli

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRootCmd_Version(t *testing.T) {
	root := NewRootCmd("1.2.3", "2024-01-01")
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"version"})

	require.NoError(t, root.Execute())
	assert.Contains(t, out.String(), "version=1.2.3")
	assert.Contains(t, out.String(), "buildDate=2024-01-01")
}

func TestRequireLogin_Missing(t *testing.T) {
	flags := &rootFlags{}
	_, err := requireLogin(flags)
	assert.Error(t, err)
}

func TestRequireLogin_Present(t *testing.T) {
	flags := &rootFlags{login: "alice"}
	login, err := requireLogin(flags)
	require.NoError(t, err)
	assert.Equal(t, "alice", login)
}
