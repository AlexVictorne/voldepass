package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadPassword_NonTerminalInput(t *testing.T) {
	in := strings.NewReader("my-secret-password\n")
	var out bytes.Buffer

	pw, err := readPassword(in, &out, "Password: ")
	require.NoError(t, err)
	assert.Equal(t, "my-secret-password", pw)
	assert.Contains(t, out.String(), "Password: ")
}

func TestReadPassword_TrimsCRLF(t *testing.T) {
	in := strings.NewReader("secret\r\n")
	var out bytes.Buffer

	pw, err := readPassword(in, &out, "")
	require.NoError(t, err)
	assert.Equal(t, "secret", pw)
}

func TestReadPassword_NoTrailingNewline(t *testing.T) {
	in := strings.NewReader("secret-no-newline")
	var out bytes.Buffer

	pw, err := readPassword(in, &out, "")
	require.NoError(t, err)
	assert.Equal(t, "secret-no-newline", pw)
}
