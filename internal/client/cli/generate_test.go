package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/alexvictorne/voldepass/internal/client/crypto"
)

func TestRunGenerate_DefaultLength(t *testing.T) {
	var out bytes.Buffer
	require.NoError(t, runGenerate(crypto.GenerateOptions{Length: 20}, &out))
	assert.Len(t, strings.TrimSpace(out.String()), 20)
}

func TestRunGenerate_NoSymbols(t *testing.T) {
	var out bytes.Buffer
	require.NoError(t, runGenerate(crypto.GenerateOptions{Length: 16, NoSymbols: true}, &out))
	pw := strings.TrimSpace(out.String())
	for _, r := range pw {
		assert.False(t, strings.ContainsRune("!@#$%^&*()-_=+[]{}|;:,.<>?", r))
	}
}
