package crypto_test

import (
	"bytes"
	"testing"
	"testing/quick"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/alexvictorne/voldepass/internal/client/crypto"
	"github.com/alexvictorne/voldepass/internal/domain"
)

var fastParams = domain.KdfParams{Time: 1, Memory: 16 * 1024, Threads: 1, KeyLen: 32}

func TestGenerateSalt_Length(t *testing.T) {
	salt, err := crypto.GenerateSalt()
	require.NoError(t, err)
	assert.Len(t, salt, 32)
}

func TestGenerateSalt_Unique(t *testing.T) {
	a, err := crypto.GenerateSalt()
	require.NoError(t, err)
	b, err := crypto.GenerateSalt()
	require.NoError(t, err)
	assert.False(t, bytes.Equal(a, b), "two salts must differ")
}

func TestDeriveKeys_Deterministic(t *testing.T) {
	salt, _ := crypto.GenerateSalt()
	authKey1, encKey1 := crypto.DeriveKeys("master-password", salt, fastParams)
	authKey2, encKey2 := crypto.DeriveKeys("master-password", salt, fastParams)

	assert.Equal(t, authKey1, authKey2, "authKey must be deterministic")
	assert.Equal(t, encKey1, encKey2, "encKey must be deterministic")
}

func TestDeriveKeys_DomainSeparation(t *testing.T) {
	salt, _ := crypto.GenerateSalt()
	authKey, encKey := crypto.DeriveKeys("master-password", salt, fastParams)
	assert.False(t, bytes.Equal(authKey, encKey), "authKey and encKey must differ")
}

func TestDeriveKeys_DifferentPasswords(t *testing.T) {
	salt, _ := crypto.GenerateSalt()
	authKey1, _ := crypto.DeriveKeys("password-A", salt, fastParams)
	authKey2, _ := crypto.DeriveKeys("password-B", salt, fastParams)
	assert.False(t, bytes.Equal(authKey1, authKey2), "different passwords must yield different keys")
}

func TestDeriveKeys_DifferentSalts(t *testing.T) {
	saltA, _ := crypto.GenerateSalt()
	saltB, _ := crypto.GenerateSalt()
	authKey1, _ := crypto.DeriveKeys("same-password", saltA, fastParams)
	authKey2, _ := crypto.DeriveKeys("same-password", saltB, fastParams)
	assert.False(t, bytes.Equal(authKey1, authKey2), "different salts must yield different keys")
}

func TestDeriveKeys_KeyLength(t *testing.T) {
	salt, _ := crypto.GenerateSalt()
	authKey, encKey := crypto.DeriveKeys("pw", salt, fastParams)
	assert.Len(t, authKey, int(fastParams.KeyLen))
	assert.Len(t, encKey, int(fastParams.KeyLen))
}

// Property: для любого пароля и соли деривация детерминирована.
func TestDeriveKeys_Property_Deterministic(t *testing.T) {
	f := func(password string, saltSeed [32]byte) bool {
		if len(password) == 0 {
			return true
		}
		salt := saltSeed[:]
		a, _ := crypto.DeriveKeys(password, salt, fastParams)
		b, _ := crypto.DeriveKeys(password, salt, fastParams)
		return bytes.Equal(a, b)
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 10}); err != nil {
		t.Error(err)
	}
}
