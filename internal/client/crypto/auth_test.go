package crypto_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/alexvictorne/voldepass/internal/client/crypto"
)

func TestAuthMessage_Deterministic(t *testing.T) {
	salt, _ := crypto.GenerateSalt()
	authKey, _ := crypto.DeriveKeys("password", salt, fastParams)

	nonce := []byte("server-nonce-12345")
	msg1 := crypto.AuthMessage(authKey, nonce)
	msg2 := crypto.AuthMessage(authKey, nonce)
	assert.Equal(t, msg1, msg2)
}

func TestAuthMessage_Length(t *testing.T) {
	salt, _ := crypto.GenerateSalt()
	authKey, _ := crypto.DeriveKeys("password", salt, fastParams)
	msg := crypto.AuthMessage(authKey, []byte("nonce"))
	assert.Len(t, msg, 32, "HMAC-SHA256 must be 32 bytes")
}

func TestAuthMessage_DifferentNonces(t *testing.T) {
	salt, _ := crypto.GenerateSalt()
	authKey, _ := crypto.DeriveKeys("password", salt, fastParams)

	msg1 := crypto.AuthMessage(authKey, []byte("nonce-A"))
	msg2 := crypto.AuthMessage(authKey, []byte("nonce-B"))
	assert.NotEqual(t, msg1, msg2, "different nonces must produce different auth messages")
}
