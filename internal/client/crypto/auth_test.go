package crypto_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

func TestVerifyAuthMessage_Valid(t *testing.T) {
	salt, _ := crypto.GenerateSalt()
	authKey, _ := crypto.DeriveKeys("password", salt, fastParams)
	nonce := []byte("server-nonce")

	msg := crypto.AuthMessage(authKey, nonce)
	assert.True(t, crypto.VerifyAuthMessage(authKey, nonce, msg))
}

func TestVerifyAuthMessage_WrongKey(t *testing.T) {
	saltA, _ := crypto.GenerateSalt()
	saltB, _ := crypto.GenerateSalt()
	authKeyA, _ := crypto.DeriveKeys("password", saltA, fastParams)
	authKeyB, _ := crypto.DeriveKeys("password", saltB, fastParams)
	nonce := []byte("server-nonce")

	msg := crypto.AuthMessage(authKeyA, nonce)
	assert.False(t, crypto.VerifyAuthMessage(authKeyB, nonce, msg), "wrong key must fail verification")
}

func TestVerifyAuthMessage_WrongNonce(t *testing.T) {
	salt, _ := crypto.GenerateSalt()
	authKey, _ := crypto.DeriveKeys("password", salt, fastParams)

	msg := crypto.AuthMessage(authKey, []byte("original-nonce"))
	assert.False(t, crypto.VerifyAuthMessage(authKey, []byte("replayed-nonce"), msg), "replayed nonce must fail")
}

func TestVerifyAuthMessage_TamperedMsg(t *testing.T) {
	salt, _ := crypto.GenerateSalt()
	authKey, _ := crypto.DeriveKeys("password", salt, fastParams)
	nonce := []byte("nonce")

	msg := crypto.AuthMessage(authKey, nonce)
	require.NotEmpty(t, msg)
	msg[0] ^= 0xFF
	assert.False(t, crypto.VerifyAuthMessage(authKey, nonce, msg), "tampered message must fail")
}
