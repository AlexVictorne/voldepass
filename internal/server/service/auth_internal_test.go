package service

import (
	"crypto/hmac"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hmacAuthMsg считает HMAC-SHA256(authKey, nonce) напрямую — так же, как это
// делает internal/client/crypto.AuthMessage на стороне клиента, но без
// зависимости этого пакета сервера от пакета клиента.
func hmacAuthMsg(authKey, nonce []byte) []byte {
	mac := hmac.New(sha256.New, authKey)
	mac.Write(nonce)
	return mac.Sum(nil)
}

func TestVerifyAuthMessage_Valid(t *testing.T) {
	authKey := []byte("authkey-1234567890123456789012")
	nonce := []byte("server-nonce")

	msg := hmacAuthMsg(authKey, nonce)
	assert.True(t, verifyAuthMessage(authKey, nonce, msg))
}

func TestVerifyAuthMessage_WrongKey(t *testing.T) {
	authKeyA := []byte("authkey-a-123456789012345678901")
	authKeyB := []byte("authkey-b-123456789012345678901")
	nonce := []byte("server-nonce")

	msg := hmacAuthMsg(authKeyA, nonce)
	assert.False(t, verifyAuthMessage(authKeyB, nonce, msg), "wrong key must fail verification")
}

func TestVerifyAuthMessage_WrongNonce(t *testing.T) {
	authKey := []byte("authkey-1234567890123456789012")

	msg := hmacAuthMsg(authKey, []byte("original-nonce"))
	assert.False(t, verifyAuthMessage(authKey, []byte("replayed-nonce"), msg), "replayed nonce must fail")
}

func TestVerifyAuthMessage_TamperedMsg(t *testing.T) {
	authKey := []byte("authkey-1234567890123456789012")
	nonce := []byte("nonce")

	msg := hmacAuthMsg(authKey, nonce)
	require.NotEmpty(t, msg)
	msg[0] ^= 0xFF
	assert.False(t, verifyAuthMessage(authKey, nonce, msg), "tampered message must fail")
}
