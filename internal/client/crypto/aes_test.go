package crypto_test

import (
	"bytes"
	"testing"
	"testing/quick"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/alexvictorne/voldepass/internal/client/crypto"
)

func newTestKey(t *testing.T) []byte {
	t.Helper()
	salt, err := crypto.GenerateSalt()
	require.NoError(t, err)
	_, encKey := crypto.DeriveKeys("test-password", salt, fastParams)
	return encKey
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	key := newTestKey(t)
	plaintext := []byte("hello, voldepass!")

	ct, nonce, err := crypto.Encrypt(key, plaintext)
	require.NoError(t, err)

	got, err := crypto.Decrypt(key, ct, nonce)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)
}

func TestEncrypt_UniqueNonce(t *testing.T) {
	key := newTestKey(t)
	_, nonce1, _ := crypto.Encrypt(key, []byte("data"))
	_, nonce2, _ := crypto.Encrypt(key, []byte("data"))
	assert.False(t, bytes.Equal(nonce1, nonce2), "each encryption must use a unique nonce")
}

func TestEncrypt_UniqueCiphertext(t *testing.T) {
	key := newTestKey(t)
	ct1, _, _ := crypto.Encrypt(key, []byte("same plaintext"))
	ct2, _, _ := crypto.Encrypt(key, []byte("same plaintext"))
	assert.False(t, bytes.Equal(ct1, ct2), "same plaintext encrypted twice must produce different ciphertexts")
}

func TestDecrypt_WrongKey(t *testing.T) {
	key := newTestKey(t)
	wrongKey := newTestKey(t)

	ct, nonce, err := crypto.Encrypt(key, []byte("secret"))
	require.NoError(t, err)

	_, err = crypto.Decrypt(wrongKey, ct, nonce)
	assert.Error(t, err, "decryption with wrong key must fail")
}

func TestDecrypt_TamperedCiphertext(t *testing.T) {
	key := newTestKey(t)
	ct, nonce, err := crypto.Encrypt(key, []byte("important data"))
	require.NoError(t, err)

	ct[0] ^= 0xFF // порча первого байта
	_, err = crypto.Decrypt(key, ct, nonce)
	assert.Error(t, err, "tampered ciphertext must fail authentication")
}

func TestDecrypt_WrongNonceLength_ReturnsErrorNotPanic(t *testing.T) {
	key := newTestKey(t)
	ct, _, err := crypto.Encrypt(key, []byte("data"))
	require.NoError(t, err)

	for _, n := range [][]byte{nil, {}, {1}, {1, 2, 3}, make([]byte, 11), make([]byte, 13), make([]byte, 32)} {
		_, err := crypto.Decrypt(key, ct, n)
		assert.ErrorIs(t, err, crypto.ErrInvalidNonceLength, "nonce of length %d must be rejected with an error, not panic", len(n))
	}
}

func TestDecrypt_EmptyPlaintext(t *testing.T) {
	key := newTestKey(t)
	ct, nonce, err := crypto.Encrypt(key, []byte{})
	require.NoError(t, err)

	got, err := crypto.Decrypt(key, ct, nonce)
	require.NoError(t, err)
	// gcm.Open возвращает nil для пустого plaintext — приводим к пустому слайсу.
	assert.Empty(t, got)
}

// Property: encrypt→decrypt всегда возвращает исходный plaintext.
func TestEncryptDecrypt_Property_RoundTrip(t *testing.T) {
	key := newTestKey(t)

	f := func(data []byte) bool {
		if len(data) == 0 {
			data = []byte{0}
		}
		ct, nonce, err := crypto.Encrypt(key, data)
		if err != nil {
			return false
		}
		got, err := crypto.Decrypt(key, ct, nonce)
		if err != nil {
			return false
		}
		return bytes.Equal(data, got)
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 50}); err != nil {
		t.Error(err)
	}
}
