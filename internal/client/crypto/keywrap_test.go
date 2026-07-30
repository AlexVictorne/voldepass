package crypto_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/alexvictorne/voldepass/internal/client/crypto"
)

func TestGenerateDataKey_Length(t *testing.T) {
	key, err := crypto.GenerateDataKey()
	require.NoError(t, err)
	assert.Len(t, key, 32)
}

func TestGenerateDataKey_Unique(t *testing.T) {
	a, _ := crypto.GenerateDataKey()
	b, _ := crypto.GenerateDataKey()
	assert.False(t, bytes.Equal(a, b), "two data keys must differ")
}

func TestWrapUnwrapKey_RoundTrip(t *testing.T) {
	encKey := newTestKey(t)
	dataKey, err := crypto.GenerateDataKey()
	require.NoError(t, err)

	wrapped, err := crypto.WrapKey(encKey, dataKey)
	require.NoError(t, err)

	unwrapped, err := crypto.UnwrapKey(encKey, wrapped)
	require.NoError(t, err)
	assert.Equal(t, dataKey, unwrapped)
}

func TestUnwrapKey_WrongEncKey(t *testing.T) {
	encKey := newTestKey(t)
	wrongEncKey := newTestKey(t)
	dataKey, _ := crypto.GenerateDataKey()

	wrapped, err := crypto.WrapKey(encKey, dataKey)
	require.NoError(t, err)

	_, err = crypto.UnwrapKey(wrongEncKey, wrapped)
	assert.Error(t, err, "unwrap with wrong encKey must fail")
}

func TestUnwrapKey_TamperedWrapped(t *testing.T) {
	encKey := newTestKey(t)
	dataKey, _ := crypto.GenerateDataKey()
	wrapped, _ := crypto.WrapKey(encKey, dataKey)

	wrapped[len(wrapped)-1] ^= 0xFF
	_, err := crypto.UnwrapKey(encKey, wrapped)
	assert.Error(t, err, "tampered wrapped key must fail")
}

func TestUnwrapKey_TooShort(t *testing.T) {
	encKey := newTestKey(t)
	_, err := crypto.UnwrapKey(encKey, []byte("short"))
	assert.Error(t, err)
}

func TestWrapKey_UniqueEachTime(t *testing.T) {
	encKey := newTestKey(t)
	dataKey, _ := crypto.GenerateDataKey()

	w1, _ := crypto.WrapKey(encKey, dataKey)
	w2, _ := crypto.WrapKey(encKey, dataKey)
	// Разные nonce → разные wrapped, но оба разворачиваются в одинаковый dataKey.
	assert.False(t, bytes.Equal(w1, w2), "wrap must use random nonce each time")

	u1, _ := crypto.UnwrapKey(encKey, w1)
	u2, _ := crypto.UnwrapKey(encKey, w2)
	assert.Equal(t, u1, u2)
}
