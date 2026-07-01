package auth_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/alexvictorne/voldepass/internal/server/auth"
)

func newJWT(t *testing.T) *auth.JWTManager {
	t.Helper()
	return auth.NewJWTManager([]byte("test-secret-32-bytes-long-enough"), 15*time.Minute)
}

func TestJWT_IssueAndParse(t *testing.T) {
	m := newJWT(t)
	token, err := m.Issue("user-123")
	require.NoError(t, err)
	require.NotEmpty(t, token)

	uid, err := m.Parse(token)
	require.NoError(t, err)
	assert.Equal(t, "user-123", uid)
}

func TestJWT_Expired(t *testing.T) {
	m := auth.NewJWTManager([]byte("secret-32-bytes-exactly-padded!!"), -time.Second)
	token, err := m.Issue("user-123")
	require.NoError(t, err)

	_, err = m.Parse(token)
	assert.Error(t, err, "expired token must be rejected")
}

func TestJWT_WrongSecret(t *testing.T) {
	m1 := auth.NewJWTManager([]byte("secret-A-32-bytes-padded-exactly!"), time.Minute)
	m2 := auth.NewJWTManager([]byte("secret-B-32-bytes-padded-exactly!"), time.Minute)

	token, _ := m1.Issue("user-123")
	_, err := m2.Parse(token)
	assert.Error(t, err, "token signed with different secret must be rejected")
}

func TestJWT_Tampered(t *testing.T) {
	m := newJWT(t)
	token, _ := m.Issue("user-123")

	// Меняем один символ в сигнатуре (последняя часть после второй точки).
	parts := []byte(token)
	parts[len(parts)-5] ^= 0x01
	tampered := string(parts)
	_, err := m.Parse(tampered)
	assert.Error(t, err, "tampered token must be rejected")
}

func TestJWT_InvalidFormat(t *testing.T) {
	m := newJWT(t)
	_, err := m.Parse("not.a.jwt")
	assert.Error(t, err)
}
