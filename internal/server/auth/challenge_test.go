package auth_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/alexvictorne/voldepass/internal/server/auth"
)

func TestChallengeStore_IssueAndConsume(t *testing.T) {
	s := auth.NewChallengeStore(time.Minute)

	nonce, err := s.Issue("alice")
	require.NoError(t, err)
	assert.Len(t, nonce, 64, "hex-encoded 32 bytes = 64 chars")

	got, err := s.Consume("alice")
	require.NoError(t, err)
	assert.Equal(t, nonce, got)
}

func TestChallengeStore_ConsumeOnlyOnce(t *testing.T) {
	s := auth.NewChallengeStore(time.Minute)
	s.Issue("alice")
	s.Consume("alice")

	// Повторное потребление того же challenge → ошибка (replay защита).
	_, err := s.Consume("alice")
	assert.Error(t, err, "consumed challenge must not be reusable")
}

func TestChallengeStore_Expired(t *testing.T) {
	s := auth.NewChallengeStore(time.Millisecond)
	s.Issue("alice")
	time.Sleep(5 * time.Millisecond)

	_, err := s.Consume("alice")
	assert.Error(t, err, "expired challenge must be rejected")
}

func TestChallengeStore_NoChallenge(t *testing.T) {
	s := auth.NewChallengeStore(time.Minute)
	_, err := s.Consume("ghost")
	assert.Error(t, err)
}

func TestChallengeStore_IssueOverwrites(t *testing.T) {
	s := auth.NewChallengeStore(time.Minute)
	nonce1, _ := s.Issue("alice")
	nonce2, _ := s.Issue("alice")
	assert.NotEqual(t, nonce1, nonce2)

	// Consume должен вернуть последний nonce.
	got, err := s.Consume("alice")
	require.NoError(t, err)
	assert.Equal(t, nonce2, got)
}

func TestChallengeStore_UniqueNonces(t *testing.T) {
	s := auth.NewChallengeStore(time.Minute)
	n1, _ := s.Issue("alice")
	n2, _ := s.Issue("bob")
	assert.NotEqual(t, n1, n2)
}
