package crypto_test

import (
	"strings"
	"testing"
	"unicode"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/alexvictorne/voldepass/internal/client/crypto"
)

// ── GeneratePassword ─────────────────────────────────────────────────────────

func TestGeneratePassword_DefaultLength(t *testing.T) {
	pw, err := crypto.GeneratePassword(crypto.GenerateOptions{Length: 16})
	require.NoError(t, err)
	assert.Len(t, pw, 16)
}

func TestGeneratePassword_MinLength(t *testing.T) {
	// Длина < 8 должна быть заменена на 8.
	pw, err := crypto.GeneratePassword(crypto.GenerateOptions{Length: 4})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(pw), 8)
}

func TestGeneratePassword_ContainsRequiredClasses(t *testing.T) {
	pw, err := crypto.GeneratePassword(crypto.GenerateOptions{Length: 24})
	require.NoError(t, err)

	var lower, upper, digit, symbol bool
	for _, r := range pw {
		switch {
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			digit = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			symbol = true
		}
	}
	assert.True(t, lower, "must contain lowercase")
	assert.True(t, upper, "must contain uppercase")
	assert.True(t, digit, "must contain digit")
	assert.True(t, symbol, "must contain symbol")
}

func TestGeneratePassword_NoSymbols(t *testing.T) {
	pw, err := crypto.GeneratePassword(crypto.GenerateOptions{Length: 20, NoSymbols: true})
	require.NoError(t, err)
	for _, r := range pw {
		assert.False(t, unicode.IsPunct(r) || unicode.IsSymbol(r), "must not contain symbols")
	}
}

func TestGeneratePassword_NoDigits(t *testing.T) {
	pw, err := crypto.GeneratePassword(crypto.GenerateOptions{Length: 20, NoDigits: true})
	require.NoError(t, err)
	for _, r := range pw {
		assert.False(t, unicode.IsDigit(r), "must not contain digits")
	}
}

func TestGeneratePassword_Unique(t *testing.T) {
	a, _ := crypto.GeneratePassword(crypto.GenerateOptions{Length: 24})
	b, _ := crypto.GeneratePassword(crypto.GenerateOptions{Length: 24})
	assert.NotEqual(t, a, b, "two generated passwords must differ")
}

// ── EvaluatePasswordStrength ──────────────────────────────────────────────────

func TestEvaluatePasswordStrength_TooShort(t *testing.T) {
	r := crypto.EvaluatePasswordStrength("abc")
	assert.Contains(t, r.Feedback, "Password is too short (minimum 8 characters)")
	assert.Equal(t, crypto.StrengthVeryWeak, r.Score)
}

func TestEvaluatePasswordStrength_Common(t *testing.T) {
	r := crypto.EvaluatePasswordStrength("password")
	assert.Contains(t, r.Feedback, "This is a commonly used password")
	assert.Equal(t, crypto.StrengthVeryWeak, r.Score)
}

func TestEvaluatePasswordStrength_AllClasses(t *testing.T) {
	// Длинный пароль со всеми классами символов.
	pw := "Correct#Horse7Battery"
	r := crypto.EvaluatePasswordStrength(pw)
	assert.Empty(t, r.Feedback, "strong password should have no feedback")
	assert.GreaterOrEqual(t, int(r.Score), int(crypto.StrengthStrong))
}

func TestEvaluatePasswordStrength_MissingClasses(t *testing.T) {
	r := crypto.EvaluatePasswordStrength("alllowercase1234")
	feedbackStr := strings.Join(r.Feedback, " ")
	assert.Contains(t, feedbackStr, "uppercase")
	assert.Contains(t, feedbackStr, "special")
}

func TestEvaluatePasswordStrength_ScoreRange(t *testing.T) {
	cases := []string{"a", "password", "P@ssword1", "Tr0ub4dor&3!!XYZ"}
	for _, pw := range cases {
		r := crypto.EvaluatePasswordStrength(pw)
		assert.GreaterOrEqual(t, int(r.Score), 0)
		assert.LessOrEqual(t, int(r.Score), 4)
	}
}
