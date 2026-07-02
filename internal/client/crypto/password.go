package crypto

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
	"unicode"
)

// Наборы символов для генератора паролей.
const (
	charsetLower   = "abcdefghijklmnopqrstuvwxyz"
	charsetUpper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	charsetDigits  = "0123456789"
	charsetSymbols = "!@#$%^&*()-_=+[]{}|;:,.<>?"
)

// GenerateOptions задаёт параметры генерации пароля.
type GenerateOptions struct {
	// Length — длина генерируемого пароля (минимум 8).
	Length int
	// NoSymbols — исключить специальные символы.
	NoSymbols bool
	// NoDigits — исключить цифры.
	NoDigits bool
	// NoUpper — исключить заглавные буквы.
	NoUpper bool
}

// GeneratePassword генерирует стойкий случайный пароль с помощью crypto/rand.
// Гарантирует наличие хотя бы одного символа из каждого включённого класса.
func GeneratePassword(opts GenerateOptions) (string, error) {
	if opts.Length < 8 {
		opts.Length = 8
	}

	// Формируем полный алфавит и список обязательных классов.
	var alphabet strings.Builder
	type charClass struct {
		chars string
	}
	required := []charClass{{charsetLower}}
	alphabet.WriteString(charsetLower)

	if !opts.NoUpper {
		alphabet.WriteString(charsetUpper)
		required = append(required, charClass{charsetUpper})
	}
	if !opts.NoDigits {
		alphabet.WriteString(charsetDigits)
		required = append(required, charClass{charsetDigits})
	}
	if !opts.NoSymbols {
		alphabet.WriteString(charsetSymbols)
		required = append(required, charClass{charsetSymbols})
	}

	pool := alphabet.String()
	poolLen := big.NewInt(int64(len(pool)))

	result := make([]byte, opts.Length)

	// Сначала заполняем обязательные позиции из соответствующих классов.
	positions, err := randomPermutation(opts.Length)
	if err != nil {
		return "", err
	}

	for i, cls := range required {
		if i >= opts.Length {
			break
		}
		ch, err := randomChar(cls.chars)
		if err != nil {
			return "", err
		}
		result[positions[i]] = ch
	}

	// Оставшиеся позиции — случайные символы из полного алфавита.
	for i := len(required); i < opts.Length; i++ {
		idx, err := rand.Int(rand.Reader, poolLen)
		if err != nil {
			return "", fmt.Errorf("generate password char: %w", err)
		}
		result[positions[i]] = pool[idx.Int64()]
	}

	return string(result), nil
}

// randomChar выбирает случайный символ из набора chars.
func randomChar(chars string) (byte, error) {
	idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
	if err != nil {
		return 0, fmt.Errorf("random char: %w", err)
	}
	return chars[idx.Int64()], nil
}

// randomPermutation возвращает случайную перестановку индексов [0, n).
func randomPermutation(n int) ([]int, error) {
	perm := make([]int, n)
	for i := range perm {
		perm[i] = i
	}
	// Fisher-Yates shuffle через crypto/rand.
	for i := n - 1; i > 0; i-- {
		jBig, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return nil, fmt.Errorf("shuffle: %w", err)
		}
		j := int(jBig.Int64())
		perm[i], perm[j] = perm[j], perm[i]
	}
	return perm, nil
}

// StrengthScore — оценка стойкости пароля (0–4, как в zxcvbn).
type StrengthScore int

const (
	StrengthVeryWeak   StrengthScore = 0
	StrengthWeak       StrengthScore = 1
	StrengthFair       StrengthScore = 2
	StrengthStrong     StrengthScore = 3
	StrengthVeryStrong StrengthScore = 4
)

// StrengthResult содержит оценку и предупреждения.
type StrengthResult struct {
	// Score — итоговая оценка (0–4).
	Score StrengthScore
	// Feedback — список конкретных рекомендаций на английском языке.
	Feedback []string
}

// EvaluatePasswordStrength оценивает стойкость пароля (не блокирует, только предупреждает).
// Используется при регистрации для UX-подсказок.
func EvaluatePasswordStrength(pw string) StrengthResult {
	var feedback []string
	score := 0

	// Длина.
	if len(pw) < 8 {
		feedback = append(feedback, "Password is too short (minimum 8 characters)")
	} else if len(pw) >= 12 {
		score++
	}
	if len(pw) >= 16 {
		score++
	}

	// Классы символов.
	var hasLower, hasUpper, hasDigit, hasSymbol bool
	for _, r := range pw {
		switch {
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			hasSymbol = true
		}
	}

	classCount := 0
	if hasLower {
		classCount++
	}
	if hasUpper {
		classCount++
	}
	if hasDigit {
		classCount++
	}
	if hasSymbol {
		classCount++
	}

	if classCount >= 3 {
		score++
	}
	if !hasUpper {
		feedback = append(feedback, "Add uppercase letters")
	}
	if !hasDigit {
		feedback = append(feedback, "Add numbers")
	}
	if !hasSymbol {
		feedback = append(feedback, "Add special characters")
	}

	// Проверка по топ-списку слабых паролей.
	if isCommonPassword(strings.ToLower(pw)) {
		feedback = append(feedback, "This is a commonly used password")
		score = 0
	}

	// Нормализуем счёт.
	if score < 0 {
		score = 0
	}
	if score > 4 {
		score = 4
	}

	return StrengthResult{
		Score:    StrengthScore(score),
		Feedback: feedback,
	}
}

// commonPasswords — топ-список распространённых слабых паролей.
var commonPasswords = map[string]struct{}{
	"password": {}, "password1": {}, "123456": {}, "12345678": {},
	"qwerty": {}, "abc123": {}, "monkey": {}, "1234567": {},
	"letmein": {}, "trustno1": {}, "dragon": {}, "master": {},
	"sunshine": {}, "iloveyou": {}, "princess": {}, "welcome": {},
	"shadow": {}, "superman": {}, "michael": {}, "football": {},
	"admin": {}, "login": {}, "passw0rd": {}, "starwars": {},
}

func isCommonPassword(pw string) bool {
	_, ok := commonPasswords[pw]
	return ok
}
