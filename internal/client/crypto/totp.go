package crypto

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // SHA1 is RFC 6238's default/most widely supported TOTP algorithm, not used for a security-critical hash here
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"strings"
	"time"
)

// totpDefaultDigits — количество цифр в TOTP-коде по умолчанию.
const totpDefaultDigits = 6

// totpDefaultPeriod — период смены TOTP-кода в секундах по умолчанию.
const totpDefaultPeriod = 30

// GenerateTOTP вычисляет TOTP-код согласно RFC 6238 для заданного момента времени t.
// secret — base32-кодированный общий секрет; algorithm — "SHA1", "SHA256" или "SHA512";
// digits — число цифр (6 или 8); period — период в секундах.
// Нулевые значения digits и period заменяются значениями по умолчанию.
func GenerateTOTP(secret, algorithm string, digits, period int, t time.Time) (string, error) {
	if digits == 0 {
		digits = totpDefaultDigits
	}
	if period == 0 {
		period = totpDefaultPeriod
	}

	// Декодирование base32-секрета (без учёта регистра, без паддинга).
	secret = strings.ToUpper(strings.TrimSpace(secret))
	// Добавляем паддинг, если необходим.
	if rem := len(secret) % 8; rem != 0 {
		secret += strings.Repeat("=", 8-rem)
	}
	key, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", fmt.Errorf("decode totp secret: %w", err)
	}

	// T = floor(unix_timestamp / period).
	counter := uint64(t.Unix()) / uint64(period) //nolint:gosec // период всегда > 0

	// HOTP(K, C) = Truncate(HMAC(K, C)).
	code, err := hotp(key, counter, algorithm, digits)
	if err != nil {
		return "", err
	}
	return code, nil
}

// hotp реализует HOTP (RFC 4226) — базовый алгоритм для TOTP.
func hotp(key []byte, counter uint64, algorithm string, digits int) (string, error) {
	var h func() hash.Hash
	switch strings.ToUpper(algorithm) {
	case "", "SHA1":
		h = sha1.New
	case "SHA256":
		h = sha256.New
	case "SHA512":
		h = sha512.New
	default:
		return "", fmt.Errorf("unsupported totp algorithm: %s", algorithm)
	}

	// Кодируем counter как big-endian uint64.
	msg := make([]byte, 8)
	binary.BigEndian.PutUint64(msg, counter)

	mac := hmac.New(h, key)
	mac.Write(msg)
	sum := mac.Sum(nil)

	// Dynamic truncation: берём последние 4 бита для смещения.
	offset := sum[len(sum)-1] & 0x0F
	truncated := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7FFFFFFF

	// Берём digits-значных цифр.
	mod := uint32(math.Pow10(digits)) //nolint:gosec
	code := truncated % mod
	return fmt.Sprintf("%0*d", digits, code), nil
}
