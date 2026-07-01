// Пакет auth реализует аутентификацию сервера: JWT, challenge-response, refresh-токены.
package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// claims — приватный тип claims для access-токена.
type claims struct {
	jwt.RegisteredClaims
	UserID string `json:"uid"`
}

// JWTManager выдаёт и проверяет короткоживущие access-токены.
type JWTManager struct {
	secret []byte
	ttl    time.Duration
}

// NewJWTManager создаёт менеджер с заданным секретом и TTL токена.
func NewJWTManager(secret []byte, ttl time.Duration) *JWTManager {
	return &JWTManager{secret: secret, ttl: ttl}
}

// Issue выдаёт подписанный access-токен для пользователя userID.
func (m *JWTManager) Issue(userID string) (string, error) {
	now := time.Now()
	c := claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.ttl)),
		},
		UserID: userID,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	signed, err := token.SignedString(m.secret)
	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}
	return signed, nil
}

// Parse проверяет подпись и срок действия токена, возвращает userID.
func (m *JWTManager) Parse(tokenStr string) (userID string, err error) {
	token, err := jwt.ParseWithClaims(tokenStr, &claims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return m.secret, nil
	})
	if err != nil {
		return "", fmt.Errorf("parse jwt: %w", err)
	}

	c, ok := token.Claims.(*claims)
	if !ok || !token.Valid {
		return "", fmt.Errorf("invalid jwt claims")
	}
	return c.UserID, nil
}
