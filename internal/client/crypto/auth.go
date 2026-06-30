package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
)

// AuthMessage вычисляет HMAC-SHA256(authKey, serverNonce) для challenge-response аутентификации.
// authKey никогда не передаётся по сети; сервер проверяет HMAC, используя
// сохранённый верификатор authKey.
func AuthMessage(authKey, serverNonce []byte) []byte {
	mac := hmac.New(sha256.New, authKey)
	mac.Write(serverNonce)
	return mac.Sum(nil)
}

// VerifyAuthMessage проверяет authMsg в constant-time, чтобы исключить timing-атаки.
// Используется на сервере: authKeyVerifier — сохранённый authKey пользователя.
func VerifyAuthMessage(authKeyVerifier, serverNonce, authMsg []byte) bool {
	expected := AuthMessage(authKeyVerifier, serverNonce)
	return hmac.Equal(expected, authMsg)
}
