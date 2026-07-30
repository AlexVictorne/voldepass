package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
)

// AuthMessage вычисляет HMAC-SHA256(authKey, serverNonce) для challenge-response аутентификации.
// authKey никогда не передаётся по сети; сервер проверяет HMAC независимо
// (см. internal/server/auth.VerifyAuthMessage), используя сохранённый верификатор authKey.
func AuthMessage(authKey, serverNonce []byte) []byte {
	mac := hmac.New(sha256.New, authKey)
	mac.Write(serverNonce)
	return mac.Sum(nil)
}
