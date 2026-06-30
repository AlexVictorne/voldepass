package crypto

import (
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"

	"github.com/alexvictorne/voldepass/internal/domain"
)

// saltLen — длина случайной соли KDF в байтах.
const saltLen = 32

// GenerateSalt генерирует криптографически случайную соль для KDF.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	return salt, nil
}

// DeriveKeys выводит authKey и encKey из мастер-пароля и соли через Argon2id.
//
// Разделение доменов достигается двумя независимыми вызовами Argon2id с
// разными контекстными строками, добавленными к паролю:
//   - authKey: password + "|auth"
//   - encKey:  password + "|enc"
//
// Это гарантирует, что даже при компрометации одного ключа второй остаётся
// независимым.
func DeriveKeys(masterPassword string, salt []byte, params domain.KdfParams) (authKey, encKey []byte) {
	authKey = argon2.IDKey(
		[]byte(masterPassword+"|auth"),
		salt,
		params.Time,
		params.Memory,
		params.Threads,
		params.KeyLen,
	)
	encKey = argon2.IDKey(
		[]byte(masterPassword+"|enc"),
		salt,
		params.Time,
		params.Memory,
		params.Threads,
		params.KeyLen,
	)
	return authKey, encKey
}
