package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// ErrInvalidNonceLength возвращается Decrypt, если переданный nonce не равен nonceLen —
// gcm.Open в стандартной библиотеке паникует на nonce неверной длины вместо
// возврата ошибки, поэтому длину нужно проверять заранее.
var ErrInvalidNonceLength = errors.New("invalid nonce length")

// nonceLen — стандартная длина nonce для AES-256-GCM.
const nonceLen = 12

// Encrypt шифрует plaintext ключом key через AES-256-GCM.
// Возвращает шифротекст и случайный nonce; nonce необходимо сохранить
// вместе с шифротекстом (он не является секретным, но должен быть уникальным).
func Encrypt(key, plaintext []byte) (ciphertext, nonce []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("create gcm: %w", err)
	}

	nonce = make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("generate nonce: %w", err)
	}

	// Seal добавляет тег аутентификации к шифротексту.
	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

// Decrypt расшифровывает ciphertext ключом key и проверяет тег целостности.
// Ошибка означает либо неверный ключ, либо повреждённые данные.
func Decrypt(key, ciphertext, nonce []byte) ([]byte, error) {
	if len(nonce) != nonceLen {
		return nil, fmt.Errorf("%w: got %d bytes, want %d", ErrInvalidNonceLength, len(nonce), nonceLen)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, nil
}
