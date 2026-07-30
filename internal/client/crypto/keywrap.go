package crypto

import (
	"crypto/rand"
	"fmt"
	"io"
)

// dataKeyLen — длина случайного dataKey в байтах (AES-256).
const dataKeyLen = 32

// GenerateDataKey генерирует случайный 256-битный ключ шифрования записей.
// dataKey никогда не хранится в открытом виде; на сервер уходит только wrappedDataKey.
func GenerateDataKey() ([]byte, error) {
	key := make([]byte, dataKeyLen)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generate data key: %w", err)
	}
	return key, nil
}

// WrapKey оборачивает dataKey с помощью encKey через AES-256-GCM.
// Результат (wrapped) безопасно хранить на сервере — без encKey dataKey не восстановить.
func WrapKey(encKey, dataKey []byte) ([]byte, error) {
	wrapped, nonce, err := Encrypt(encKey, dataKey)
	if err != nil {
		return nil, fmt.Errorf("wrap key: %w", err)
	}
	// Формат: nonce || ciphertext; nonce имеет фиксированную длину nonceLen.
	result := make([]byte, len(nonce)+len(wrapped))
	copy(result, nonce)
	copy(result[len(nonce):], wrapped)
	return result, nil
}

// UnwrapKey разворачивает dataKey, зашифрованный через WrapKey.
func UnwrapKey(encKey, wrapped []byte) ([]byte, error) {
	if len(wrapped) <= nonceLen {
		return nil, fmt.Errorf("unwrap key: wrapped data too short")
	}
	nonce := wrapped[:nonceLen]
	ciphertext := wrapped[nonceLen:]
	dataKey, err := Decrypt(encKey, ciphertext, nonce)
	if err != nil {
		return nil, fmt.Errorf("unwrap key: %w", err)
	}
	return dataKey, nil
}
