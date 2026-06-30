package crypto

import (
	"encoding/json"
	"fmt"

	"github.com/alexvictorne/voldepass/internal/domain"
)

// ExportBundle — зашифрованный бандл для air-gapped резервной копии.
// Версионируется полем Version для будущих миграций формата.
type ExportBundle struct {
	// Version — версия формата бандла.
	Version int `json:"version"`
	// KDFSalt — соль, использованная при деривации ключей.
	KDFSalt []byte `json:"kdf_salt"`
	// KDFParams — параметры Argon2id, использованные при деривации.
	KDFParams domain.KdfParams `json:"kdf_params"`
	// WrappedDataKey — dataKey, обёрнутый encKey (nonce||ciphertext).
	WrappedDataKey []byte `json:"wrapped_data_key"`
	// Records — зашифрованные записи хранилища.
	Records []domain.RecordDTO `json:"records"`
	// Nonce — nonce для шифрования plaintext-содержимого бандла.
	Nonce []byte `json:"nonce"`
	// Ciphertext — зашифрованный JSON с KDFSalt/KDFParams/WrappedDataKey/Records.
	Ciphertext []byte `json:"ciphertext"`
}

// exportBundleInner — незашифрованное содержимое бандла (шифруется dataKey).
type exportBundleInner struct {
	KDFSalt        []byte             `json:"kdf_salt"`
	KDFParams      domain.KdfParams   `json:"kdf_params"`
	WrappedDataKey []byte             `json:"wrapped_data_key"`
	Records        []domain.RecordDTO `json:"records"`
}

// ExportData создаёт зашифрованный бандл из dataKey, записей и профиля.
// Бандл шифруется тем же dataKey, поэтому для импорта нужен мастер-пароль.
func ExportData(dataKey []byte, records []domain.RecordDTO, kdfSalt []byte, kdfParams domain.KdfParams, wrappedDataKey []byte) ([]byte, error) {
	inner := exportBundleInner{
		KDFSalt:        kdfSalt,
		KDFParams:      kdfParams,
		WrappedDataKey: wrappedDataKey,
		Records:        records,
	}

	plaintext, err := json.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("marshal export bundle: %w", err)
	}

	ciphertext, nonce, err := Encrypt(dataKey, plaintext)
	if err != nil {
		return nil, fmt.Errorf("encrypt export bundle: %w", err)
	}

	bundle := ExportBundle{
		Version:    1,
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}

	raw, err := json.Marshal(bundle)
	if err != nil {
		return nil, fmt.Errorf("marshal final bundle: %w", err)
	}
	return raw, nil
}

// ImportResult — содержимое успешно импортированного бандла.
type ImportResult struct {
	// KDFSalt — соль для деривации ключей.
	KDFSalt []byte
	// KDFParams — параметры Argon2id.
	KDFParams domain.KdfParams
	// WrappedDataKey — оригинальный wrappedDataKey из бандла.
	WrappedDataKey []byte
	// Records — расшифрованные записи.
	Records []domain.RecordDTO
}

// ImportData расшифровывает и разбирает бандл, созданный через ExportData.
// dataKey должен соответствовать ключу, которым был зашифрован бандл.
func ImportData(raw, dataKey []byte) (*ImportResult, error) {
	var bundle ExportBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		return nil, fmt.Errorf("unmarshal export bundle: %w", err)
	}

	if bundle.Version != 1 {
		return nil, fmt.Errorf("unsupported export bundle version: %d", bundle.Version)
	}

	plaintext, err := Decrypt(dataKey, bundle.Ciphertext, bundle.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decrypt export bundle: %w", err)
	}

	var inner exportBundleInner
	if err := json.Unmarshal(plaintext, &inner); err != nil {
		return nil, fmt.Errorf("unmarshal bundle inner: %w", err)
	}

	return &ImportResult{
		KDFSalt:        inner.KDFSalt,
		KDFParams:      inner.KDFParams,
		WrappedDataKey: inner.WrappedDataKey,
		Records:        inner.Records,
	}, nil
}
