package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/alexvictorne/voldepass/internal/client/crypto"
)

// fileEnvelope — формат файла на диске: nonce и зашифрованный JSON-снапшот State.
// Хранится отдельно от State, чтобы plaintext-структура никогда не сериализовалась
// напрямую в файл.
type fileEnvelope struct {
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

// FileStore — Store с персистом в зашифрованный файл на диске.
// Использует тот же Store для in-memory рабочего набора; Load/Save управляют файлом явно.
type FileStore struct {
	*Store
	path string
}

// NewFileStore создаёт FileStore с пустым in-memory состоянием, привязанный к path.
// Данные с диска нужно загрузить явным вызовом Load.
func NewFileStore(path string) *FileStore {
	return &FileStore{Store: NewStore(), path: path}
}

// Load читает и расшифровывает файл по FileStore.path ключом dataKey.
// Если файл не существует — оставляет пустое состояние (первый запуск), не ошибка.
func (fs *FileStore) Load(dataKey []byte) error {
	raw, err := os.ReadFile(fs.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read storage file: %w", err)
	}

	var env fileEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("unmarshal storage envelope: %w", err)
	}

	plaintext, err := crypto.Decrypt(dataKey, env.Ciphertext, env.Nonce)
	if err != nil {
		return fmt.Errorf("decrypt storage file: %w", err)
	}

	var state State
	if err := json.Unmarshal(plaintext, &state); err != nil {
		return fmt.Errorf("unmarshal storage state: %w", err)
	}

	state = migrate(state)
	fs.Store = newStoreFromState(state)
	return nil
}

// Save шифрует текущее состояние ключом dataKey и атомарно записывает его в файл:
// пишет во временный файл, вызывает fsync, затем переименовывает поверх целевого пути.
// Это защищает от повреждения файла при краше процесса во время записи.
func (fs *FileStore) Save(dataKey []byte) error {
	state := fs.Snapshot()
	state.Version = currentFormatVersion

	plaintext, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal storage state: %w", err)
	}

	ciphertext, nonce, err := crypto.Encrypt(dataKey, plaintext)
	if err != nil {
		return fmt.Errorf("encrypt storage state: %w", err)
	}

	raw, err := json.Marshal(fileEnvelope{Nonce: nonce, Ciphertext: ciphertext})
	if err != nil {
		return fmt.Errorf("marshal storage envelope: %w", err)
	}

	return atomicWriteFile(fs.path, raw)
}

// atomicWriteFile пишет data во временный файл в той же директории, что и path,
// вызывает fsync и атомарно переименовывает его поверх path.
func atomicWriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	// При любом раннем возврате подчищаем временный файл, если rename не произошёл.
	defer os.Remove(tmpPath) //nolint:errcheck

	if _, err := tmp.Write(data); err != nil {
		tmp.Close() //nolint:errcheck
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close() //nolint:errcheck
		return fmt.Errorf("fsync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}
	return nil
}

// migrate приводит State произвольной сохранённой версии к currentFormatVersion.
// Версия 0 (нулевое значение) трактуется как "до версионирования" и апгрейдится в 1.
func migrate(s State) State {
	if s.Version == 0 {
		s.Version = 1
	}
	if s.Records == nil {
		s.Records = make(map[string]StoredRecord)
	}
	return s
}
