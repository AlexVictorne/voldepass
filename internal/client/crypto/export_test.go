package crypto_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/alexvictorne/voldepass/internal/client/crypto"
	"github.com/alexvictorne/voldepass/internal/domain"
)

func makeTestProfile(t *testing.T) (dataKey, encKey, kdfSalt []byte, params domain.KdfParams, wrapped []byte) {
	t.Helper()
	kdfSalt, err := crypto.GenerateSalt()
	require.NoError(t, err)

	params = fastParams
	_, encKey = crypto.DeriveKeys("test-master-password", kdfSalt, params)

	dataKey, err = crypto.GenerateDataKey()
	require.NoError(t, err)

	wrapped, err = crypto.WrapKey(encKey, dataKey)
	require.NoError(t, err)
	return
}

func TestExportImport_RoundTrip(t *testing.T) {
	dataKey, _, kdfSalt, params, wrapped := makeTestProfile(t)

	records := []domain.RecordDTO{
		{ID: "rec-1", Type: domain.DataTypeCredentials, Ciphertext: []byte("ct1"), Nonce: []byte("nonce000000001"), Version: 1},
		{ID: "rec-2", Type: domain.DataTypeText, Ciphertext: []byte("ct2"), Nonce: []byte("nonce000000002"), Version: 2},
	}

	raw, err := crypto.ExportData(dataKey, records, kdfSalt, params, wrapped)
	require.NoError(t, err)
	assert.NotEmpty(t, raw)

	result, err := crypto.ImportData(raw, dataKey)
	require.NoError(t, err)

	assert.Equal(t, kdfSalt, result.KDFSalt)
	assert.Equal(t, params, result.KDFParams)
	assert.Equal(t, wrapped, result.WrappedDataKey)
	require.Len(t, result.Records, 2)
	assert.Equal(t, records[0].ID, result.Records[0].ID)
	assert.Equal(t, records[1].ID, result.Records[1].ID)
}

func TestExportImport_EmptyRecords(t *testing.T) {
	dataKey, _, kdfSalt, params, wrapped := makeTestProfile(t)

	raw, err := crypto.ExportData(dataKey, []domain.RecordDTO{}, kdfSalt, params, wrapped)
	require.NoError(t, err)

	result, err := crypto.ImportData(raw, dataKey)
	require.NoError(t, err)
	assert.Empty(t, result.Records)
}

func TestImportData_WrongKey(t *testing.T) {
	dataKey, _, kdfSalt, params, wrapped := makeTestProfile(t)
	wrongKey, _ := crypto.GenerateDataKey()

	raw, err := crypto.ExportData(dataKey, nil, kdfSalt, params, wrapped)
	require.NoError(t, err)

	_, err = crypto.ImportData(raw, wrongKey)
	assert.Error(t, err, "import with wrong key must fail")
}

func TestImportData_TamperedBundle(t *testing.T) {
	dataKey, _, kdfSalt, params, wrapped := makeTestProfile(t)

	raw, err := crypto.ExportData(dataKey, nil, kdfSalt, params, wrapped)
	require.NoError(t, err)

	raw[len(raw)/2] ^= 0xFF
	_, err = crypto.ImportData(raw, dataKey)
	assert.Error(t, err, "tampered bundle must fail")
}

func TestImportData_UnsupportedVersion(t *testing.T) {
	// Мутируем поле version в JSON.
	raw := []byte(`{"version":99,"nonce":"AAAA","ciphertext":"BBBB"}`)
	_, err := crypto.ImportData(raw, make([]byte, 32))
	assert.Error(t, err)
}
