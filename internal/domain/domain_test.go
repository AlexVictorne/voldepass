package domain_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/alexvictorne/voldepass/internal/domain"
)

// ── DataType ─────────────────────────────────────────────────────────────────

func TestDataType_Valid(t *testing.T) {
	tests := []struct {
		dt   domain.DataType
		want bool
	}{
		{domain.DataTypeUnknown, false},
		{domain.DataTypeCredentials, true},
		{domain.DataTypeText, true},
		{domain.DataTypeBinary, true},
		{domain.DataTypeCard, true},
		{domain.DataTypeOTP, true},
		{domain.DataType(99), false},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, tc.dt.Valid(), "DataType(%d).Valid()", tc.dt)
	}
}

func TestDataType_String(t *testing.T) {
	tests := []struct {
		dt   domain.DataType
		want string
	}{
		{domain.DataTypeUnknown, "unknown"},
		{domain.DataTypeCredentials, "credentials"},
		{domain.DataTypeText, "text"},
		{domain.DataTypeBinary, "binary"},
		{domain.DataTypeCard, "card"},
		{domain.DataTypeOTP, "otp"},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, tc.dt.String())
	}
}

// ── Payload JSON round-trip ───────────────────────────────────────────────────

func TestCredentialsPayload_RoundTrip(t *testing.T) {
	orig := domain.CredentialsPayload{Login: "user@example.com", Password: "s3cr3t"}
	data, err := json.Marshal(orig)
	require.NoError(t, err)

	var got domain.CredentialsPayload
	require.NoError(t, json.Unmarshal(data, &got))
	assert.Equal(t, orig, got)
}

func TestTextPayload_RoundTrip(t *testing.T) {
	orig := domain.TextPayload{Content: "secret note\nwith newline"}
	data, err := json.Marshal(orig)
	require.NoError(t, err)

	var got domain.TextPayload
	require.NoError(t, json.Unmarshal(data, &got))
	assert.Equal(t, orig, got)
}

func TestBinaryPayload_RoundTrip(t *testing.T) {
	orig := domain.BinaryPayload{Data: []byte{0x00, 0xFF, 0xAB}, Filename: "key.bin"}
	data, err := json.Marshal(orig)
	require.NoError(t, err)

	var got domain.BinaryPayload
	require.NoError(t, json.Unmarshal(data, &got))
	assert.Equal(t, orig, got)
}

func TestCardPayload_RoundTrip(t *testing.T) {
	orig := domain.CardPayload{
		Number: "4111111111111111",
		Holder: "JOHN DOE",
		Expiry: "12/26",
		CVV:    "123",
	}
	data, err := json.Marshal(orig)
	require.NoError(t, err)

	var got domain.CardPayload
	require.NoError(t, json.Unmarshal(data, &got))
	assert.Equal(t, orig, got)
}

func TestOTPPayload_RoundTrip(t *testing.T) {
	orig := domain.OTPPayload{
		Secret:    "JBSWY3DPEHPK3PXP",
		Issuer:    "GitHub",
		Account:   "user@example.com",
		Algorithm: "SHA1",
		Digits:    6,
		Period:    30,
	}
	data, err := json.Marshal(orig)
	require.NoError(t, err)

	var got domain.OTPPayload
	require.NoError(t, json.Unmarshal(data, &got))
	assert.Equal(t, orig, got)
}

// ── Sync DTO JSON round-trip ──────────────────────────────────────────────────

func TestRecordDTO_RoundTrip(t *testing.T) {
	orig := domain.RecordDTO{
		ID:            "550e8400-e29b-41d4-a716-446655440000",
		Type:          domain.DataTypeCredentials,
		EncryptedMeta: []byte("encrypted-meta"),
		MetaNonce:     []byte("meta-nonce-12345"),
		Ciphertext:    []byte("ciphertext-data"),
		Nonce:         []byte("nonce-123456789"),
		BaseVersion:   9,
		Version:       10,
		UpdatedAt:     time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC),
		IsDeleted:     false,
	}
	data, err := json.Marshal(orig)
	require.NoError(t, err)

	var got domain.RecordDTO
	require.NoError(t, json.Unmarshal(data, &got))
	assert.Equal(t, orig.ID, got.ID)
	assert.Equal(t, orig.Type, got.Type)
	assert.Equal(t, orig.Ciphertext, got.Ciphertext)
	assert.Equal(t, orig.Version, got.Version)
	assert.True(t, orig.UpdatedAt.Equal(got.UpdatedAt))
}

func TestSyncPushResponse_ConflictStatus(t *testing.T) {
	resp := domain.SyncPushResponse{
		Results: []domain.PushResult{
			{ID: "id-1", Status: domain.PushStatusApplied, ServerRecord: domain.RecordDTO{Version: 5}},
			{ID: "id-2", Status: domain.PushStatusConflict, ServerRecord: domain.RecordDTO{Version: 11}},
		},
	}
	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var got domain.SyncPushResponse
	require.NoError(t, json.Unmarshal(data, &got))
	require.Len(t, got.Results, 2)
	assert.Equal(t, domain.PushStatusApplied, got.Results[0].Status)
	assert.Equal(t, domain.PushStatusConflict, got.Results[1].Status)
	assert.Equal(t, int64(11), got.Results[1].ServerRecord.Version)
}

// ── KdfParams ─────────────────────────────────────────────────────────────────

func TestDefaultKdfParams(t *testing.T) {
	p := domain.DefaultKdfParams()
	assert.Equal(t, uint32(2), p.Time)
	assert.Equal(t, uint32(64*1024), p.Memory)
	assert.Equal(t, uint8(4), p.Threads)
	assert.Equal(t, uint32(32), p.KeyLen)
}

// ── APIVersion ────────────────────────────────────────────────────────────────

func TestAPIVersion_NotEmpty(t *testing.T) {
	assert.NotEmpty(t, domain.APIVersion)
}
