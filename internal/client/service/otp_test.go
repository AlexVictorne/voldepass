package service_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/alexvictorne/voldepass/internal/domain"
)

func TestVaultManager_CurrentTOTP(t *testing.T) {
	v := newVaultManager(t)

	payload := domain.OTPPayload{
		Secret:    "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
		Algorithm: "SHA1",
		Digits:    8,
		Period:    30,
	}
	dto, err := v.Create(domain.DataTypeOTP, "github", payload)
	require.NoError(t, err)

	code, err := v.CurrentTOTP(dto.ID, time.Unix(59, 0))
	require.NoError(t, err)
	assert.Equal(t, "94287082", code, "must match RFC 6238 test vector")
}

func TestVaultManager_CurrentTOTP_WrongType(t *testing.T) {
	v := newVaultManager(t)
	dto, err := v.Create(domain.DataTypeText, "", domain.TextPayload{Content: "not otp"})
	require.NoError(t, err)

	_, err = v.CurrentTOTP(dto.ID, time.Now())
	assert.Error(t, err)
}

func TestVaultManager_CurrentTOTP_NotFound(t *testing.T) {
	v := newVaultManager(t)
	_, err := v.CurrentTOTP("ghost", time.Now())
	assert.ErrorIs(t, err, domain.ErrNotFound)
}
