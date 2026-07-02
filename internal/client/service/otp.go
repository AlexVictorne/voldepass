package service

import (
	"fmt"
	"time"

	"github.com/alexvictorne/voldepass/internal/client/crypto"
	"github.com/alexvictorne/voldepass/internal/domain"
)

// CurrentTOTP расшифровывает OTP-запись по ID и вычисляет текущий TOTP-код
// на момент времени t (обычно time.Now()).
func (v *VaultManager) CurrentTOTP(id string, t time.Time) (string, error) {
	var payload domain.OTPPayload
	_, dto, err := v.Get(id, &payload)
	if err != nil {
		return "", fmt.Errorf("current totp: %w", err)
	}
	if dto.Type != domain.DataTypeOTP {
		return "", fmt.Errorf("current totp: record %s is not an OTP record", id)
	}

	code, err := crypto.GenerateTOTP(payload.Secret, payload.Algorithm, payload.Digits, payload.Period, t)
	if err != nil {
		return "", fmt.Errorf("current totp: %w", err)
	}
	return code, nil
}
