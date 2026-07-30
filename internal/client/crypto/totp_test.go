package crypto_test

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/alexvictorne/voldepass/internal/client/crypto"
)

type totpVector struct {
	Secret    string `json:"secret"`
	Algorithm string `json:"algorithm"`
	Digits    int    `json:"digits"`
	Period    int    `json:"period"`
	Unix      int64  `json:"unix"`
	Expected  string `json:"expected"`
}

// TestGenerateTOTP_RFC6238Vectors проверяет реализацию против официальных тест-векторов RFC 6238.
func TestGenerateTOTP_RFC6238Vectors(t *testing.T) {
	data, err := os.ReadFile("testdata/rfc6238_vectors.json")
	require.NoError(t, err)

	var vectors []totpVector
	require.NoError(t, json.Unmarshal(data, &vectors))

	for _, v := range vectors {
		t.Run(v.Algorithm+"_"+v.Expected, func(t *testing.T) {
			got, err := crypto.GenerateTOTP(v.Secret, v.Algorithm, v.Digits, v.Period, time.Unix(v.Unix, 0))
			require.NoError(t, err)
			assert.Equal(t, v.Expected, got)
		})
	}
}

func TestGenerateTOTP_Defaults(t *testing.T) {
	// Проверяем, что нулевые digits/period заменяются значениями по умолчанию.
	secret := "JBSWY3DPEHPK3PXP"
	// 1000000000 % 30 == 10, т.е. период заканчивается через 20 сек.
	t1 := time.Unix(1000000000, 0)
	t2 := time.Unix(1000000000+19, 0) // в том же периоде (до границы)

	code1, err := crypto.GenerateTOTP(secret, "SHA1", 0, 0, t1)
	require.NoError(t, err)
	code2, err := crypto.GenerateTOTP(secret, "SHA1", 0, 0, t2)
	require.NoError(t, err)

	assert.Len(t, code1, 6, "default digits must be 6")
	assert.Equal(t, code1, code2, "codes within the same period must match")
}

func TestGenerateTOTP_PeriodBoundary(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	period := 30
	base := int64(1000000000)
	// base и base+period — разные периоды.
	code1, _ := crypto.GenerateTOTP(secret, "SHA1", 6, period, time.Unix(base, 0))
	code2, _ := crypto.GenerateTOTP(secret, "SHA1", 6, period, time.Unix(base+int64(period), 0))
	assert.NotEqual(t, code1, code2, "codes in adjacent periods must differ")
}

func TestGenerateTOTP_InvalidAlgorithm(t *testing.T) {
	_, err := crypto.GenerateTOTP("JBSWY3DPEHPK3PXP", "MD5", 6, 30, time.Now())
	assert.Error(t, err)
}

func TestGenerateTOTP_InvalidSecret(t *testing.T) {
	_, err := crypto.GenerateTOTP("not-valid-base32!!!", "SHA1", 6, 30, time.Now())
	assert.Error(t, err)
}
