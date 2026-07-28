//go:build slow

package tui

import (
	"io"
	"regexp"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/exp/teatest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/alexvictorne/voldepass/internal/client/service"
	"github.com/alexvictorne/voldepass/internal/domain"
)

var totpCodeRe = regexp.MustCompile(`TOTP: (\d{6})`)

// waitForOTPCode ждёт первого появления строки "TOTP: <код>" в выводе и возвращает код.
// Опирается на teatest.WaitFor — тот же механизм polling'а/таймаута, что и waitForOutput,
// вместо ручного цикла с io.ReadAll/time.Sleep.
func waitForOTPCode(t *testing.T, r io.Reader, timeout time.Duration) string {
	t.Helper()
	var code string
	teatest.WaitFor(t, r, func(b []byte) bool {
		m := totpCodeRe.FindSubmatch(b)
		if m == nil {
			return false
		}
		code = string(m[1])
		return true
	}, teatest.WithDuration(timeout), teatest.WithCheckInterval(20*time.Millisecond))
	return code
}

// waitForDifferentOTPCode ждёт появления в выводе кода TOTP, отличного от initial —
// используется, чтобы доказать, что код обновился через настоящий tea.Tick, а не
// был просто отрисован один раз при открытии экрана деталей.
func waitForDifferentOTPCode(t *testing.T, r io.Reader, initial string, timeout time.Duration) string {
	t.Helper()
	var code string
	teatest.WaitFor(t, r, func(b []byte) bool {
		for _, m := range totpCodeRe.FindAllSubmatch(b, -1) {
			if c := string(m[1]); c != initial {
				code = c
				return true
			}
		}
		return false
	}, teatest.WithDuration(timeout), teatest.WithCheckInterval(50*time.Millisecond))
	return code
}

// TestTUI_Teatest_LiveOTPTickThroughRealTimer проверяет, что живой TOTP-код на
// экране деталей реально обновляется через настоящий bubbletea-таймер (tea.Tick),
// а не только через ручной вызов otpTickMsg, как это делают остальные тесты пакета
// (TestModel_Detail_LiveOTPUpdatesOnTick), которые не могут отличить настоящую
// работу таймера от простого повторного вызова Update().
//
// Тест ждёт реального срабатывания tea.Tick (Period=1s, таймаут до 5s) — это
// заметно медленнее остальных тестов пакета, поэтому он вынесен под build tag
// slow и не входит в обычный `make test`; гоняется отдельно через `make test-slow`.
func TestTUI_Teatest_LiveOTPTickThroughRealTimer(t *testing.T) {
	dataKey := testDataKey(t)
	m := newTestModel(t, dataKey, func(t *testing.T, v *service.VaultManager) {
		// Period=1s совпадает с otpTickInterval — гарантирует смену кода в пределах
		// нескольких секунд без ожидания полного 30-секундного окна по умолчанию.
		_, err := v.Create(domain.DataTypeOTP, "gh", domain.OTPPayload{
			Secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", Algorithm: "SHA1", Digits: 6, Period: 1,
		})
		require.NoError(t, err)
	})

	tm := teatest.NewTestModel(t, m, teatest.WithInitialTermSize(100, 30))

	tm.Type("alice")
	tm.Send(tea.KeyMsg{Type: tea.KeyTab})
	tm.Type("master-password")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})

	waitForOutput(t, tm, "otp: gh")

	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // открыть экран деталей

	initial := waitForOTPCode(t, tm.Output(), 3*time.Second)
	changed := waitForDifferentOTPCode(t, tm.Output(), initial, 5*time.Second)
	assert.NotEqual(t, initial, changed)

	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))
}
