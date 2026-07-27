package tui

import (
	"bytes"
	"io"
	"regexp"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/exp/teatest"
	"github.com/stretchr/testify/assert"

	"github.com/alexvictorne/voldepass/internal/client/service"
	"github.com/alexvictorne/voldepass/internal/domain"
)

// TestTUI_Teatest_LoginAddAndQuit — сквозной smoke-тест через реальный bubbletea
// event loop (в отличие от остальных тестов пакета, которые вызывают
// Update()/View() напрямую). Гоняет настоящую tea.Program поверх in-memory
// заглушки openSession: логин → пустой список → добавление Credentials-записи
// через форму → запись появляется в списке с расшифрованным meta-лейблом →
// выход. Проверяет, что реальная маршрутизация клавиш и асинхронные tea.Cmd
// (login, submit формы) работают через настоящий раннер, а не только через
// прямые вызовы Update() в остальных тестах.
func TestTUI_Teatest_LoginAddAndQuit(t *testing.T) {
	dataKey := testDataKey(t)
	m := newTestModel(t, dataKey, nil)

	tm := teatest.NewTestModel(t, m, teatest.WithInitialTermSize(100, 30))

	tm.Type("alice")
	tm.Send(tea.KeyMsg{Type: tea.KeyTab})
	tm.Type("master-password")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})

	waitForOutput(t, tm, "no records")

	// 'n' -> экран выбора типа; первый вариант (Credentials) уже под курсором.
	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("n")})
	waitForOutput(t, tm, "choose type")

	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})
	waitForOutput(t, tm, "Add credentials record")

	tm.Type("gmail")
	tm.Send(tea.KeyMsg{Type: tea.KeyTab})
	tm.Type("alice@example.com")
	tm.Send(tea.KeyMsg{Type: tea.KeyTab})
	tm.Type("hunter2")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // сабмит формы (последнее поле)

	waitForOutput(t, tm, "credentials: gmail")

	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))
}

// TestTUI_Teatest_EditAndDeleteThroughRealRunner прогоняет через настоящий
// bubbletea event loop полный жизненный цикл записи: добавление → редактирование
// (с предзаполненной формой) → просмотр обновлённого значения → удаление с
// подтверждением → список снова пуст. Проверяет, что реальная маршрутизация
// клавиш 'e'/'d'/'y' и переиспользование screenAddForm в режиме редактирования
// работают через настоящий раннер, а не только через прямые вызовы Update().
func TestTUI_Teatest_EditAndDeleteThroughRealRunner(t *testing.T) {
	dataKey := testDataKey(t)
	m := newTestModel(t, dataKey, func(v *service.VaultManager) {
		v.Create(domain.DataTypeText, "my-note", domain.TextPayload{Content: "original content"})
	})

	tm := teatest.NewTestModel(t, m, teatest.WithInitialTermSize(100, 30))

	tm.Type("alice")
	tm.Send(tea.KeyMsg{Type: tea.KeyTab})
	tm.Type("master-password")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})

	waitForOutput(t, tm, "text: my-note")

	// Открываем детали и правим запись.
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})
	waitForOutput(t, tm, "original content")

	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("e")})
	waitForOutput(t, tm, "Edit text record")

	tm.Send(tea.KeyMsg{Type: tea.KeyTab}) // meta -> content
	for range "original content" {
		tm.Send(tea.KeyMsg{Type: tea.KeyBackspace})
	}
	tm.Type("updated content")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // сабмит

	waitForOutput(t, tm, "text: my-note")

	// Открываем детали снова и убеждаемся, что новое значение реально сохранилось.
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})
	waitForOutput(t, tm, "updated content")
	tm.Send(tea.KeyMsg{Type: tea.KeyEsc})
	waitForOutput(t, tm, "text: my-note")

	// Удаляем с подтверждением.
	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("d")})
	waitForOutput(t, tm, "delete")

	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})
	waitForOutput(t, tm, "no records")

	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))
}

// waitForOutput ждёт, пока вывод программы не начнёт содержать needle, с разумным таймаутом.
func waitForOutput(t *testing.T, tm *teatest.TestModel, needle string) {
	t.Helper()
	teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
		return bytes.Contains(b, []byte(needle))
	}, teatest.WithDuration(3*time.Second), teatest.WithCheckInterval(20*time.Millisecond))
}

var totpCodeRe = regexp.MustCompile(`TOTP: (\d{6})`)

// waitForOTPCode ждёт первого появления строки "TOTP: <код>" в выводе и возвращает код.
func waitForOTPCode(t *testing.T, r io.Reader, timeout time.Duration) string {
	t.Helper()
	var buf bytes.Buffer
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		_, _ = io.ReadAll(io.TeeReader(r, &buf))
		if m := totpCodeRe.FindSubmatch(buf.Bytes()); m != nil {
			return string(m[1])
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no TOTP code appeared within %s; output so far:\n%s", timeout, buf.String())
	return ""
}

// waitForDifferentOTPCode ждёт появления в выводе кода TOTP, отличного от initial —
// используется, чтобы доказать, что код обновился через настоящий tea.Tick, а не
// был просто отрисован один раз при открытии экрана деталей.
func waitForDifferentOTPCode(t *testing.T, r io.Reader, initial string, timeout time.Duration) string {
	t.Helper()
	var buf bytes.Buffer
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		_, _ = io.ReadAll(io.TeeReader(r, &buf))
		for _, m := range totpCodeRe.FindAllSubmatch(buf.Bytes(), -1) {
			if code := string(m[1]); code != initial {
				return code
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("no OTP code different from %q appeared within %s (live tick never fired); output so far:\n%s", initial, timeout, buf.String())
	return ""
}

// TestTUI_Teatest_LiveOTPTickThroughRealTimer проверяет, что живой TOTP-код на
// экране деталей реально обновляется через настоящий bubbletea-таймер (tea.Tick),
// а не только через ручной вызов otpTickMsg, как это делают остальные тесты пакета
// (TestModel_Detail_LiveOTPUpdatesOnTick), которые не могут отличить настоящую
// работу таймера от простого повторного вызова Update().
func TestTUI_Teatest_LiveOTPTickThroughRealTimer(t *testing.T) {
	dataKey := testDataKey(t)
	m := newTestModel(t, dataKey, func(v *service.VaultManager) {
		// Period=1s совпадает с otpTickInterval — гарантирует смену кода в пределах
		// нескольких секунд без ожидания полного 30-секундного окна по умолчанию.
		_, _ = v.Create(domain.DataTypeOTP, "gh", domain.OTPPayload{
			Secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", Algorithm: "SHA1", Digits: 6, Period: 1,
		})
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
