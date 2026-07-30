package tui

import (
	"bytes"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/exp/teatest"
	"github.com/stretchr/testify/require"

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
	m := newTestModel(t, dataKey, func(t *testing.T, v *service.VaultManager) {
		_, err := v.Create(domain.DataTypeText, "my-note", domain.TextPayload{Content: "original content"})
		require.NoError(t, err)
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
