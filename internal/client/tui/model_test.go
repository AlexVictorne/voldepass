package tui

import (
	"context"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	clientcfg "github.com/alexvictorne/voldepass/internal/client/config"
	"github.com/alexvictorne/voldepass/internal/client/service"
	"github.com/alexvictorne/voldepass/internal/client/storage"
	"github.com/alexvictorne/voldepass/internal/domain"
)

// newTestModel создаёт модель с in-memory openSession-заглушкой — без сети и файлов.
func newTestModel(t *testing.T, dataKey []byte, seedRecords func(v *service.VaultManager)) *Model {
	t.Helper()
	store := storage.NewStore()
	vault := service.NewVaultManager(store, dataKey)
	if seedRecords != nil {
		seedRecords(vault)
	}
	fileStore := storage.NewFileStore(t.TempDir() + "/storage.vp")
	fileStore.Store = store
	session := service.NewSession(fileStore, dataKey, nil)

	m := NewModel(clientcfg.Default())
	m.openSession = func(ctx context.Context, cfg clientcfg.Config, login, password string) (*service.Session, *service.VaultManager, *service.Syncer, error) {
		return session, vault, nil, nil
	}
	return m
}

func testDataKey(t *testing.T) []byte {
	t.Helper()
	// 32 нулевых байт — детерминированный тестовый ключ, реальная стойкость не важна.
	return make([]byte, 32)
}

func TestModel_InitialScreen(t *testing.T) {
	m := NewModel(clientcfg.Default())
	assert.Equal(t, screenLogin, m.screen)
}

func TestModel_Login_TabSwitchesFocus(t *testing.T) {
	m := newTestModel(t, testDataKey(t), nil)
	assert.Equal(t, 0, m.focus)

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyTab})
	m2 := updated.(*Model)
	assert.Equal(t, 1, m2.focus)
}

func TestModel_Login_EscQuits(t *testing.T) {
	m := newTestModel(t, testDataKey(t), nil)
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	require.NotNil(t, cmd)
	assert.True(t, m.quitting)
}

func TestModel_Login_EnterSuccess_MovesToList(t *testing.T) {
	dataKey := testDataKey(t)
	m := newTestModel(t, dataKey, func(v *service.VaultManager) {
		v.Create(domain.DataTypeText, "note", domain.TextPayload{Content: "hi"})
	})

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m2 := updated.(*Model)
	assert.Equal(t, screenList, m2.screen)
	assert.Len(t, m2.records, 1)
}

func TestModel_Login_EnterFailure_ShowsError(t *testing.T) {
	m := NewModel(clientcfg.Default())
	m.openSession = func(ctx context.Context, cfg clientcfg.Config, login, password string) (*service.Session, *service.VaultManager, *service.Syncer, error) {
		return nil, nil, nil, assert.AnError
	}

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m2 := updated.(*Model)
	assert.Equal(t, screenLogin, m2.screen)
	assert.Error(t, m2.err)
}

func TestModel_List_NavigateDownAndUp(t *testing.T) {
	dataKey := testDataKey(t)
	m := newTestModel(t, dataKey, func(v *service.VaultManager) {
		v.Create(domain.DataTypeText, "", domain.TextPayload{Content: "a"})
		v.Create(domain.DataTypeText, "", domain.TextPayload{Content: "b"})
	})
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(*Model)
	require.Equal(t, screenList, m.screen)
	require.Len(t, m.records, 2)

	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
	m = updated.(*Model)
	assert.Equal(t, 1, m.cursor)

	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("k")})
	m = updated.(*Model)
	assert.Equal(t, 0, m.cursor)
}

func TestModel_List_EnterOpensDetail(t *testing.T) {
	dataKey := testDataKey(t)
	m := newTestModel(t, dataKey, func(v *service.VaultManager) {
		v.Create(domain.DataTypeText, "my-note", domain.TextPayload{Content: "secret content"})
	})
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter}) // login
	m = updated.(*Model)

	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter}) // open detail
	m = updated.(*Model)
	assert.Equal(t, screenDetail, m.screen)
	assert.Equal(t, "my-note", m.detailMeta)
	assert.Contains(t, m.detailPayload, "secret content")
	assert.NotNil(t, cmd, "must schedule OTP tick")
}

func TestModel_Detail_EscReturnsToList(t *testing.T) {
	dataKey := testDataKey(t)
	m := newTestModel(t, dataKey, func(v *service.VaultManager) {
		v.Create(domain.DataTypeText, "", domain.TextPayload{Content: "x"})
	})
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(*Model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(*Model)
	require.Equal(t, screenDetail, m.screen)

	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = updated.(*Model)
	assert.Equal(t, screenList, m.screen)
}

func TestModel_Detail_LiveOTPUpdatesOnTick(t *testing.T) {
	dataKey := testDataKey(t)
	m := newTestModel(t, dataKey, func(v *service.VaultManager) {
		v.Create(domain.DataTypeOTP, "gh", domain.OTPPayload{
			Secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", Algorithm: "SHA1", Digits: 6, Period: 30,
		})
	})
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(*Model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(*Model)
	require.Equal(t, screenDetail, m.screen)
	assert.NotEmpty(t, m.otpCode)

	m.otpCode = ""
	updated, cmd := m.Update(otpTickMsg{})
	m = updated.(*Model)
	assert.NotEmpty(t, m.otpCode, "tick must refresh OTP code")
	assert.NotNil(t, cmd, "must schedule next tick")
}

func TestModel_View_DoesNotPanic(t *testing.T) {
	m := NewModel(clientcfg.Default())
	assert.NotPanics(t, func() { m.View() })

	m.screen = screenList
	assert.NotPanics(t, func() { m.View() })

	m.screen = screenDetail
	assert.NotPanics(t, func() { m.View() })
}
