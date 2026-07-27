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

// fakeSyncTransport — заглушка транспорта синхронизации для тестов Model.
// Pull возвращает заранее заданные записи один раз, затем ничего (since уже сдвинут).
type fakeSyncTransport struct {
	pullRecords []domain.RecordDTO
	pullErr     error
	pulled      bool
}

func (f *fakeSyncTransport) Pull(ctx context.Context, sinceVersion int64) (domain.SyncPullResponse, error) {
	if f.pullErr != nil {
		return domain.SyncPullResponse{}, f.pullErr
	}
	if f.pulled {
		return domain.SyncPullResponse{}, nil
	}
	f.pulled = true
	return domain.SyncPullResponse{Records: f.pullRecords}, nil
}

func (f *fakeSyncTransport) Push(ctx context.Context, idempotencyKey string, req domain.SyncPushRequest) (domain.SyncPushResponse, error) {
	return domain.SyncPushResponse{}, nil
}

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

// newTestModelWithSyncer — как newTestModel, но с реальным *service.Syncer поверх
// fakeSyncTransport, чтобы тестировать ручной sync (клавиша "s" на экране списка).
func newTestModelWithSyncer(t *testing.T, dataKey []byte, transport *fakeSyncTransport, seedRecords func(v *service.VaultManager)) *Model {
	t.Helper()
	store := storage.NewStore()
	vault := service.NewVaultManager(store, dataKey)
	if seedRecords != nil {
		seedRecords(vault)
	}
	fileStore := storage.NewFileStore(t.TempDir() + "/storage.vp")
	fileStore.Store = store
	syncer := service.NewSyncer(transport, store)
	session := service.NewSession(fileStore, dataKey, syncer)

	m := NewModel(clientcfg.Default())
	m.openSession = func(ctx context.Context, cfg clientcfg.Config, login, password string) (*service.Session, *service.VaultManager, *service.Syncer, error) {
		return session, vault, syncer, nil
	}
	return m
}

func testDataKey(t *testing.T) []byte {
	t.Helper()
	// 32 нулевых байт — детерминированный тестовый ключ, реальная стойкость не важна.
	return make([]byte, 32)
}

// loginViaEnter выполняет KeyEnter на экране логина и синхронно прогоняет
// асинхронную loginCmd (см. Model.loginCmd) — так же, как это делает
// настоящий Program, но без реального event loop.
func loginViaEnter(t *testing.T, m *Model) *Model {
	t.Helper()
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(*Model)
	require.NotNil(t, cmd, "KeyEnter on login screen must return the async login command")

	msg := cmd()
	updated, _ = m.Update(msg)
	return updated.(*Model)
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

func TestModel_Login_EnterReturnsAsyncCommand(t *testing.T) {
	m := newTestModel(t, testDataKey(t), nil)

	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m2 := updated.(*Model)
	require.NotNil(t, cmd, "must not block Update; login must run via tea.Cmd")
	assert.True(t, m2.loggingIn)
	assert.Equal(t, screenLogin, m2.screen, "screen must not change until the async result arrives")
}

func TestModel_Login_EnterSuccess_MovesToList(t *testing.T) {
	dataKey := testDataKey(t)
	m := newTestModel(t, dataKey, func(v *service.VaultManager) {
		v.Create(domain.DataTypeText, "note", domain.TextPayload{Content: "hi"})
	})

	m2 := loginViaEnter(t, m)
	assert.Equal(t, screenList, m2.screen)
	assert.False(t, m2.loggingIn)
	assert.Len(t, m2.records, 1)
}

func TestModel_Login_EnterFailure_ShowsError(t *testing.T) {
	m := NewModel(clientcfg.Default())
	m.openSession = func(ctx context.Context, cfg clientcfg.Config, login, password string) (*service.Session, *service.VaultManager, *service.Syncer, error) {
		return nil, nil, nil, assert.AnError
	}

	m2 := loginViaEnter(t, m)
	assert.Equal(t, screenLogin, m2.screen)
	assert.False(t, m2.loggingIn)
	assert.Error(t, m2.err)
}

func TestModel_Login_EnterIgnoredWhileLoggingIn(t *testing.T) {
	m := newTestModel(t, testDataKey(t), nil)

	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(*Model)
	require.NotNil(t, cmd)

	// Повторный Enter, пока первый логин ещё не завершился, не должен запускать второй.
	updated, cmd2 := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(*Model)
	assert.Nil(t, cmd2)
	assert.True(t, m.loggingIn)
}

func TestModel_List_NavigateDownAndUp(t *testing.T) {
	dataKey := testDataKey(t)
	m := newTestModel(t, dataKey, func(v *service.VaultManager) {
		v.Create(domain.DataTypeText, "", domain.TextPayload{Content: "a"})
		v.Create(domain.DataTypeText, "", domain.TextPayload{Content: "b"})
	})
	m = loginViaEnter(t, m)
	require.Equal(t, screenList, m.screen)
	require.Len(t, m.records, 2)

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
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
	m = loginViaEnter(t, m)

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
	m = loginViaEnter(t, m)
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
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
	m = loginViaEnter(t, m)
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
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

func TestModel_List_SyncPullsNewRecords(t *testing.T) {
	dataKey := testDataKey(t)
	transport := &fakeSyncTransport{pullRecords: []domain.RecordDTO{
		{ID: "remote-1", Type: domain.DataTypeText, Ciphertext: []byte("ct"), Nonce: []byte("n")},
	}}
	m := newTestModelWithSyncer(t, dataKey, transport, nil)
	m = loginViaEnter(t, m)
	require.Empty(t, m.records, "no records before sync")

	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("s")})
	m = updated.(*Model)
	require.NotNil(t, cmd, "sync must run asynchronously via tea.Cmd")
	assert.True(t, m.syncing)

	msg := cmd()
	updated, _ = m.Update(msg)
	m = updated.(*Model)

	assert.False(t, m.syncing)
	assert.Nil(t, m.err)
	require.Len(t, m.records, 1)
	assert.Equal(t, "remote-1", m.records[0].ID)
}

func TestModel_List_SyncError_ShowsError(t *testing.T) {
	dataKey := testDataKey(t)
	transport := &fakeSyncTransport{pullErr: assert.AnError}
	m := newTestModelWithSyncer(t, dataKey, transport, nil)
	m = loginViaEnter(t, m)

	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("s")})
	m = updated.(*Model)
	require.NotNil(t, cmd)

	msg := cmd()
	updated, _ = m.Update(msg)
	m = updated.(*Model)

	assert.False(t, m.syncing)
	assert.Error(t, m.err)
}

func TestModel_List_SyncIgnoredWithoutSyncer(t *testing.T) {
	dataKey := testDataKey(t)
	m := newTestModel(t, dataKey, nil) // openSession возвращает nil syncer
	m = loginViaEnter(t, m)

	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("s")})
	m = updated.(*Model)
	assert.Nil(t, cmd, "sync without a syncer must be a no-op")
	assert.False(t, m.syncing)
}

func TestModel_List_SyncIgnoredWhileSyncing(t *testing.T) {
	dataKey := testDataKey(t)
	transport := &fakeSyncTransport{}
	m := newTestModelWithSyncer(t, dataKey, transport, nil)
	m = loginViaEnter(t, m)

	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("s")})
	m = updated.(*Model)
	require.NotNil(t, cmd)

	updated, cmd2 := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("s")})
	m = updated.(*Model)
	assert.Nil(t, cmd2, "must not start a second sync while one is in flight")
	assert.True(t, m.syncing)
}

// sendRunes отправляет строку как последовательность tea.KeyRunes сообщений.
func sendRunes(m *Model, s string) *Model {
	for _, r := range s {
		updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
		m = updated.(*Model)
	}
	return m
}

func openAddForm(t *testing.T, m *Model, typeCursor int) *Model {
	t.Helper()
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("n")})
	m = updated.(*Model)
	require.Equal(t, screenAddType, m.screen)

	for i := 0; i < typeCursor; i++ {
		updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
		m = updated.(*Model)
	}
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(*Model)
	require.Equal(t, screenAddForm, m.screen)
	return m
}

// fillAndSubmitAddForm печатает values в текущий сфокусированный field, переходя
// к следующему клавишей Enter, и на последнем поле сабмитит форму.
func fillAndSubmitAddForm(m *Model, values ...string) *Model {
	for i, v := range values {
		m = sendRunes(m, v)
		key := tea.KeyEnter
		updated, _ := m.Update(tea.KeyMsg{Type: key})
		m = updated.(*Model)
		_ = i
	}
	return m
}

func TestModel_AddType_NavigatesAllFiveTypes(t *testing.T) {
	dataKey := testDataKey(t)
	m := newTestModel(t, dataKey, nil)
	m = loginViaEnter(t, m)

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("n")})
	m = updated.(*Model)
	require.Equal(t, screenAddType, m.screen)
	assert.Equal(t, 0, m.addTypeCursor)

	for i := 0; i < len(addTypeOptions)+2; i++ {
		updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
		m = updated.(*Model)
	}
	assert.Equal(t, len(addTypeOptions)-1, m.addTypeCursor, "cursor must clamp at the last option")
}

func TestModel_AddType_EscCancelsBackToList(t *testing.T) {
	dataKey := testDataKey(t)
	m := newTestModel(t, dataKey, nil)
	m = loginViaEnter(t, m)

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("n")})
	m = updated.(*Model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = updated.(*Model)
	assert.Equal(t, screenList, m.screen)
}

func TestModel_AddForm_EscCancelsBackToList(t *testing.T) {
	dataKey := testDataKey(t)
	m := newTestModel(t, dataKey, nil)
	m = loginViaEnter(t, m)
	m = openAddForm(t, m, 0)

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = updated.(*Model)
	assert.Equal(t, screenList, m.screen)
	assert.Empty(t, m.records)
}

func TestModel_AddForm_Credentials_CreatesRecord(t *testing.T) {
	dataKey := testDataKey(t)
	m := newTestModel(t, dataKey, nil)
	m = loginViaEnter(t, m)
	m = openAddForm(t, m, 0) // Credentials

	m = fillAndSubmitAddForm(m, "my-service", "alice", "s3cret")

	require.Equal(t, screenList, m.screen)
	require.NoError(t, m.err)
	require.Len(t, m.records, 1)
	assert.Equal(t, domain.DataTypeCredentials, m.records[0].Type)

	var payload domain.CredentialsPayload
	meta, _, err := m.vault.Get(m.records[0].ID, &payload)
	require.NoError(t, err)
	assert.Equal(t, "my-service", meta)
	assert.Equal(t, "alice", payload.Login)
	assert.Equal(t, "s3cret", payload.Password)
}

func TestModel_AddForm_Text_CreatesRecord(t *testing.T) {
	dataKey := testDataKey(t)
	m := newTestModel(t, dataKey, nil)
	m = loginViaEnter(t, m)
	m = openAddForm(t, m, 1) // Text

	m = fillAndSubmitAddForm(m, "note", "hello world")

	require.Len(t, m.records, 1)
	var payload domain.TextPayload
	_, _, err := m.vault.Get(m.records[0].ID, &payload)
	require.NoError(t, err)
	assert.Equal(t, "hello world", payload.Content)
}

func TestModel_AddForm_Binary_CreatesRecord(t *testing.T) {
	dataKey := testDataKey(t)
	m := newTestModel(t, dataKey, nil)
	m = loginViaEnter(t, m)
	m = openAddForm(t, m, 2) // Binary

	m = fillAndSubmitAddForm(m, "file", "raw-bytes", "note.txt")

	require.Len(t, m.records, 1)
	var payload domain.BinaryPayload
	_, _, err := m.vault.Get(m.records[0].ID, &payload)
	require.NoError(t, err)
	assert.Equal(t, []byte("raw-bytes"), payload.Data)
	assert.Equal(t, "note.txt", payload.Filename)
}

func TestModel_AddForm_Card_CreatesRecord(t *testing.T) {
	dataKey := testDataKey(t)
	m := newTestModel(t, dataKey, nil)
	m = loginViaEnter(t, m)
	m = openAddForm(t, m, 3) // Card

	m = fillAndSubmitAddForm(m, "visa", "4111111111111111", "Alice", "12/30", "123")

	require.Len(t, m.records, 1)
	var payload domain.CardPayload
	_, _, err := m.vault.Get(m.records[0].ID, &payload)
	require.NoError(t, err)
	assert.Equal(t, "4111111111111111", payload.Number)
	assert.Equal(t, "Alice", payload.Holder)
	assert.Equal(t, "12/30", payload.Expiry)
	assert.Equal(t, "123", payload.CVV)
}

func TestModel_AddForm_OTP_CreatesRecordWithDefaults(t *testing.T) {
	dataKey := testDataKey(t)
	m := newTestModel(t, dataKey, nil)
	m = loginViaEnter(t, m)
	m = openAddForm(t, m, 4) // OTP

	// meta, secret, issuer, account — заполняем; algorithm/digits/period оставляем
	// пустыми, чтобы проверить дефолты (SHA1/6/30 применяются на стороне REST/crypto,
	// а тут — что пустая строка не ломает парсинг чисел).
	m = fillAndSubmitAddForm(m, "gh", "JBSWY3DPEHPK3PXP", "GitHub", "alice@example.com", "", "", "")

	require.NoError(t, m.err)
	require.Len(t, m.records, 1)
	var payload domain.OTPPayload
	_, _, err := m.vault.Get(m.records[0].ID, &payload)
	require.NoError(t, err)
	assert.Equal(t, "JBSWY3DPEHPK3PXP", payload.Secret)
	assert.Equal(t, "GitHub", payload.Issuer)
	assert.Equal(t, "alice@example.com", payload.Account)
	assert.Equal(t, 6, payload.Digits)
	assert.Equal(t, 30, payload.Period)
}

func TestModel_AddForm_InvalidDigits_ShowsError(t *testing.T) {
	dataKey := testDataKey(t)
	m := newTestModel(t, dataKey, nil)
	m = loginViaEnter(t, m)
	m = openAddForm(t, m, 4) // OTP

	m = fillAndSubmitAddForm(m, "gh", "JBSWY3DPEHPK3PXP", "", "", "", "not-a-number", "30")

	assert.Equal(t, screenAddForm, m.screen, "must stay on the form when a field fails to parse")
	assert.Error(t, m.err)
	assert.Empty(t, m.records)
}

func TestModel_List_ShowsLastSyncTime(t *testing.T) {
	dataKey := testDataKey(t)
	transport := &fakeSyncTransport{}
	m := newTestModelWithSyncer(t, dataKey, transport, nil)
	m = loginViaEnter(t, m)

	assert.True(t, m.lastSyncAt.IsZero(), "must not report a sync time before any sync ran")
	assert.Contains(t, m.viewList(), "not synced yet")

	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("s")})
	m = updated.(*Model)
	require.NotNil(t, cmd)

	msg := cmd()
	updated, _ = m.Update(msg)
	m = updated.(*Model)

	assert.False(t, m.lastSyncAt.IsZero(), "successful sync must record a timestamp")
	assert.Contains(t, m.viewList(), m.lastSyncAt.Format("2006-01-02 15:04:05"))
}

func TestModel_List_SyncError_DoesNotUpdateLastSyncTime(t *testing.T) {
	dataKey := testDataKey(t)
	transport := &fakeSyncTransport{pullErr: assert.AnError}
	m := newTestModelWithSyncer(t, dataKey, transport, nil)
	m = loginViaEnter(t, m)

	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("s")})
	m = updated.(*Model)
	require.NotNil(t, cmd)

	msg := cmd()
	updated, _ = m.Update(msg)
	m = updated.(*Model)

	assert.True(t, m.lastSyncAt.IsZero(), "failed sync must not record a timestamp")
	assert.Contains(t, m.viewList(), "not synced yet")
}

func TestModel_List_ShowsMetaLabelNotRawID(t *testing.T) {
	dataKey := testDataKey(t)
	m := newTestModel(t, dataKey, func(v *service.VaultManager) {
		v.Create(domain.DataTypeCredentials, "gmail", domain.CredentialsPayload{Login: "a", Password: "b"})
	})
	m = loginViaEnter(t, m)

	require.Len(t, m.recordLabels, 1)
	assert.Contains(t, m.recordLabels[0], "gmail")
	assert.NotContains(t, m.recordLabels[0], m.records[0].ID, "list must not show the raw record UUID when a meta label is available")

	view := m.viewList()
	assert.Contains(t, view, "gmail")
	assert.NotContains(t, view, m.records[0].ID)
}

func TestModel_List_FallsBackToIDWhenMetaEmpty(t *testing.T) {
	dataKey := testDataKey(t)
	m := newTestModel(t, dataKey, func(v *service.VaultManager) {
		v.Create(domain.DataTypeText, "", domain.TextPayload{Content: "no meta"})
	})
	m = loginViaEnter(t, m)

	require.Len(t, m.recordLabels, 1)
	assert.Contains(t, m.recordLabels[0], m.records[0].ID, "must fall back to the record ID when there is no meta label")
}

func TestModel_AddForm_NewRecordGetsMetaLabelInList(t *testing.T) {
	dataKey := testDataKey(t)
	m := newTestModel(t, dataKey, nil)
	m = loginViaEnter(t, m)
	m = openAddForm(t, m, 1) // Text

	m = fillAndSubmitAddForm(m, "my-note", "hello world")

	require.Len(t, m.recordLabels, 1)
	assert.Contains(t, m.recordLabels[0], "my-note")
}

// ── Delete ──────────────────────────────────────────────────────────────────

func TestModel_List_DeleteKey_ShowsConfirmation(t *testing.T) {
	dataKey := testDataKey(t)
	m := newTestModel(t, dataKey, func(v *service.VaultManager) {
		v.Create(domain.DataTypeText, "my-note", domain.TextPayload{Content: "x"})
	})
	m = loginViaEnter(t, m)

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("d")})
	m = updated.(*Model)

	assert.Equal(t, m.records[0].ID, m.confirmDeleteID)
	assert.Contains(t, m.viewList(), "my-note")
	assert.Contains(t, m.viewList(), "(y/n)")
	require.Len(t, m.records, 1, "record must not be deleted until confirmed")
}

func TestModel_List_DeleteKey_EmptyListIsNoop(t *testing.T) {
	dataKey := testDataKey(t)
	m := newTestModel(t, dataKey, nil)
	m = loginViaEnter(t, m)

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("d")})
	m = updated.(*Model)

	assert.Empty(t, m.confirmDeleteID)
}

func TestModel_DeleteConfirm_Yes_DeletesRecord(t *testing.T) {
	dataKey := testDataKey(t)
	m := newTestModel(t, dataKey, func(v *service.VaultManager) {
		v.Create(domain.DataTypeText, "my-note", domain.TextPayload{Content: "x"})
	})
	m = loginViaEnter(t, m)

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("d")})
	m = updated.(*Model)
	require.NotEmpty(t, m.confirmDeleteID)

	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})
	m = updated.(*Model)

	assert.Empty(t, m.confirmDeleteID)
	assert.Empty(t, m.records, "record must be gone from the list after confirmed delete")
}

func TestModel_DeleteConfirm_AnyOtherKey_Cancels(t *testing.T) {
	dataKey := testDataKey(t)
	m := newTestModel(t, dataKey, func(v *service.VaultManager) {
		v.Create(domain.DataTypeText, "my-note", domain.TextPayload{Content: "x"})
	})
	m = loginViaEnter(t, m)

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("d")})
	m = updated.(*Model)
	require.NotEmpty(t, m.confirmDeleteID)

	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("n")})
	m = updated.(*Model)

	assert.Empty(t, m.confirmDeleteID)
	require.Len(t, m.records, 1, "record must survive a non-'y' response")
}

func TestModel_DeleteConfirm_ClampsCursorWhenLastRecordDeleted(t *testing.T) {
	dataKey := testDataKey(t)
	m := newTestModel(t, dataKey, func(v *service.VaultManager) {
		v.Create(domain.DataTypeText, "a", domain.TextPayload{Content: "a"})
		v.Create(domain.DataTypeText, "b", domain.TextPayload{Content: "b"})
	})
	m = loginViaEnter(t, m)
	m.cursor = 1 // последняя запись

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("d")})
	m = updated.(*Model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})
	m = updated.(*Model)

	require.Len(t, m.records, 1)
	assert.Equal(t, 0, m.cursor, "cursor must clamp to the last remaining index")
}

// ── Edit ────────────────────────────────────────────────────────────────────

func TestModel_Detail_EditKey_OpensPrefilledForm(t *testing.T) {
	dataKey := testDataKey(t)
	m := newTestModel(t, dataKey, func(v *service.VaultManager) {
		v.Create(domain.DataTypeCredentials, "gmail", domain.CredentialsPayload{Login: "alice", Password: "s3cret"})
	})
	m = loginViaEnter(t, m)

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter}) // open detail
	m = updated.(*Model)
	require.Equal(t, screenDetail, m.screen)

	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("e")})
	m = updated.(*Model)

	require.Equal(t, screenAddForm, m.screen)
	assert.Equal(t, m.records[0].ID, m.editingID)
	assert.Equal(t, "gmail", m.addFields[0].input.Value())
	assert.Equal(t, "alice", m.addFields[1].input.Value())
	assert.Equal(t, "s3cret", m.addFields[2].input.Value())
	assert.Contains(t, m.viewAddForm(), "Edit credentials record")
}

func TestModel_Edit_Submit_UpdatesExistingRecordInPlace(t *testing.T) {
	dataKey := testDataKey(t)
	m := newTestModel(t, dataKey, func(v *service.VaultManager) {
		v.Create(domain.DataTypeText, "note", domain.TextPayload{Content: "v1"})
	})
	m = loginViaEnter(t, m)
	originalID := m.records[0].ID

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter}) // detail
	m = updated.(*Model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("e")})
	m = updated.(*Model)
	require.Equal(t, screenAddForm, m.screen)

	// Переходим на поле content (индекс 1), стираем старое значение "v1" и
	// вводим новое, затем сабмитим (Enter на последнем поле).
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyTab})
	m = updated.(*Model)
	for range "v1" {
		updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyBackspace})
		m = updated.(*Model)
	}
	m = sendRunes(m, "v2-edited")
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(*Model)

	require.Equal(t, screenList, m.screen)
	require.Len(t, m.records, 1, "edit must not create a second record")
	assert.Equal(t, originalID, m.records[0].ID, "edit must preserve the record's ID")

	var payload domain.TextPayload
	_, _, err := m.vault.Get(originalID, &payload)
	require.NoError(t, err)
	assert.Equal(t, "v2-edited", payload.Content)
}

func TestModel_Edit_EscCancel_LeavesRecordUnchanged(t *testing.T) {
	dataKey := testDataKey(t)
	m := newTestModel(t, dataKey, func(v *service.VaultManager) {
		v.Create(domain.DataTypeText, "note", domain.TextPayload{Content: "original"})
	})
	m = loginViaEnter(t, m)

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(*Model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("e")})
	m = updated.(*Model)
	require.Equal(t, screenAddForm, m.screen)

	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = updated.(*Model)

	assert.Equal(t, screenList, m.screen)
	assert.Empty(t, m.editingID)

	var payload domain.TextPayload
	_, _, err := m.vault.Get(m.records[0].ID, &payload)
	require.NoError(t, err)
	assert.Equal(t, "original", payload.Content, "cancelling edit must not touch the record")
}

func TestModel_Edit_OTP_PrefillsAllFields(t *testing.T) {
	dataKey := testDataKey(t)
	m := newTestModel(t, dataKey, func(v *service.VaultManager) {
		v.Create(domain.DataTypeOTP, "gh", domain.OTPPayload{
			Secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", Issuer: "GitHub", Account: "alice",
			Algorithm: "SHA256", Digits: 8, Period: 60,
		})
	})
	m = loginViaEnter(t, m)

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(*Model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("e")})
	m = updated.(*Model)

	require.Equal(t, screenAddForm, m.screen)
	assert.Equal(t, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", m.addFields[1].input.Value())
	assert.Equal(t, "GitHub", m.addFields[2].input.Value())
	assert.Equal(t, "alice", m.addFields[3].input.Value())
	assert.Equal(t, "SHA256", m.addFields[4].input.Value())
	assert.Equal(t, "8", m.addFields[5].input.Value())
	assert.Equal(t, "60", m.addFields[6].input.Value())
}

func TestModel_Edit_Binary_Prefills(t *testing.T) {
	dataKey := testDataKey(t)
	m := newTestModel(t, dataKey, func(v *service.VaultManager) {
		v.Create(domain.DataTypeBinary, "file", domain.BinaryPayload{Data: []byte("raw-bytes"), Filename: "note.txt"})
	})
	m = loginViaEnter(t, m)

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(*Model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("e")})
	m = updated.(*Model)

	require.Equal(t, screenAddForm, m.screen)
	assert.Equal(t, "raw-bytes", m.addFields[1].input.Value())
	assert.Equal(t, "note.txt", m.addFields[2].input.Value())
}
