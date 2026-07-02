package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	clientcfg "github.com/alexvictorne/voldepass/internal/client/config"
	"github.com/alexvictorne/voldepass/internal/client/service"
	"github.com/alexvictorne/voldepass/internal/domain"
)

// screen — текущий экран TUI.
type screen int

const (
	screenLogin screen = iota
	screenList
	screenDetail
)

// otpTickInterval — период обновления живого TOTP-кода на экране деталей.
const otpTickInterval = time.Second

// otpTickMsg сигнализирует о необходимости пересчитать TOTP-код.
type otpTickMsg time.Time

// Model — состояние TUI-приложения (реализует tea.Model).
type Model struct {
	ctx context.Context
	cfg clientcfg.Config

	openSession sessionOpener

	screen screen
	err    error

	loginInput    textinput.Model
	passwordInput textinput.Model
	focus         int

	session *service.Session
	vault   *service.VaultManager

	records []domain.RecordDTO
	cursor  int

	detailMeta    string
	detailPayload string
	otpCode       string
	quitting      bool
}

// NewModel создаёт начальную модель на экране логина.
func NewModel(cfg clientcfg.Config) *Model {
	loginInput := textinput.New()
	loginInput.Placeholder = "login"
	loginInput.Focus()

	passwordInput := textinput.New()
	passwordInput.Placeholder = "master password"
	passwordInput.EchoMode = textinput.EchoPassword
	passwordInput.EchoCharacter = '•'

	return &Model{
		ctx:           context.Background(),
		cfg:           cfg,
		openSession:   defaultOpenSession,
		screen:        screenLogin,
		loginInput:    loginInput,
		passwordInput: passwordInput,
	}
}

// Init реализует tea.Model.
func (m *Model) Init() tea.Cmd {
	return textinput.Blink
}

// Update реализует tea.Model — маршрутизирует сообщения по текущему экрану.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch m.screen {
		case screenLogin:
			return m.updateLogin(msg)
		case screenList:
			return m.updateList(msg)
		case screenDetail:
			return m.updateDetail(msg)
		}
	case otpTickMsg:
		if m.screen == screenDetail {
			m.refreshOTP()
			return m, otpTickCmd()
		}
	}
	return m, nil
}

// updateLogin обрабатывает ввод на экране логина: Tab переключает поле,
// Enter пытается залогиниться.
func (m *Model) updateLogin(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyCtrlC, tea.KeyEsc:
		m.quitting = true
		return m, tea.Quit
	case tea.KeyTab:
		m.focus = (m.focus + 1) % 2
		m.applyFocus()
		return m, nil
	case tea.KeyEnter:
		session, vault, _, err := m.openSession(m.ctx, m.cfg, m.loginInput.Value(), m.passwordInput.Value())
		if err != nil {
			m.err = err
			return m, nil
		}
		m.err = nil
		m.session = session
		m.vault = vault
		m.records = vault.List()
		m.screen = screenList
		return m, nil
	}

	var cmd tea.Cmd
	if m.focus == 0 {
		m.loginInput, cmd = m.loginInput.Update(msg)
	} else {
		m.passwordInput, cmd = m.passwordInput.Update(msg)
	}
	return m, cmd
}

// applyFocus переключает bubbles-фокус между полями логина/пароля.
func (m *Model) applyFocus() {
	if m.focus == 0 {
		m.loginInput.Focus()
		m.passwordInput.Blur()
	} else {
		m.loginInput.Blur()
		m.passwordInput.Focus()
	}
}

// updateList обрабатывает навигацию по списку записей.
func (m *Model) updateList(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "q":
		m.quitting = true
		if m.session != nil {
			_ = m.session.Close(m.ctx)
		}
		return m, tea.Quit
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.records)-1 {
			m.cursor++
		}
	case "enter":
		if len(m.records) == 0 {
			return m, nil
		}
		m.openDetail(m.records[m.cursor])
		m.screen = screenDetail
		return m, otpTickCmd()
	}
	return m, nil
}

// openDetail расшифровывает выбранную запись для отображения на экране деталей.
func (m *Model) openDetail(dto domain.RecordDTO) {
	target := newPayloadTarget(dto.Type)
	meta, _, err := m.vault.Get(dto.ID, target)
	if err != nil {
		m.err = err
		return
	}
	m.err = nil
	m.detailMeta = meta
	data, _ := json.MarshalIndent(target, "", "  ")
	m.detailPayload = string(data)
	m.refreshOTP()
}

// refreshOTP пересчитывает текущий TOTP-код для записи, если она открыта на экране деталей.
func (m *Model) refreshOTP() {
	if len(m.records) == 0 {
		return
	}
	dto := m.records[m.cursor]
	if dto.Type != domain.DataTypeOTP {
		m.otpCode = ""
		return
	}
	code, err := m.vault.CurrentTOTP(dto.ID, time.Now())
	if err != nil {
		m.otpCode = ""
		return
	}
	m.otpCode = code
}

// updateDetail обрабатывает экран деталей записи.
func (m *Model) updateDetail(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "q":
		m.quitting = true
		if m.session != nil {
			_ = m.session.Close(m.ctx)
		}
		return m, tea.Quit
	case "esc", "b":
		m.screen = screenList
		return m, nil
	}
	return m, nil
}

// otpTickCmd планирует следующий пересчёт TOTP через otpTickInterval.
func otpTickCmd() tea.Cmd {
	return tea.Tick(otpTickInterval, func(t time.Time) tea.Msg {
		return otpTickMsg(t)
	})
}

// View реализует tea.Model.
func (m *Model) View() string {
	if m.quitting {
		return ""
	}

	switch m.screen {
	case screenLogin:
		return m.viewLogin()
	case screenList:
		return m.viewList()
	case screenDetail:
		return m.viewDetail()
	default:
		return ""
	}
}

func (m *Model) viewLogin() string {
	s := "Voldepass — sign in\n\n"
	s += m.loginInput.View() + "\n"
	s += m.passwordInput.View() + "\n"
	if m.err != nil {
		s += fmt.Sprintf("\nerror: %v\n", m.err)
	}
	s += "\n(tab to switch fields, enter to log in, esc to quit)"
	return s
}

func (m *Model) viewList() string {
	s := "Vault records\n\n"
	if len(m.records) == 0 {
		s += "(no records)\n"
	}
	for i, r := range m.records {
		cursor := "  "
		if i == m.cursor {
			cursor = "> "
		}
		s += fmt.Sprintf("%s%s\n", cursor, r.ID)
	}
	s += "\n(up/down to navigate, enter to view, q to quit)"
	return s
}

func (m *Model) viewDetail() string {
	s := fmt.Sprintf("meta: %s\n\n%s\n", m.detailMeta, m.detailPayload)
	if m.otpCode != "" {
		s += fmt.Sprintf("\nTOTP: %s\n", m.otpCode)
	}
	s += "\n(esc to go back, q to quit)"
	return s
}

// newPayloadTarget возвращает указатель на нулевое значение payload-типа для decode.
func newPayloadTarget(dataType domain.DataType) any {
	switch dataType {
	case domain.DataTypeCredentials:
		return &domain.CredentialsPayload{}
	case domain.DataTypeText:
		return &domain.TextPayload{}
	case domain.DataTypeCard:
		return &domain.CardPayload{}
	case domain.DataTypeOTP:
		return &domain.OTPPayload{}
	default:
		return &map[string]any{}
	}
}
