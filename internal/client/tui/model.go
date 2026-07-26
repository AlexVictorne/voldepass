package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
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
	screenAddType
	screenAddForm
)

// addTypeOption — выбираемый в screenAddType вариант типа новой записи.
type addTypeOption struct {
	dataType domain.DataType
	label    string
}

// addTypeOptions — все 5 поддерживаемых типов данных, в порядке отображения.
var addTypeOptions = []addTypeOption{
	{domain.DataTypeCredentials, "Credentials (login/password)"},
	{domain.DataTypeText, "Text"},
	{domain.DataTypeBinary, "Binary (base64 or raw text as data)"},
	{domain.DataTypeCard, "Card"},
	{domain.DataTypeOTP, "OTP (TOTP)"},
}

// addFormField — одно поле динамической формы добавления записи.
type addFormField struct {
	label string
	input textinput.Model
}

// newAddFormField создаёт поле формы с заданным лейблом и placeholder'ом.
func newAddFormField(label, placeholder string, secret bool) addFormField {
	ti := textinput.New()
	ti.Placeholder = placeholder
	if secret {
		ti.EchoMode = textinput.EchoPassword
		ti.EchoCharacter = '•'
	}
	return addFormField{label: label, input: ti}
}

// buildAddFormFields возвращает набор полей формы для выбранного типа записи.
// Первое поле всегда — необязательная meta-метка.
func buildAddFormFields(dataType domain.DataType) []addFormField {
	fields := []addFormField{newAddFormField("meta (label)", "optional note", false)}
	switch dataType {
	case domain.DataTypeCredentials:
		fields = append(fields,
			newAddFormField("login", "", false),
			newAddFormField("password", "", true),
		)
	case domain.DataTypeText:
		fields = append(fields, newAddFormField("content", "", false))
	case domain.DataTypeBinary:
		fields = append(fields,
			newAddFormField("data", "raw text, stored as bytes", false),
			newAddFormField("filename", "optional", false),
		)
	case domain.DataTypeCard:
		fields = append(fields,
			newAddFormField("number", "", false),
			newAddFormField("holder", "", false),
			newAddFormField("expiry", "MM/YY", false),
			newAddFormField("cvv", "", true),
		)
	case domain.DataTypeOTP:
		fields = append(fields,
			newAddFormField("secret", "base32", false),
			newAddFormField("issuer", "optional", false),
			newAddFormField("account", "optional", false),
			newAddFormField("algorithm", "SHA1/SHA256/SHA512 (default SHA1)", false),
			newAddFormField("digits", "default 6", false),
			newAddFormField("period", "default 30 (seconds)", false),
		)
	}
	return fields
}

// buildAddPayload собирает payload нужного типа из значений полей формы.
// fields[0] — всегда meta, остальные соответствуют порядку в buildAddFormFields.
func buildAddPayload(dataType domain.DataType, fields []addFormField) (meta string, payload any, err error) {
	meta = fields[0].input.Value()
	values := fields[1:]
	v := func(i int) string { return values[i].input.Value() }

	switch dataType {
	case domain.DataTypeCredentials:
		return meta, domain.CredentialsPayload{Login: v(0), Password: v(1)}, nil
	case domain.DataTypeText:
		return meta, domain.TextPayload{Content: v(0)}, nil
	case domain.DataTypeBinary:
		return meta, domain.BinaryPayload{Data: []byte(v(0)), Filename: v(1)}, nil
	case domain.DataTypeCard:
		return meta, domain.CardPayload{Number: v(0), Holder: v(1), Expiry: v(2), CVV: v(3)}, nil
	case domain.DataTypeOTP:
		digits := 6
		if s := v(4); s != "" {
			digits, err = strconv.Atoi(s)
			if err != nil {
				return "", nil, fmt.Errorf("digits: %w", err)
			}
		}
		period := 30
		if s := v(5); s != "" {
			period, err = strconv.Atoi(s)
			if err != nil {
				return "", nil, fmt.Errorf("period: %w", err)
			}
		}
		return meta, domain.OTPPayload{
			Secret: v(0), Issuer: v(1), Account: v(2), Algorithm: v(3), Digits: digits, Period: period,
		}, nil
	default:
		return "", nil, fmt.Errorf("%w: unsupported type %v", domain.ErrInvalidArgument, dataType)
	}
}

// otpTickInterval — период обновления живого TOTP-кода на экране деталей.
const otpTickInterval = time.Second

// otpTickMsg сигнализирует о необходимости пересчитать TOTP-код.
type otpTickMsg time.Time

// sessionResultMsg — результат асинхронного openSession (см. loginCmd).
type sessionResultMsg struct {
	session *service.Session
	vault   *service.VaultManager
	syncer  *service.Syncer
	err     error
}

// syncResultMsg — результат асинхронного Syncer.Sync (см. syncCmd).
type syncResultMsg struct {
	conflicts []domain.RecordDTO
	err       error
}

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
	loggingIn     bool

	session *service.Session
	vault   *service.VaultManager
	syncer  *service.Syncer
	syncing bool

	records    []domain.RecordDTO
	cursor     int
	lastSyncAt time.Time

	detailMeta    string
	detailPayload string
	otpCode       string
	quitting      bool

	addTypeCursor int
	addDataType   domain.DataType
	addFields     []addFormField
	addFocus      int
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
		case screenAddType:
			return m.updateAddType(msg)
		case screenAddForm:
			return m.updateAddForm(msg)
		}
	case otpTickMsg:
		if m.screen == screenDetail {
			m.refreshOTP()
			return m, otpTickCmd()
		}
	case sessionResultMsg:
		return m.handleSessionResult(msg)
	case syncResultMsg:
		return m.handleSyncResult(msg)
	}
	return m, nil
}

// handleSessionResult обрабатывает результат асинхронного логина (см. loginCmd).
func (m *Model) handleSessionResult(msg sessionResultMsg) (tea.Model, tea.Cmd) {
	m.loggingIn = false
	if msg.err != nil {
		m.err = msg.err
		return m, nil
	}
	m.err = nil
	m.session = msg.session
	m.vault = msg.vault
	m.syncer = msg.syncer
	m.records = msg.vault.List()
	m.screen = screenList
	return m, nil
}

// handleSyncResult обрабатывает результат асинхронного Syncer.Sync (см. syncCmd).
func (m *Model) handleSyncResult(msg syncResultMsg) (tea.Model, tea.Cmd) {
	m.syncing = false
	if msg.err != nil {
		m.err = msg.err
		return m, nil
	}
	m.err = nil
	m.lastSyncAt = time.Now()
	m.records = m.vault.List()
	if m.cursor >= len(m.records) {
		m.cursor = max(len(m.records)-1, 0)
	}
	if len(msg.conflicts) > 0 {
		m.err = fmt.Errorf("sync completed with %d unresolved conflict(s)", len(msg.conflicts))
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
		if m.loggingIn {
			return m, nil
		}
		m.loggingIn = true
		m.err = nil
		return m, m.loginCmd(m.loginInput.Value(), m.passwordInput.Value())
	}

	var cmd tea.Cmd
	if m.focus == 0 {
		m.loginInput, cmd = m.loginInput.Update(msg)
	} else {
		m.passwordInput, cmd = m.passwordInput.Update(msg)
	}
	return m, cmd
}

// loginCmd запускает openSession (сеть + Argon2id) в отдельной горутине bubbletea.
//
// openSession выполняет сетевой запрос и Argon2id — потенциально небыстрая
// операция. Вызов её синхронно внутри Update заблокировал бы отрисовку и обработку
// сообщений на время её выполнения; tea.Cmd выполняется bubbletea в отдельной
// горутине специально для таких случаев (не блокирует event loop, поэтому во время
// логина остаются отзывчивыми, например, анимации/тик-сообщения).
func (m *Model) loginCmd(login, password string) tea.Cmd {
	return func() tea.Msg {
		session, vault, syncer, err := m.openSession(m.ctx, m.cfg, login, password)
		return sessionResultMsg{session: session, vault: vault, syncer: syncer, err: err}
	}
}

// syncCmd запускает Syncer.Sync (сеть) в отдельной горутине bubbletea, чтобы не
// блокировать event loop на время синхронизации.
func (m *Model) syncCmd() tea.Cmd {
	syncer := m.syncer
	return func() tea.Msg {
		conflicts, err := syncer.Sync(m.ctx)
		return syncResultMsg{conflicts: conflicts, err: err}
	}
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
	case "s":
		if m.syncing || m.syncer == nil {
			return m, nil
		}
		m.syncing = true
		m.err = nil
		return m, m.syncCmd()
	case "enter":
		if len(m.records) == 0 {
			return m, nil
		}
		m.openDetail(m.records[m.cursor])
		m.screen = screenDetail
		return m, otpTickCmd()
	case "n":
		m.err = nil
		m.addTypeCursor = 0
		m.screen = screenAddType
		return m, nil
	}
	return m, nil
}

// updateAddType обрабатывает выбор типа новой записи (экран screenAddType).
func (m *Model) updateAddType(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "esc":
		m.screen = screenList
		return m, nil
	case "up", "k":
		if m.addTypeCursor > 0 {
			m.addTypeCursor--
		}
	case "down", "j":
		if m.addTypeCursor < len(addTypeOptions)-1 {
			m.addTypeCursor++
		}
	case "enter":
		opt := addTypeOptions[m.addTypeCursor]
		m.addDataType = opt.dataType
		m.addFields = buildAddFormFields(opt.dataType)
		m.addFocus = 0
		m.addFields[0].input.Focus()
		m.screen = screenAddForm
		return m, nil
	}
	return m, nil
}

// updateAddForm обрабатывает ввод в динамической форме добавления записи.
func (m *Model) updateAddForm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyCtrlC, tea.KeyEsc:
		m.addFields = nil
		m.screen = screenList
		return m, nil
	case tea.KeyTab, tea.KeyDown:
		m.addFields[m.addFocus].input.Blur()
		m.addFocus = (m.addFocus + 1) % len(m.addFields)
		m.addFields[m.addFocus].input.Focus()
		return m, nil
	case tea.KeyShiftTab, tea.KeyUp:
		m.addFields[m.addFocus].input.Blur()
		m.addFocus = (m.addFocus - 1 + len(m.addFields)) % len(m.addFields)
		m.addFields[m.addFocus].input.Focus()
		return m, nil
	case tea.KeyEnter:
		if m.addFocus < len(m.addFields)-1 {
			m.addFields[m.addFocus].input.Blur()
			m.addFocus++
			m.addFields[m.addFocus].input.Focus()
			return m, nil
		}
		return m.submitAddForm()
	}

	var cmd tea.Cmd
	m.addFields[m.addFocus].input, cmd = m.addFields[m.addFocus].input.Update(msg)
	return m, cmd
}

// submitAddForm собирает payload из формы, создаёт запись через VaultManager
// и возвращается к списку. Create — чисто локальная операция (шифрование +
// запись в локальное хранилище), поэтому вызывается синхронно, без tea.Cmd;
// отправка на сервер происходит отдельно, по 's' (см. syncCmd).
func (m *Model) submitAddForm() (tea.Model, tea.Cmd) {
	meta, payload, err := buildAddPayload(m.addDataType, m.addFields)
	if err != nil {
		m.err = err
		return m, nil
	}
	if _, err := m.vault.Create(m.addDataType, meta, payload); err != nil {
		m.err = err
		return m, nil
	}
	m.err = nil
	m.records = m.vault.List()
	m.addFields = nil
	m.screen = screenList
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
	case screenAddType:
		return m.viewAddType()
	case screenAddForm:
		return m.viewAddForm()
	default:
		return ""
	}
}

func (m *Model) viewLogin() string {
	s := "Voldepass — sign in\n\n"
	s += m.loginInput.View() + "\n"
	s += m.passwordInput.View() + "\n"
	if m.loggingIn {
		s += "\nlogging in...\n"
	}
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
	if m.syncing {
		s += "\nsyncing...\n"
	} else if !m.lastSyncAt.IsZero() {
		s += fmt.Sprintf("\nlast sync: %s\n", m.lastSyncAt.Format("2006-01-02 15:04:05"))
	} else {
		s += "\nnot synced yet\n"
	}
	if m.err != nil {
		s += fmt.Sprintf("\nerror: %v\n", m.err)
	}
	s += "\n(up/down to navigate, enter to view, n to add, s to sync, q to quit)"
	return s
}

func (m *Model) viewAddType() string {
	s := "Add record — choose type\n\n"
	for i, opt := range addTypeOptions {
		cursor := "  "
		if i == m.addTypeCursor {
			cursor = "> "
		}
		s += fmt.Sprintf("%s%s\n", cursor, opt.label)
	}
	s += "\n(up/down to choose, enter to continue, esc to cancel)"
	return s
}

func (m *Model) viewAddForm() string {
	s := fmt.Sprintf("Add %v record\n\n", m.addDataType)
	for i, f := range m.addFields {
		marker := "  "
		if i == m.addFocus {
			marker = "> "
		}
		s += fmt.Sprintf("%s%s: %s\n", marker, f.label, f.input.View())
	}
	if m.err != nil {
		s += fmt.Sprintf("\nerror: %v\n", m.err)
	}
	s += "\n(tab/shift+tab to switch fields, enter on last field to save, esc to cancel)"
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
