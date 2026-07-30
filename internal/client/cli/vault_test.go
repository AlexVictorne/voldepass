package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/alexvictorne/voldepass/internal/domain"
)

func TestParseDataType(t *testing.T) {
	cases := map[string]domain.DataType{
		"cred": domain.DataTypeCredentials, "credentials": domain.DataTypeCredentials,
		"text": domain.DataTypeText, "card": domain.DataTypeCard,
		"otp": domain.DataTypeOTP, "binary": domain.DataTypeBinary,
	}
	for in, want := range cases {
		got, err := parseDataType(in)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	}

	_, err := parseDataType("bogus")
	assert.Error(t, err)
}

func TestNewPayloadTarget(t *testing.T) {
	assert.IsType(t, &domain.CredentialsPayload{}, newPayloadTarget(domain.DataTypeCredentials))
	assert.IsType(t, &domain.TextPayload{}, newPayloadTarget(domain.DataTypeText))
	assert.IsType(t, &domain.CardPayload{}, newPayloadTarget(domain.DataTypeCard))
	assert.IsType(t, &domain.OTPPayload{}, newPayloadTarget(domain.DataTypeOTP))
	assert.IsType(t, &domain.BinaryPayload{}, newPayloadTarget(domain.DataTypeBinary))
	assert.IsType(t, &map[string]any{}, newPayloadTarget(domain.DataTypeUnknown))
}

func TestBuildPayload(t *testing.T) {
	f := payloadFlags{
		login: "u", password: "p", content: "c",
		number: "n", holder: "h", expiry: "e", cvv: "v",
		secret: "s", issuer: "i", account: "a", algorithm: "SHA1", digits: 6, period: 30,
		filename: "f.bin",
	}

	cred, err := buildPayload(domain.DataTypeCredentials, f)
	require.NoError(t, err)
	assert.Equal(t, domain.CredentialsPayload{Login: "u", Password: "p"}, cred)

	text, err := buildPayload(domain.DataTypeText, f)
	require.NoError(t, err)
	assert.Equal(t, domain.TextPayload{Content: "c"}, text)

	binary, err := buildPayload(domain.DataTypeBinary, f)
	require.NoError(t, err)
	assert.Equal(t, domain.BinaryPayload{Data: []byte("c"), Filename: "f.bin"}, binary)

	card, err := buildPayload(domain.DataTypeCard, f)
	require.NoError(t, err)
	assert.Equal(t, domain.CardPayload{Number: "n", Holder: "h", Expiry: "e", CVV: "v"}, card)

	otp, err := buildPayload(domain.DataTypeOTP, f)
	require.NoError(t, err)
	assert.Equal(t, domain.OTPPayload{Secret: "s", Issuer: "i", Account: "a", Algorithm: "SHA1", Digits: 6, Period: 30}, otp)

	_, err = buildPayload(domain.DataTypeUnknown, f)
	assert.Error(t, err, "unknown type has no CLI payload builder")
}

func TestRunAddGetListDelete_Credentials(t *testing.T) {
	srv := newLiveServer(t)
	defer srv.Close()
	cfg := testConfig(srv, filepath.Join(t.TempDir(), "storage.vp"))
	ctx := context.Background()
	require.NoError(t, runRegister(ctx, cfg, "alice", "master-password", &bytes.Buffer{}))

	var addOut bytes.Buffer
	f := payloadFlags{meta: "github", login: "octocat", password: "s3cr3t"}
	require.NoError(t, runAdd(ctx, cfg, "alice", "master-password", domain.DataTypeCredentials, f, &addOut))
	assert.Contains(t, addOut.String(), "created record")

	var listOut bytes.Buffer
	require.NoError(t, runList(ctx, cfg, "alice", "master-password", &listOut))
	assert.Contains(t, listOut.String(), "github")

	// Извлекаем ID из вывода add: "created record <id>\n"
	id := extractRecordID(t, addOut.String())

	var getOut bytes.Buffer
	require.NoError(t, runGet(ctx, cfg, "alice", "master-password", id, &getOut))
	assert.Contains(t, getOut.String(), "octocat")
	assert.Contains(t, getOut.String(), "s3cr3t")

	var delOut bytes.Buffer
	require.NoError(t, runDelete(ctx, cfg, "alice", "master-password", id, &delOut))
	assert.Contains(t, delOut.String(), "deleted record")

	var listOut2 bytes.Buffer
	require.NoError(t, runList(ctx, cfg, "alice", "master-password", &listOut2))
	assert.NotContains(t, listOut2.String(), id, "deleted record must not appear in list")
}

func TestRunList_SyncsBeforePrinting(t *testing.T) {
	srv := newLiveServer(t)
	defer srv.Close()
	ctx := context.Background()

	cfgA := testConfig(srv, filepath.Join(t.TempDir(), "device-a.vp"))
	require.NoError(t, runRegister(ctx, cfgA, "alice", "master-password", &bytes.Buffer{}))

	// "Другое устройство": свой локальный файл, тот же аккаунт.
	cfgB := testConfig(srv, filepath.Join(t.TempDir(), "device-b.vp"))
	var addOut bytes.Buffer
	f := payloadFlags{content: "from device B"}
	require.NoError(t, runAdd(ctx, cfgB, "alice", "master-password", domain.DataTypeText, f, &addOut))

	// list на первом устройстве не видел это изменение локально — должен подтянуть его через sync.
	var listOut bytes.Buffer
	require.NoError(t, runList(ctx, cfgA, "alice", "master-password", &listOut))
	id := extractRecordID(t, addOut.String())
	assert.Contains(t, listOut.String(), id, "list must sync remote changes before printing")
}

func TestRunEdit_UpdatesPayload(t *testing.T) {
	srv := newLiveServer(t)
	defer srv.Close()
	cfg := testConfig(srv, filepath.Join(t.TempDir(), "storage.vp"))
	ctx := context.Background()
	require.NoError(t, runRegister(ctx, cfg, "alice", "master-password", &bytes.Buffer{}))

	var addOut bytes.Buffer
	require.NoError(t, runAdd(ctx, cfg, "alice", "master-password", domain.DataTypeText,
		payloadFlags{content: "v1"}, &addOut))
	id := extractRecordID(t, addOut.String())

	require.NoError(t, runEdit(ctx, cfg, "alice", "master-password", id, domain.DataTypeText,
		payloadFlags{content: "v2"}, &bytes.Buffer{}))

	var getOut bytes.Buffer
	require.NoError(t, runGet(ctx, cfg, "alice", "master-password", id, &getOut))
	assert.Contains(t, getOut.String(), "v2")
}

func TestRunAdd_InvalidType(t *testing.T) {
	srv := newLiveServer(t)
	defer srv.Close()
	cfg := testConfig(srv, filepath.Join(t.TempDir(), "storage.vp"))
	ctx := context.Background()
	require.NoError(t, runRegister(ctx, cfg, "alice", "master-password", &bytes.Buffer{}))

	err := runAdd(ctx, cfg, "alice", "master-password", domain.DataTypeUnknown, payloadFlags{}, &bytes.Buffer{})
	assert.Error(t, err)
}

// extractRecordID парсит "created record <id>\n" из вывода runAdd.
func extractRecordID(t *testing.T, output string) string {
	t.Helper()
	const prefix = "created record "
	idx := bytes.Index([]byte(output), []byte(prefix))
	require.GreaterOrEqual(t, idx, 0, "output must contain %q: %s", prefix, output)
	rest := output[idx+len(prefix):]
	end := bytes.IndexByte([]byte(rest), '\n')
	require.GreaterOrEqual(t, end, 0)
	return rest[:end]
}
