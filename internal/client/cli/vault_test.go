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
