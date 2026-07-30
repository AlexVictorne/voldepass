package cli

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRootCmd_Version(t *testing.T) {
	root, err := NewRootCmd("1.2.3", "2024-01-01")
	require.NoError(t, err)
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"version"})

	require.NoError(t, root.Execute())
	assert.Contains(t, out.String(), "version=1.2.3")
	assert.Contains(t, out.String(), "buildDate=2024-01-01")
}

// TestRootCmd_InvalidConfigEnv_FailsEarly проверяет, что некорректное значение
// в переменной окружения (например, нечисловое MAX_RETRIES) приводит к ошибке
// из NewRootCmd, а не к молчаливому откату на дефолты — оператор мог задать
// это значение намеренно, и незаметный откат усложнил бы отладку.
func TestRootCmd_InvalidConfigEnv_FailsEarly(t *testing.T) {
	t.Setenv("VOLDEPASS_CLIENT_MAX_RETRIES", "not-a-number")

	_, err := NewRootCmd("1.2.3", "2024-01-01")
	require.Error(t, err)
}

func TestRequireLogin_Missing(t *testing.T) {
	flags := &rootFlags{}
	_, err := requireLogin(flags)
	assert.Error(t, err)
}

func TestRequireLogin_Present(t *testing.T) {
	flags := &rootFlags{login: "alice"}
	login, err := requireLogin(flags)
	require.NoError(t, err)
	assert.Equal(t, "alice", login)
}
