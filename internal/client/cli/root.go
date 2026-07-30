package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	clientcfg "github.com/alexvictorne/voldepass/internal/client/config"
)

// rootFlags хранит значения persistent-флагов, переопределяющих конфигурацию клиента.
type rootFlags struct {
	login       string
	serverURL   string
	storageFile string
}

// NewRootCmd собирает корневую cobra-команду CLI со всеми подкомандами.
// version/buildDate передаются из ldflags cmd/client/main.go.
//
// Ошибка загрузки конфигурации (например, переменная окружения задана в
// некорректном формате) возвращается вызывающему коду, а не проглатывается
// молча с откатом на дефолты — оператор мог намеренно задать эти значения,
// и незаметный откат к дефолтам усложнил бы отладку и мог бы привести к
// работе с неверными параметрами незамеченным ("fail early").
func NewRootCmd(version, buildDate string) (*cobra.Command, error) {
	cfg, err := clientcfg.Load(nil) // только defaults → JSON-файл → env; флаги парсит cobra
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}

	flags := &rootFlags{login: os.Getenv("VOLDEPASS_LOGIN")}

	root := &cobra.Command{
		Use:           "voldepass-client",
		Short:         "Voldepass — zero-knowledge password manager client",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.PersistentFlags().StringVar(&flags.login, "login", flags.login, "account login (or set VOLDEPASS_LOGIN)")
	root.PersistentFlags().StringVar(&flags.serverURL, "server-url", cfg.ServerURL, "Voldepass server base URL")
	root.PersistentFlags().StringVar(&flags.storageFile, "storage-file", cfg.StorageFile, "path to local encrypted storage file")

	// effectiveConfig применяет значения persistent-флагов поверх загруженного cfg.
	effectiveConfig := func() clientcfg.Config {
		c := cfg
		c.ServerURL = flags.serverURL
		c.StorageFile = flags.storageFile
		return c
	}

	root.AddCommand(newVersionCmd(version, buildDate))
	root.AddCommand(newRegisterCmd(effectiveConfig, flags))
	root.AddCommand(newLoginCmd(effectiveConfig, flags))
	root.AddCommand(newLogoutCmd(effectiveConfig, flags))
	root.AddCommand(newVaultCommands(effectiveConfig, flags)...)
	root.AddCommand(newSyncCmd(effectiveConfig, flags))
	root.AddCommand(newOTPCmd(effectiveConfig, flags))
	root.AddCommand(newExportCmd(effectiveConfig, flags))
	root.AddCommand(newImportCmd(effectiveConfig, flags))
	root.AddCommand(newGenerateCmd())
	root.AddCommand(newTUICmd(effectiveConfig))

	return root, nil
}

// requireLogin возвращает login из флага/окружения или ошибку, если он не задан.
func requireLogin(flags *rootFlags) (string, error) {
	if flags.login == "" {
		return "", fmt.Errorf("--login is required (or set VOLDEPASS_LOGIN)")
	}
	return flags.login, nil
}
