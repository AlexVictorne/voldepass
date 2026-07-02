package cli

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	clientcfg "github.com/alexvictorne/voldepass/internal/client/config"
	"github.com/alexvictorne/voldepass/internal/client/crypto"
)

// runImport открывает сессию, расшифровывает бандл из inputPath (созданный этим же
// аккаунтом через export) и добавляет записи в локальное хранилище как Dirty —
// они будут отправлены на сервер при следующей синхронизации.
func runImport(ctx context.Context, cfg clientcfg.Config, login, password, inputPath string, out io.Writer) error {
	b, err := openSession(ctx, cfg, login, password)
	if err != nil {
		return fmt.Errorf("import: %w", err)
	}

	raw, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("import: read bundle: %w", err)
	}

	result, err := crypto.ImportData(raw, b.session.DataKey())
	if err != nil {
		return fmt.Errorf("import: %w", err)
	}

	b.vault.Import(result.Records)
	if err := b.session.Close(ctx); err != nil {
		return fmt.Errorf("import: %w", err)
	}

	fmt.Fprintf(out, "imported %d record(s) from %s\n", len(result.Records), inputPath)
	return nil
}

func newImportCmd(effectiveConfig func() clientcfg.Config, flags *rootFlags) *cobra.Command {
	var input string
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Import an encrypted backup file into the vault",
		RunE: func(cmd *cobra.Command, args []string) error {
			login, err := requireLogin(flags)
			if err != nil {
				return err
			}
			password, err := readPassword(cmd.InOrStdin(), cmd.OutOrStdout(), "Master password: ")
			if err != nil {
				return err
			}
			return runImport(cmd.Context(), effectiveConfig(), login, password, input, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&input, "input", "", "path to the encrypted backup file")
	_ = cmd.MarkFlagRequired("input")
	return cmd
}
