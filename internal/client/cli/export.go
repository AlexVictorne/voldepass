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

// runExport открывает сессию и пишет зашифрованный бандл всех локальных записей
// в outputPath — для офлайн-бэкапа или переноса без сервера.
func runExport(ctx context.Context, cfg clientcfg.Config, login, password, outputPath string, out io.Writer) error {
	b, err := openSession(ctx, cfg, login, password)
	if err != nil {
		return fmt.Errorf("export: %w", err)
	}

	kdfSalt, kdfParams, wrappedDataKey := b.session.Profile()
	records := b.vault.List()

	bundle, err := crypto.ExportData(b.session.DataKey(), records, kdfSalt, kdfParams, wrappedDataKey)
	if err != nil {
		return fmt.Errorf("export: %w", err)
	}

	if err := os.WriteFile(outputPath, bundle, 0o600); err != nil {
		return fmt.Errorf("export: write bundle: %w", err)
	}
	if err := b.session.Close(ctx); err != nil {
		return fmt.Errorf("export: %w", err)
	}

	fmt.Fprintf(out, "exported %d record(s) to %s\n", len(records), outputPath)
	return nil
}

func newExportCmd(effectiveConfig func() clientcfg.Config, flags *rootFlags) *cobra.Command {
	var output string
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export the vault to an encrypted backup file",
		RunE: func(cmd *cobra.Command, args []string) error {
			login, err := requireLogin(flags)
			if err != nil {
				return err
			}
			password, err := readPassword(cmd.InOrStdin(), cmd.OutOrStdout(), "Master password: ")
			if err != nil {
				return err
			}
			return runExport(cmd.Context(), effectiveConfig(), login, password, output, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&output, "output", "backup.vpenc", "output file path")
	return cmd
}
