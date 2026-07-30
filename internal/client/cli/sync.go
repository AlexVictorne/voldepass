package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	clientcfg "github.com/alexvictorne/voldepass/internal/client/config"
)

// runSync открывает сессию (что уже выполняет Login) и запускает дополнительный
// явный цикл синхронизации перед закрытием — полезно как самостоятельная команда
// для принудительной синхронизации без изменения записей.
func runSync(ctx context.Context, cfg clientcfg.Config, login, password string, out io.Writer) error {
	b, err := openSession(ctx, cfg, login, password)
	if err != nil {
		return fmt.Errorf("sync: %w", err)
	}

	conflicts, err := b.syncer.Sync(ctx)
	if err != nil {
		return fmt.Errorf("sync: %w", err)
	}
	if err := b.session.Close(ctx); err != nil {
		return fmt.Errorf("sync: %w", err)
	}

	if len(conflicts) > 0 {
		_, _ = fmt.Fprintf(out, "sync completed with %d unresolved conflict(s):\n", len(conflicts))
		for _, c := range conflicts {
			_, _ = fmt.Fprintf(out, "  - %s\n", c.ID)
		}
		return nil
	}

	_, _ = fmt.Fprintln(out, "sync completed")
	return nil
}

func newSyncCmd(effectiveConfig func() clientcfg.Config, flags *rootFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "sync",
		Short: "Synchronize local vault with the server",
		RunE: func(cmd *cobra.Command, args []string) error {
			login, err := requireLogin(flags)
			if err != nil {
				return err
			}
			password, err := readPassword(cmd.InOrStdin(), cmd.OutOrStdout(), "Master password: ")
			if err != nil {
				return err
			}
			return runSync(cmd.Context(), effectiveConfig(), login, password, cmd.OutOrStdout())
		},
	}
}
