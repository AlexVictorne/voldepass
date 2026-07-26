package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	clientcfg "github.com/alexvictorne/voldepass/internal/client/config"
)

// runLogout логинится, чтобы получить dataKey, затем очищает сохранённые токены
// сессии в локальном файле (принудительный повторный challenge-response при следующем входе).
func runLogout(ctx context.Context, cfg clientcfg.Config, login, password string, out io.Writer) error {
	b, err := openSession(ctx, cfg, login, password)
	if err != nil {
		return fmt.Errorf("logout: %w", err)
	}

	b.session.ClearTokens()
	if err := b.session.CloseWithoutSync(); err != nil {
		return fmt.Errorf("logout: %w", err)
	}

	_, _ = fmt.Fprintf(out, "logged out %q\n", login)
	return nil
}

func newLogoutCmd(effectiveConfig func() clientcfg.Config, flags *rootFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Clear the local session (tokens)",
		RunE: func(cmd *cobra.Command, args []string) error {
			login, err := requireLogin(flags)
			if err != nil {
				return err
			}
			password, err := readPassword(cmd.InOrStdin(), cmd.OutOrStdout(), "Master password: ")
			if err != nil {
				return err
			}
			return runLogout(cmd.Context(), effectiveConfig(), login, password, cmd.OutOrStdout())
		},
	}
}
