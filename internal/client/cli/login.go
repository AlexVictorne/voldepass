package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	clientcfg "github.com/alexvictorne/voldepass/internal/client/config"
)

// runLogin проверяет учётные данные и обновляет локальный кэш сессии.
// Отдельная команда login полезна для валидации пароля и прогрева локального
// кэша без выполнения какой-либо другой операции.
func runLogin(ctx context.Context, cfg clientcfg.Config, login, password string, out io.Writer) error {
	b, err := openSession(ctx, cfg, login, password)
	if err != nil {
		return fmt.Errorf("login: %w", err)
	}
	if err := b.session.Close(ctx); err != nil {
		return fmt.Errorf("login: %w", err)
	}

	_, _ = fmt.Fprintf(out, "logged in as %q\n", login)
	return nil
}

func newLoginCmd(effectiveConfig func() clientcfg.Config, flags *rootFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Log in to an existing account",
		RunE: func(cmd *cobra.Command, args []string) error {
			login, err := requireLogin(flags)
			if err != nil {
				return err
			}
			password, err := readPassword(cmd.InOrStdin(), cmd.OutOrStdout(), "Master password: ")
			if err != nil {
				return err
			}
			return runLogin(cmd.Context(), effectiveConfig(), login, password, cmd.OutOrStdout())
		},
	}
}
