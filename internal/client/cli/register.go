package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	clientcfg "github.com/alexvictorne/voldepass/internal/client/config"
	"github.com/alexvictorne/voldepass/internal/client/crypto"
)

// runRegister регистрирует нового пользователя, выводит предупреждение о слабом
// пароле (не блокирует) и сохраняет локальную сессию.
func runRegister(ctx context.Context, cfg clientcfg.Config, login, password string, out io.Writer) error {
	strength := crypto.EvaluatePasswordStrength(password)
	for _, msg := range strength.Feedback {
		_, _ = fmt.Fprintf(out, "warning: %s\n", msg)
	}

	b, err := openNewSession(ctx, cfg, login, password)
	if err != nil {
		return fmt.Errorf("register: %w", err)
	}
	if err := b.session.Close(ctx); err != nil {
		return fmt.Errorf("register: %w", err)
	}

	_, _ = fmt.Fprintf(out, "registered %q\n", login)
	return nil
}

func newRegisterCmd(effectiveConfig func() clientcfg.Config, flags *rootFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "register",
		Short: "Register a new account",
		RunE: func(cmd *cobra.Command, args []string) error {
			login, err := requireLogin(flags)
			if err != nil {
				return err
			}
			password, err := readPassword(cmd.InOrStdin(), cmd.OutOrStdout(), "Master password: ")
			if err != nil {
				return err
			}
			return runRegister(cmd.Context(), effectiveConfig(), login, password, cmd.OutOrStdout())
		},
	}
}
