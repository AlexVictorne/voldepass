package cli

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	clientcfg "github.com/alexvictorne/voldepass/internal/client/config"
)

// runOTPGet открывает сессию и печатает текущий TOTP-код для записи id.
func runOTPGet(ctx context.Context, cfg clientcfg.Config, login, password, id string, out io.Writer) error {
	b, err := openSession(ctx, cfg, login, password)
	if err != nil {
		return fmt.Errorf("otp: %w", err)
	}

	code, err := b.vault.CurrentTOTP(id, time.Now())
	if err != nil {
		return fmt.Errorf("otp: %w", err)
	}
	if err := b.session.Close(ctx); err != nil {
		return fmt.Errorf("otp: %w", err)
	}

	fmt.Fprintln(out, code)
	return nil
}

func newOTPCmd(effectiveConfig func() clientcfg.Config, flags *rootFlags) *cobra.Command {
	otpCmd := &cobra.Command{
		Use:   "otp",
		Short: "One-time password operations",
	}

	var id string
	getCmd := &cobra.Command{
		Use:   "get",
		Short: "Print the current TOTP code for a record",
		RunE: func(cmd *cobra.Command, args []string) error {
			login, err := requireLogin(flags)
			if err != nil {
				return err
			}
			password, err := readPassword(cmd.InOrStdin(), cmd.OutOrStdout(), "Master password: ")
			if err != nil {
				return err
			}
			return runOTPGet(cmd.Context(), effectiveConfig(), login, password, id, cmd.OutOrStdout())
		},
	}
	getCmd.Flags().StringVar(&id, "id", "", "OTP record ID")
	_ = getCmd.MarkFlagRequired("id")

	otpCmd.AddCommand(getCmd)
	return otpCmd
}
