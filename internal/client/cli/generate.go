package cli

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/alexvictorne/voldepass/internal/client/crypto"
)

// runGenerate генерирует пароль по заданным опциям и печатает его.
func runGenerate(opts crypto.GenerateOptions, out io.Writer) error {
	pw, err := crypto.GeneratePassword(opts)
	if err != nil {
		return fmt.Errorf("generate: %w", err)
	}
	_, _ = fmt.Fprintln(out, pw)
	return nil
}

func newGenerateCmd() *cobra.Command {
	var opts crypto.GenerateOptions
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate a strong random password",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGenerate(opts, cmd.OutOrStdout())
		},
	}
	cmd.Flags().IntVar(&opts.Length, "length", 20, "password length")
	cmd.Flags().BoolVar(&opts.NoSymbols, "no-symbols", false, "exclude special characters")
	cmd.Flags().BoolVar(&opts.NoDigits, "no-digits", false, "exclude digits")
	cmd.Flags().BoolVar(&opts.NoUpper, "no-upper", false, "exclude uppercase letters")
	return cmd
}
