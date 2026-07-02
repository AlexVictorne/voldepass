package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// newVersionCmd создаёт команду "version", печатающую version/buildDate из ldflags.
func newVersionCmd(version, buildDate string) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print client version and build date",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintf(cmd.OutOrStdout(), "voldepass-client version=%s buildDate=%s\n", version, buildDate)
			return nil
		},
	}
}
