package cli

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	clientcfg "github.com/alexvictorne/voldepass/internal/client/config"
	"github.com/alexvictorne/voldepass/internal/client/tui"
)

// newTUICmd запускает интерактивный терминальный интерфейс.
func newTUICmd(effectiveConfig func() clientcfg.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "tui",
		Short: "Launch the interactive terminal UI",
		RunE: func(cmd *cobra.Command, args []string) error {
			p := tea.NewProgram(tui.NewModel(effectiveConfig()))
			_, err := p.Run()
			return err
		},
	}
}
