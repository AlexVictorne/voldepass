package cli

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"golang.org/x/term"
)

// readPassword читает пароль с терминала без эха, если in — это терминал (os.Stdin).
// Иначе (например, в тестах или при пайпе) читает одну строку из in как есть.
func readPassword(in io.Reader, out io.Writer, prompt string) (string, error) {
	fmt.Fprint(out, prompt)

	if f, ok := in.(interface{ Fd() uintptr }); ok && term.IsTerminal(int(f.Fd())) {
		raw, err := term.ReadPassword(int(f.Fd()))
		fmt.Fprintln(out)
		if err != nil {
			return "", fmt.Errorf("read password: %w", err)
		}
		return string(raw), nil
	}

	reader := bufio.NewReader(in)
	line, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("read password: %w", err)
	}
	return strings.TrimRight(line, "\r\n"), nil
}
