package integration

import "strings"

// QuoteForBash safely wraps a command string for bash -lc on remote hosts.
func QuoteForBash(command string) string {
	if command == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(command, "'", "'\"'\"'") + "'"
}
