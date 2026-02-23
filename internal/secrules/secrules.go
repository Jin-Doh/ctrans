package secrules

import (
	"regexp"
	"strings"
)

const (
	DefaultSensitiveKeyPatternExpr  = `(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key)`
	DefaultSensitivePathPatternExpr = `(?i)(^|/)(id_rsa|id_ed25519|.*\\.pem|.*\\.key)$`
)

// CompilePattern compiles user-provided regex patterns with fallback.
func CompilePattern(patterns []string, fallback *regexp.Regexp) *regexp.Regexp {
	valid := make([]string, 0, len(patterns))
	for _, p := range patterns {
		trimmed := strings.TrimSpace(p)
		if trimmed == "" {
			continue
		}
		if _, err := regexp.Compile(trimmed); err != nil {
			continue
		}
		valid = append(valid, "("+trimmed+")")
	}
	if len(valid) == 0 {
		return fallback
	}
	compiled, err := regexp.Compile(strings.Join(valid, "|"))
	if err != nil {
		return fallback
	}
	return compiled
}
