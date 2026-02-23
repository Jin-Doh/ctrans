package secrules

import (
	"regexp"
	"testing"
)

func TestCompilePattern(t *testing.T) {
	fallback := regexp.MustCompile(`(?i)secret`)

	pat := CompilePattern([]string{`[`}, fallback)
	if !pat.MatchString("MY_SECRET") {
		t.Fatalf("invalid custom pattern should fallback")
	}

	pat = CompilePattern([]string{`(?i)token`}, fallback)
	if !pat.MatchString("AUTH_TOKEN") {
		t.Fatalf("valid custom pattern should compile")
	}
}
