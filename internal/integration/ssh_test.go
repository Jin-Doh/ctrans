package integration

import "testing"

func TestQuoteForBash(t *testing.T) {
	if got := QuoteForBash(""); got != "''" {
		t.Fatalf("unexpected empty quote: %q", got)
	}

	if got := QuoteForBash("echo hello"); got != "'echo hello'" {
		t.Fatalf("unexpected quoted command: %q", got)
	}

	got := QuoteForBash("echo 'hi'")
	want := "'echo '\"'\"'hi'\"'\"''"
	if got != want {
		t.Fatalf("unexpected single-quote escaping: got=%q want=%q", got, want)
	}
}
