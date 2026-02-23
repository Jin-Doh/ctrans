package report

import (
	"strings"
	"testing"
)

func TestFindingStringVariants(t *testing.T) {
	f := Finding{
		ID:             "id",
		Severity:       SeverityError,
		Service:        "app",
		Field:          "env.DB_PASSWORD",
		Message:        "secret found",
		MaskedValue:    "ab****yz",
		Recommendation: "inject at runtime",
	}
	got := f.String()
	if got == "" {
		t.Fatalf("expected non-empty string")
	}
	if !strings.HasPrefix(got, "오류") {
		t.Fatalf("expected 오류 prefix, got %q", got)
	}

	w := Finding{Severity: SeverityWarn, Message: "warn"}
	if s := w.String(); !strings.HasPrefix(s, "경고") {
		t.Fatalf("expected 경고 prefix, got %q", s)
	}
}

func TestBuildSummaryAndFail(t *testing.T) {
	findings := []Finding{
		{Severity: SeverityWarn},
		{Severity: SeverityError},
	}
	s := BuildSummary(findings)
	if s.Warn != 1 || s.Error != 1 {
		t.Fatalf("unexpected summary: %+v", s)
	}

	if Fail(findings, "none") {
		t.Fatalf("none threshold should not fail")
	}
	if !Fail(findings, "warn") {
		t.Fatalf("warn threshold should fail")
	}
	if !Fail(findings, "error") {
		t.Fatalf("error threshold should fail")
	}
	if !Fail(findings, "unexpected") {
		t.Fatalf("default threshold should behave like error")
	}

	onlyWarn := []Finding{{Severity: SeverityWarn}}
	if Fail(onlyWarn, "error") {
		t.Fatalf("warn-only should not fail for error threshold")
	}
}
