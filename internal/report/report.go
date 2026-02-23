package report

import "fmt"

// Severity indicates how critical a finding is.
type Severity string

const (
	SeverityWarn  Severity = "warn"
	SeverityError Severity = "error"
)

// Finding is a structured warning/error reported by scan/verify/render.
type Finding struct {
	ID             string   `json:"id"`
	Severity       Severity `json:"severity"`
	Service        string   `json:"service,omitempty"`
	Field          string   `json:"field,omitempty"`
	Message        string   `json:"message"`
	MaskedValue    string   `json:"masked_value,omitempty"`
	Recommendation string   `json:"recommendation,omitempty"`
}

func (f Finding) String() string {
	prefix := "경고"
	if f.Severity == SeverityError {
		prefix = "오류"
	}
	loc := ""
	if f.Service != "" || f.Field != "" {
		loc = fmt.Sprintf(" [%s:%s]", f.Service, f.Field)
	}
	masked := ""
	if f.MaskedValue != "" {
		masked = fmt.Sprintf(" (masked=%s)", f.MaskedValue)
	}
	rec := ""
	if f.Recommendation != "" {
		rec = fmt.Sprintf(" recommendation=%s", f.Recommendation)
	}
	return fmt.Sprintf("%s%s %s%s%s", prefix, loc, f.Message, masked, rec)
}

// Summary is a count of findings by severity.
type Summary struct {
	Warn  int `json:"warn"`
	Error int `json:"error"`
}

func BuildSummary(findings []Finding) Summary {
	var s Summary
	for _, f := range findings {
		switch f.Severity {
		case SeverityError:
			s.Error++
		default:
			s.Warn++
		}
	}
	return s
}

// Fail reports whether execution should fail with the given threshold.
func Fail(findings []Finding, threshold string) bool {
	s := BuildSummary(findings)
	switch threshold {
	case "none":
		return false
	case "warn":
		return s.Warn > 0 || s.Error > 0
	default:
		return s.Error > 0
	}
}
