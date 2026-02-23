package security

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"compose_to_run/internal/compose"
	"compose_to_run/internal/report"
)

var (
	sensitiveKeyPattern  = regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key)`)
	privatePathPattern   = regexp.MustCompile(`(?i)(^|/)(id_rsa|id_ed25519|.*\.pem|.*\.key)$`)
	privateBlockPattern  = regexp.MustCompile(`(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----`)
	highEntropyLikeValue = regexp.MustCompile(`^[A-Za-z0-9_\-\+/=]{40,}$`)
)

// Config controls scan behavior.
type Config struct {
	Mask bool
}

// Report is the output of the scanner.
type Report struct {
	Files    []string         `json:"files"`
	Findings []report.Finding `json:"findings"`
	Summary  report.Summary   `json:"summary"`
}

func Scan(project *compose.Project, preFindings []report.Finding, cfg Config) Report {
	findings := append([]report.Finding{}, preFindings...)
	for _, svcName := range project.ServiceNames() {
		svc := project.Services[svcName]
		findings = append(findings, scanService(svc, cfg)...)
	}
	return Report{
		Files:    append([]string(nil), project.Files...),
		Findings: findings,
		Summary:  report.BuildSummary(findings),
	}
}

func scanService(svc *compose.Service, cfg Config) []report.Finding {
	findings := []report.Finding{}
	keys := make([]string, 0, len(svc.Environment))
	for key := range svc.Environment {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		env := svc.Environment[key]
		if !sensitiveKeyPattern.MatchString(key) {
			continue
		}
		if !env.HasValue {
			continue
		}
		if looksEnvRef(env.Value) {
			continue
		}
		severity := report.SeverityWarn
		if privateBlockPattern.MatchString(env.Value) || highEntropyLikeValue.MatchString(env.Value) {
			severity = report.SeverityError
		}
		masked := ""
		if cfg.Mask {
			masked = MaskValue(env.Value)
		}
		findings = append(findings, report.Finding{
			ID:             "sensitive-env",
			Severity:       severity,
			Service:        svc.Name,
			Field:          fmt.Sprintf("environment.%s", key),
			Message:        "민감 환경변수 키에 인라인 비밀값이 포함된 것으로 보입니다",
			MaskedValue:    masked,
			Recommendation: "인라인 값 대신 런타임 주입(-e KEY 또는 원격 시크릿 주입)을 사용하세요",
		})
	}

	for _, vol := range svc.Volumes {
		host := hostPath(vol)
		if host == "" {
			continue
		}
		base := filepath.Base(host)
		if privatePathPattern.MatchString(strings.ToLower(base)) || strings.Contains(strings.ToLower(host), "/.ssh/") {
			findings = append(findings, report.Finding{
				ID:             "sensitive-volume-path",
				Severity:       report.SeverityError,
				Service:        svc.Name,
				Field:          "volumes",
				Message:        "볼륨 호스트 경로가 개인키 파일로 보입니다",
				MaskedValue:    MaskPath(host, cfg.Mask),
				Recommendation: "관리형 시크릿 저장소 또는 전용 런타임 시크릿 파일로 마운트하세요",
			})
		}
	}

	for _, envFile := range svc.EnvFiles {
		lower := strings.ToLower(envFile)
		if strings.Contains(lower, "secret") || strings.Contains(lower, "private") {
			findings = append(findings, report.Finding{
				ID:             "sensitive-env-file-name",
				Severity:       report.SeverityWarn,
				Service:        svc.Name,
				Field:          "env_file",
				Message:        "env_file 경로 이름에 비밀값 노출 위험 신호가 있습니다",
				MaskedValue:    MaskPath(envFile, cfg.Mask),
				Recommendation: "env_file 이 VCS에 포함되지 않도록 하고 안전한 채널로 배포하세요",
			})
		}
	}

	return findings
}

func hostPath(volume string) string {
	parts := strings.Split(volume, ":")
	if len(parts) < 2 {
		return ""
	}
	return strings.TrimSpace(parts[0])
}

func looksEnvRef(v string) bool {
	trimmed := strings.TrimSpace(v)
	return strings.HasPrefix(trimmed, "${") || strings.Contains(trimmed, "$${")
}

// MaskValue returns a short masked representation of sensitive values.
func MaskValue(v string) string {
	if v == "" {
		return ""
	}
	if len(v) <= 4 {
		return "****"
	}
	if len(v) <= 8 {
		return v[:1] + "****" + v[len(v)-1:]
	}
	return v[:2] + "****" + v[len(v)-2:]
}

// MaskPath hides most of a path while keeping troubleshooting signal.
func MaskPath(path string, enable bool) string {
	if !enable {
		return path
	}
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return ""
	}
	base := filepath.Base(trimmed)
	if base == "." || base == string(filepath.Separator) {
		return "***"
	}
	if len(base) <= 4 {
		return "***/" + base
	}
	return "***/" + base[:2] + "****" + base[len(base)-2:]
}

// PromoteWarningsToErrors upgrades warn findings to error severity.
func PromoteWarningsToErrors(findings []report.Finding) []report.Finding {
	out := make([]report.Finding, 0, len(findings))
	for _, f := range findings {
		if f.Severity == report.SeverityWarn {
			f.Severity = report.SeverityError
		}
		out = append(out, f)
	}
	return out
}
