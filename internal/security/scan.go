package security

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"compose_to_run/internal/compose"
	"compose_to_run/internal/report"
)

var (
	defaultSensitiveKeyPatternExpr  = `(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key)`
	defaultSensitivePathPatternExpr = `(?i)(^|/)(id_rsa|id_ed25519|.*\.pem|.*\.key)$`

	defaultSensitiveKeyPattern = regexp.MustCompile(defaultSensitiveKeyPatternExpr)
	defaultSensitivePathRegex  = regexp.MustCompile(defaultSensitivePathPatternExpr)

	privateBlockPattern  = regexp.MustCompile(`(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----`)
	highEntropyLikeValue = regexp.MustCompile(`^[A-Za-z0-9_\-\+/=]{40,}$`)
	credentialURLPattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+:[^/\s@]+@`)
)

// Config controls scan behavior.
type Config struct {
	Mask                  bool
	SensitiveKeyPatterns  []string
	SensitivePathPatterns []string
	ScanEnvFiles          bool
	ExtraEnvFiles         []string
	BaseDir               string
}

// Report is the output of the scanner.
type Report struct {
	Files    []string         `json:"files"`
	Findings []report.Finding `json:"findings"`
	Summary  report.Summary   `json:"summary"`
}

func Scan(project *compose.Project, preFindings []report.Finding, cfg Config) Report {
	findings := append([]report.Finding{}, preFindings...)
	keyPattern := compilePattern(cfg.SensitiveKeyPatterns, defaultSensitiveKeyPattern)
	pathPattern := compilePattern(cfg.SensitivePathPatterns, defaultSensitivePathRegex)
	scannedEnvFiles := map[string]struct{}{}

	for _, svcName := range project.ServiceNames() {
		svc := project.Services[svcName]
		findings = append(findings, scanService(svc, cfg, keyPattern, pathPattern, scannedEnvFiles)...)
	}
	if cfg.ScanEnvFiles {
		findings = append(findings, scanGlobalExtraEnvFiles(cfg, keyPattern, scannedEnvFiles)...)
	}

	return Report{
		Files:    append([]string(nil), project.Files...),
		Findings: findings,
		Summary:  report.BuildSummary(findings),
	}
}

func scanService(
	svc *compose.Service,
	cfg Config,
	keyPattern *regexp.Regexp,
	pathPattern *regexp.Regexp,
	scannedEnvFiles map[string]struct{},
) []report.Finding {
	findings := []report.Finding{}
	keys := make([]string, 0, len(svc.Environment))
	for key := range svc.Environment {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		env := svc.Environment[key]
		if !env.HasValue {
			continue
		}
		if looksEnvRef(env.Value) {
			continue
		}

		isSensitiveKey := keyPattern.MatchString(key)
		isSensitiveValue, valueSeverity := ClassifySecretValue(env.Value)
		if !isSensitiveKey && !isSensitiveValue {
			continue
		}

		severity := report.SeverityWarn
		if valueSeverity == report.SeverityError {
			severity = report.SeverityError
		}

		message := "민감 환경변수 키에 인라인 비밀값이 포함된 것으로 보입니다"
		if !isSensitiveKey {
			message = "일반 환경변수 키지만 값이 민감정보로 보입니다"
		}

		masked := ""
		if cfg.Mask {
			masked = MaskValue(env.Value)
		}

		findingID := "sensitive-env"
		if !isSensitiveKey {
			findingID = "sensitive-env-by-value"
		}

		findings = append(findings, report.Finding{
			ID:             findingID,
			Severity:       severity,
			Service:        svc.Name,
			Field:          fmt.Sprintf("environment.%s", key),
			Message:        message,
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
		if pathPattern.MatchString(strings.ToLower(base)) || strings.Contains(strings.ToLower(host), "/.ssh/") {
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
		if cfg.ScanEnvFiles {
			findings = append(findings, scanEnvFileEntries(envFile, svc.Name, cfg, keyPattern, scannedEnvFiles)...)
		}
	}

	return findings
}

func scanGlobalExtraEnvFiles(cfg Config, keyPattern *regexp.Regexp, scannedEnvFiles map[string]struct{}) []report.Finding {
	if len(cfg.ExtraEnvFiles) == 0 {
		return nil
	}
	findings := make([]report.Finding, 0)
	for _, envFile := range uniqueStrings(cfg.ExtraEnvFiles) {
		findings = append(findings, scanEnvFileEntries(envFile, "global", cfg, keyPattern, scannedEnvFiles)...)
	}
	return findings
}

func scanEnvFileEntries(
	rawPath string,
	serviceName string,
	cfg Config,
	keyPattern *regexp.Regexp,
	scannedEnvFiles map[string]struct{},
) []report.Finding {
	resolved := resolveEnvFilePath(rawPath, cfg.BaseDir)
	if _, already := scannedEnvFiles[resolved]; already {
		return nil
	}
	scannedEnvFiles[resolved] = struct{}{}

	payload, err := os.ReadFile(resolved)
	if err != nil {
		return []report.Finding{{
			ID:             "env-file-read-failed",
			Severity:       report.SeverityWarn,
			Service:        serviceName,
			Field:          fmt.Sprintf("env_file.%s", filepath.Base(rawPath)),
			Message:        "env_file 내용을 읽지 못해 민감값 검사를 건너뜁니다",
			Recommendation: "env_file 경로를 확인하고 실행 호스트에서 접근 가능한지 점검하세요",
		}}
	}

	lines := strings.Split(string(payload), "\n")
	findings := make([]report.Finding, 0)
	for idx, line := range lines {
		key, value, hasValue, ok := parseEnvLine(line)
		if !ok || !hasValue {
			continue
		}
		if looksEnvRef(value) {
			continue
		}

		isSensitiveKey := keyPattern.MatchString(key)
		isSensitiveValue, valueSeverity := ClassifySecretValue(value)
		if !isSensitiveKey && !isSensitiveValue {
			continue
		}

		severity := report.SeverityWarn
		if valueSeverity == report.SeverityError {
			severity = report.SeverityError
		}

		message := "env_file 내 민감 키의 인라인 값이 감지되었습니다"
		if !isSensitiveKey {
			message = "env_file 내 값이 민감정보로 추정됩니다"
		}

		masked := ""
		if cfg.Mask {
			masked = MaskValue(value)
		}

		findings = append(findings, report.Finding{
			ID:             "sensitive-env-file-entry",
			Severity:       severity,
			Service:        serviceName,
			Field:          fmt.Sprintf("env_file.%s:%d.%s", filepath.Base(rawPath), idx+1, key),
			Message:        message,
			MaskedValue:    masked,
			Recommendation: "env_file에 비밀값을 직접 저장하지 말고 실행 시점 시크릿 주입을 사용하세요",
		})
	}
	return findings
}

func parseEnvLine(line string) (key string, value string, hasValue bool, ok bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return "", "", false, false
	}
	if strings.HasPrefix(trimmed, "export ") {
		trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "export "))
	}
	k, v, found := strings.Cut(trimmed, "=")
	k = strings.TrimSpace(k)
	if k == "" {
		return "", "", false, false
	}
	if !found {
		return k, "", false, true
	}
	v = strings.TrimSpace(v)
	if len(v) >= 2 {
		if (strings.HasPrefix(v, "\"") && strings.HasSuffix(v, "\"")) || (strings.HasPrefix(v, "'") && strings.HasSuffix(v, "'")) {
			v = v[1 : len(v)-1]
		}
	}
	return k, v, true, true
}

func compilePattern(patterns []string, fallback *regexp.Regexp) *regexp.Regexp {
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

func resolveEnvFilePath(path string, baseDir string) string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return ""
	}
	if filepath.IsAbs(trimmed) {
		return filepath.Clean(trimmed)
	}
	if strings.TrimSpace(baseDir) == "" {
		return filepath.Clean(trimmed)
	}
	return filepath.Clean(filepath.Join(baseDir, trimmed))
}

func uniqueStrings(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(items))
	for _, item := range items {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	return out
}

// ClassifySecretValue classifies whether a value likely contains sensitive material.
func ClassifySecretValue(value string) (bool, report.Severity) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return false, report.SeverityWarn
	}
	if looksEnvRef(trimmed) {
		return false, report.SeverityWarn
	}
	if privateBlockPattern.MatchString(trimmed) {
		return true, report.SeverityError
	}
	if credentialURLPattern.MatchString(trimmed) {
		return true, report.SeverityError
	}
	if highEntropyLikeValue.MatchString(trimmed) {
		return true, report.SeverityError
	}
	return false, report.SeverityWarn
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
