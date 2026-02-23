package security

import (
	"os"
	"path/filepath"
	"testing"

	"compose_to_run/internal/compose"
)

func TestScan_EnvReferenceAndHighEntropyAndEnvFile(t *testing.T) {
	project := compose.NewProject()
	project.Files = []string{"compose.yaml"}
	project.Services["svc"] = &compose.Service{
		Name:  "svc",
		Image: "alpine",
		Environment: map[string]compose.EnvValue{
			"API_KEY":           {Value: "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcd", HasValue: true},
			"PRIVATE_KEY_VALUE": {Value: "-----BEGIN PRIVATE KEY-----", HasValue: true},
			"REF_SECRET":        {Value: "${RUNTIME_SECRET}", HasValue: true},
		},
		Volumes:  []string{"/tmp/data:/data"},
		EnvFiles: []string{"./private.env", "./normal.env"},
	}

	rep := Scan(project, nil, Config{Mask: true})
	if rep.Summary.Error < 1 {
		t.Fatalf("expected at least one error for high-risk env, got %+v", rep.Summary)
	}

	for _, f := range rep.Findings {
		if f.Field == "environment.REF_SECRET" {
			t.Fatalf("env reference should be skipped, got %+v", f)
		}
	}
}

func TestMaskHelpersAndHostPath(t *testing.T) {
	if got := MaskValue(""); got != "" {
		t.Fatalf("unexpected empty mask: %q", got)
	}
	if got := MaskValue("abcd"); got != "****" {
		t.Fatalf("unexpected short mask: %q", got)
	}
	if got := MaskValue("abcdef"); got != "a****f" {
		t.Fatalf("unexpected medium mask: %q", got)
	}
	if got := MaskValue("abcdefghij"); got != "ab****ij" {
		t.Fatalf("unexpected long mask: %q", got)
	}

	if got := MaskPath("/tmp/abcd", false); got != "/tmp/abcd" {
		t.Fatalf("mask disabled should keep path, got %q", got)
	}
	if got := MaskPath("", true); got != "" {
		t.Fatalf("empty path should stay empty")
	}
	if got := MaskPath("/", true); got != "***" {
		t.Fatalf("unexpected root path mask: %q", got)
	}
	if got := MaskPath("/tmp/key.pem", true); got == "" || got == "/tmp/key.pem" {
		t.Fatalf("expected masked path, got %q", got)
	}

	if got := hostPath("/a:/b:ro"); got != "/a" {
		t.Fatalf("unexpected host path: %q", got)
	}
	if got := hostPath("named_volume"); got != "" {
		t.Fatalf("expected empty host path for named volume, got %q", got)
	}

	if !looksEnvRef("${TOKEN}") || !looksEnvRef("prefix$${TOKEN}") || looksEnvRef("plain") {
		t.Fatalf("unexpected env ref detection")
	}
}

func TestScan_DetectsSensitiveValueWithoutSensitiveKey(t *testing.T) {
	project := compose.NewProject()
	project.Files = []string{"compose.yaml"}
	project.Services["svc"] = &compose.Service{
		Name:  "svc",
		Image: "alpine",
		Environment: map[string]compose.EnvValue{
			"DATABASE_URL": {Value: "postgres://user:password@db.local:5432/app", HasValue: true},
		},
	}

	rep := Scan(project, nil, Config{Mask: true})
	found := false
	for _, f := range rep.Findings {
		if f.ID == "sensitive-env-by-value" && f.Field == "environment.DATABASE_URL" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected sensitive-env-by-value finding, got %+v", rep.Findings)
	}
}

func TestScan_EnvFileContentAndGlobalEnvFiles(t *testing.T) {
	dir := t.TempDir()
	serviceEnv := filepath.Join(dir, "service.env")
	globalEnv := filepath.Join(dir, "global.env")
	if err := os.WriteFile(serviceEnv, []byte("APP_ENV=prod\nSECRET_TOKEN=plain-token\n"), 0o644); err != nil {
		t.Fatalf("write service env file: %v", err)
	}
	if err := os.WriteFile(globalEnv, []byte("DB_URL=postgres://user:pass@db.local:5432/app\n"), 0o644); err != nil {
		t.Fatalf("write global env file: %v", err)
	}

	project := compose.NewProject()
	project.Files = []string{"compose.yaml"}
	project.Services["svc"] = &compose.Service{
		Name:     "svc",
		Image:    "alpine",
		EnvFiles: []string{filepath.Base(serviceEnv)},
	}

	rep := Scan(project, nil, Config{
		Mask:         true,
		ScanEnvFiles: true,
		ExtraEnvFiles: []string{
			filepath.Base(globalEnv),
		},
		BaseDir: dir,
	})

	entryCount := 0
	for _, f := range rep.Findings {
		if f.ID == "sensitive-env-file-entry" {
			entryCount++
		}
	}
	if entryCount < 2 {
		t.Fatalf("expected at least two sensitive env file findings, got %+v", rep.Findings)
	}
}

func TestParseEnvLineAndClassifySecretValue(t *testing.T) {
	key, value, hasValue, ok := parseEnvLine("export TOKEN=abc")
	if !ok || !hasValue || key != "TOKEN" || value != "abc" {
		t.Fatalf("unexpected parsed env line: key=%q value=%q hasValue=%t ok=%t", key, value, hasValue, ok)
	}

	if _, _, _, ok := parseEnvLine("# comment"); ok {
		t.Fatalf("comment line should be ignored")
	}

	if sensitive, severity := ClassifySecretValue("postgres://user:pass@localhost/db"); !sensitive || severity != "error" {
		t.Fatalf("expected credential URL classified as sensitive error, got sensitive=%t severity=%s", sensitive, severity)
	}
	if sensitive, _ := ClassifySecretValue("${RUNTIME_SECRET}"); sensitive {
		t.Fatalf("env reference should not be classified as inline sensitive")
	}

	key, _, hasValue, ok = parseEnvLine("ONLY_KEY")
	if !ok || hasValue || key != "ONLY_KEY" {
		t.Fatalf("key-only env line parsing failed: key=%q hasValue=%t ok=%t", key, hasValue, ok)
	}
}

func TestCompilePatternResolvePathAndUniqueStrings(t *testing.T) {
	pat := compilePattern([]string{`[`}, defaultSensitiveKeyPattern)
	if !pat.MatchString("DB_PASSWORD") {
		t.Fatalf("invalid override patterns should fall back to default pattern")
	}

	pat = compilePattern([]string{`(?i)my_secret`}, defaultSensitiveKeyPattern)
	if !pat.MatchString("MY_SECRET") {
		t.Fatalf("custom override pattern should be compiled")
	}

	if got := resolveEnvFilePath("local.env", "/tmp/work"); got != "/tmp/work/local.env" {
		t.Fatalf("unexpected relative env file path resolution: %q", got)
	}
	if got := resolveEnvFilePath("/etc/app.env", "/tmp/work"); got != "/etc/app.env" {
		t.Fatalf("unexpected absolute env file path resolution: %q", got)
	}

	values := uniqueStrings([]string{"b", "a", "b", " ", "a"})
	if len(values) != 2 || values[0] != "a" || values[1] != "b" {
		t.Fatalf("unexpected uniqueStrings result: %v", values)
	}
}
