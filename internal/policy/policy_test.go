package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultAndLoad(t *testing.T) {
	cfg := Default()
	if cfg.Runtime.Default != "docker" {
		t.Fatalf("unexpected default runtime: %s", cfg.Runtime.Default)
	}
	if len(cfg.Compose.DefaultCandidates) != 2 {
		t.Fatalf("unexpected default compose candidates: %+v", cfg.Compose.DefaultCandidates)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	payload := `runtime:
  default: podman
  supported: [docker, podman]
secrets:
  mask: false
  fail_on: warn
  sensitive_key_patterns:
    - '(?i)(secret|token)'
  sensitive_path_patterns:
    - '(?i)(.*\\.pem)$'
  scan_env_files: false
compose:
  default_candidates:
    - compose.custom.yaml
  default_collision: prefer_docker_compose_yaml
`
	if err := os.WriteFile(path, []byte(payload), 0o644); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	if loaded.Runtime.Default != "podman" {
		t.Fatalf("expected podman default, got %s", loaded.Runtime.Default)
	}
	if loaded.Secrets.Mask {
		t.Fatalf("expected mask=false")
	}
	if loaded.Secrets.FailOn != "warn" {
		t.Fatalf("expected fail_on warn, got %s", loaded.Secrets.FailOn)
	}
	if loaded.Secrets.ScanEnvFiles {
		t.Fatalf("expected scan_env_files=false")
	}
	if len(loaded.Compose.DefaultCandidates) != 1 || loaded.Compose.DefaultCandidates[0] != "compose.custom.yaml" {
		t.Fatalf("unexpected candidates: %+v", loaded.Compose.DefaultCandidates)
	}
}

func TestLoadErrorsAndValidate(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.yaml")
	if _, err := Load(missing); err == nil {
		t.Fatalf("expected missing file error")
	}

	invalid := filepath.Join(dir, "invalid.yaml")
	if err := os.WriteFile(invalid, []byte("runtime: ["), 0o644); err != nil {
		t.Fatalf("write invalid policy file: %v", err)
	}
	if _, err := Load(invalid); err == nil {
		t.Fatalf("expected yaml parse error")
	}

	bad := Default()
	bad.Runtime.Default = "containerd"
	if err := bad.Validate(); err == nil {
		t.Fatalf("expected runtime validation error")
	}

	bad = Default()
	bad.Secrets.FailOn = "oops"
	if err := bad.Validate(); err == nil {
		t.Fatalf("expected fail_on validation error")
	}

	bad = Default()
	bad.Secrets.SensitiveKeyPatterns = []string{"["}
	err := bad.Validate()
	if err == nil || !strings.Contains(err.Error(), "invalid secrets.sensitive_key_patterns") {
		t.Fatalf("expected key pattern validation error, got %v", err)
	}

	bad = Default()
	bad.Compose.DefaultCollision = "unsupported"
	if err := bad.Validate(); err == nil {
		t.Fatalf("expected collision validation error")
	}

	bad = Default()
	bad.Runtime.Supported = nil
	if err := bad.Validate(); err == nil {
		t.Fatalf("expected runtime.supported validation error")
	}

	bad = Default()
	bad.Compose.DefaultCandidates = nil
	if err := bad.Validate(); err == nil {
		t.Fatalf("expected compose.default_candidates validation error")
	}

	bad = Default()
	bad.Secrets.SensitivePathPatterns = []string{}
	if err := bad.Validate(); err == nil {
		t.Fatalf("expected sensitive_path_patterns validation error")
	}
}
