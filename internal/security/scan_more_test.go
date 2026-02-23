package security

import (
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
