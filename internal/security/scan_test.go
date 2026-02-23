package security

import (
	"testing"

	"compose_to_run/internal/compose"
	"compose_to_run/internal/report"
)

func TestScan_SensitiveEnvAndVolume(t *testing.T) {
	project := compose.NewProject()
	project.Files = []string{"compose.yaml"}
	project.Services["app"] = &compose.Service{
		Name:  "app",
		Image: "nginx:latest",
		Environment: map[string]compose.EnvValue{
			"DB_PASSWORD": {Value: "supersecret", HasValue: true},
			"NORMAL":      {Value: "ok", HasValue: true},
		},
		Volumes: []string{"/home/user/.ssh/id_rsa:/run/keys/id_rsa:ro"},
	}

	rep := Scan(project, nil, Config{Mask: true})
	if rep.Summary.Warn == 0 {
		t.Fatalf("expected warning finding, got %+v", rep)
	}
	if rep.Summary.Error == 0 {
		t.Fatalf("expected error finding for sensitive volume path, got %+v", rep)
	}

	foundMasked := false
	for _, f := range rep.Findings {
		if f.ID == "sensitive-env" {
			if f.MaskedValue == "" {
				t.Fatalf("expected masked value for sensitive env finding")
			}
			foundMasked = true
		}
	}
	if !foundMasked {
		t.Fatalf("sensitive-env finding not found")
	}
}

func TestPromoteWarningsToErrors(t *testing.T) {
	findings := []report.Finding{{ID: "x", Severity: report.SeverityWarn}}
	promoted := PromoteWarningsToErrors(findings)
	if promoted[0].Severity != report.SeverityError {
		t.Fatalf("expected warning promoted to error, got %s", promoted[0].Severity)
	}
}
