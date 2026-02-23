package transform

import (
	"strings"
	"testing"

	"compose_to_run/internal/compose"
)

func TestBuildPlan_ErrorsAndRuntimeDefaults(t *testing.T) {
	project := compose.NewProject()
	project.Services["app"] = &compose.Service{Name: "app", Image: "nginx"}

	if _, err := BuildPlan(project, Options{Runtime: "invalid"}); err == nil {
		t.Fatalf("expected unsupported runtime error")
	}

	plan, err := BuildPlan(project, Options{})
	if err != nil {
		t.Fatalf("expected default runtime success, got %v", err)
	}
	if plan.Runtime != "docker" {
		t.Fatalf("expected default docker runtime, got %s", plan.Runtime)
	}
}

func TestBuildPlan_TargetMissingAndCycleWarning(t *testing.T) {
	project := compose.NewProject()
	project.Services["a"] = &compose.Service{Name: "a", Image: "alpine", DependsOn: []string{"b"}}
	project.Services["b"] = &compose.Service{Name: "b", Image: "alpine", DependsOn: []string{"a"}}

	if _, err := BuildPlan(project, Options{Runtime: "docker", TargetServices: []string{"missing"}}); err == nil {
		t.Fatalf("expected target missing error")
	}

	plan, err := BuildPlan(project, Options{Runtime: "docker"})
	if err != nil {
		t.Fatalf("expected cycle handled with warning, got %v", err)
	}
	if len(plan.Warnings) == 0 {
		t.Fatalf("expected cycle warning")
	}
}

func TestRenderService_FullFlagsAndWarnings(t *testing.T) {
	svc := &compose.Service{
		Name:       "app",
		Image:      "nginx",
		EnvFiles:   []string{"svc.env"},
		WorkingDir: "/work",
		Restart:    "always",
		Environment: map[string]compose.EnvValue{
			"A":            {Value: "1", HasValue: true},
			"SECRET_TOKEN": {Value: "abc", HasValue: true},
		},
		Ports:      []string{"8080:80"},
		Volumes:    []string{"/tmp:/tmp"},
		Networks:   []string{"n1", "n2"},
		Entrypoint: compose.CommandSpec{List: []string{"/bin/sh", "-c"}},
		Command:    compose.CommandSpec{String: "echo hello"},
	}

	cmd, warnings, err := renderService("docker", "demo", svc, Options{ExtraEnvFiles: []string{"global.env"}})
	if err != nil {
		t.Fatalf("renderService returned error: %v", err)
	}

	mustContain := []string{"--name demo-app", "--restart always", "-w /work", "--env-file global.env", "--env-file svc.env", "-p 8080:80", "-v /tmp:/tmp", "--network n1", "--entrypoint '/bin/sh -c'", "nginx"}
	for _, token := range mustContain {
		if !strings.Contains(cmd, token) {
			t.Fatalf("expected command to contain %q, got %s", token, cmd)
		}
	}
	if strings.Contains(cmd, "SECRET_TOKEN=abc") {
		t.Fatalf("expected sensitive env redaction, got %s", cmd)
	}
	if len(warnings) < 2 {
		t.Fatalf("expected redaction and multi-network warnings, got %+v", warnings)
	}
}

func TestRenderService_ErrorAndHelpers(t *testing.T) {
	if _, _, err := renderService("docker", "demo", &compose.Service{Name: "x"}, Options{}); err == nil {
		t.Fatalf("expected missing image error")
	}

	if got := shellQuote("abc"); got != "abc" {
		t.Fatalf("unexpected plain quote: %q", got)
	}
	if got := shellQuote("a b"); got != "'a b'" {
		t.Fatalf("unexpected spaced quote: %q", got)
	}
	if got := commandSpecString(compose.CommandSpec{List: []string{"a", "b"}}); got != "a b" {
		t.Fatalf("unexpected commandSpecString: %q", got)
	}
	if !looksEnvRef("${A}") || looksEnvRef("A") {
		t.Fatalf("unexpected looksEnvRef behavior")
	}
}

func TestTopologicalOrder_MissingDependencyWarning(t *testing.T) {
	project := compose.NewProject()
	project.Services["app"] = &compose.Service{Name: "app", Image: "alpine", DependsOn: []string{"missing"}}
	selected := map[string]bool{"app": true}

	order, warnings := topologicalOrder(project, selected)
	if len(order) != 1 || order[0] != "app" {
		t.Fatalf("unexpected order: %v", order)
	}
	if len(warnings) == 0 || warnings[0].ID != "missing-dependency" {
		t.Fatalf("expected missing dependency warning, got %+v", warnings)
	}
}
