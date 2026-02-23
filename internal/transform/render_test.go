package transform

import (
	"strings"
	"testing"

	"compose_to_run/internal/compose"
)

func TestBuildPlan_OrderAndSensitiveEnvRedaction(t *testing.T) {
	project := compose.NewProject()
	project.Name = "demo"
	project.Services["db"] = &compose.Service{
		Name:  "db",
		Image: "postgres:16",
	}
	project.Services["app"] = &compose.Service{
		Name:      "app",
		Image:     "nginx:latest",
		DependsOn: []string{"db"},
		Environment: map[string]compose.EnvValue{
			"DB_PASSWORD": {Value: "plain-text-secret", HasValue: true},
			"APP_ENV":     {Value: "prod", HasValue: true},
		},
	}

	plan, err := BuildPlan(project, Options{Runtime: "docker", Mask: true})
	if err != nil {
		t.Fatalf("BuildPlan returned error: %v", err)
	}
	if len(plan.Services) != 2 {
		t.Fatalf("expected 2 services, got %d", len(plan.Services))
	}
	if plan.Services[0].Name != "db" || plan.Services[1].Name != "app" {
		t.Fatalf("expected dependency order db->app, got %v -> %v", plan.Services[0].Name, plan.Services[1].Name)
	}
	if !strings.Contains(plan.Services[1].Command, "DB_PASSWORD") {
		t.Fatalf("expected DB_PASSWORD var in command, got %s", plan.Services[1].Command)
	}
	if strings.Contains(plan.Services[1].Command, "DB_PASSWORD=plain-text-secret") {
		t.Fatalf("expected redaction of sensitive env value, got %s", plan.Services[1].Command)
	}
	if len(plan.Warnings) == 0 {
		t.Fatalf("expected warning for sensitive env redaction")
	}
}

func TestBuildPlan_TargetIncludesDependencies(t *testing.T) {
	project := compose.NewProject()
	project.Services["db"] = &compose.Service{Name: "db", Image: "postgres:16"}
	project.Services["app"] = &compose.Service{Name: "app", Image: "nginx", DependsOn: []string{"db"}}
	project.Services["worker"] = &compose.Service{Name: "worker", Image: "busybox"}

	plan, err := BuildPlan(project, Options{Runtime: "docker", TargetServices: []string{"app"}})
	if err != nil {
		t.Fatalf("BuildPlan returned error: %v", err)
	}
	if len(plan.Services) != 2 {
		t.Fatalf("expected target closure to include 2 services, got %d", len(plan.Services))
	}
	if plan.Services[0].Name != "db" || plan.Services[1].Name != "app" {
		t.Fatalf("expected db then app, got %+v", plan.Services)
	}
}

func TestBuildPlan_EnvReferenceUsesRuntimeInjection(t *testing.T) {
	project := compose.NewProject()
	project.Services["db"] = &compose.Service{
		Name:  "db",
		Image: "postgres:16",
		Environment: map[string]compose.EnvValue{
			"POSTGRES_PASSWORD": {Value: "${POSTGRES_PASSWORD}", HasValue: true},
		},
	}

	plan, err := BuildPlan(project, Options{Runtime: "docker"})
	if err != nil {
		t.Fatalf("BuildPlan returned error: %v", err)
	}
	command := plan.Services[0].Command
	if !strings.Contains(command, "-e POSTGRES_PASSWORD") {
		t.Fatalf("expected runtime injection flag, got %s", command)
	}
	if strings.Contains(command, "POSTGRES_PASSWORD=${POSTGRES_PASSWORD}") {
		t.Fatalf("expected env reference to be omitted from command, got %s", command)
	}
}
