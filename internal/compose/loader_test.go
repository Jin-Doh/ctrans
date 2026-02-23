package compose

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveInputFiles_DefaultSingle(t *testing.T) {
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "compose.yaml"), "services:\n  app:\n    image: nginx:latest\n")

	files, warnings, err := ResolveInputFiles(nil, dir)
	if err != nil {
		t.Fatalf("ResolveInputFiles returned error: %v", err)
	}
	if len(files) != 1 || filepath.Base(files[0]) != "compose.yaml" {
		t.Fatalf("expected compose.yaml, got %v", files)
	}
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got %+v", warnings)
	}
}

func TestResolveInputFiles_DefaultCollisionPrefersDockerCompose(t *testing.T) {
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "docker-compose.yaml"), "services:\n  app:\n    image: nginx:latest\n")
	mustWriteFile(t, filepath.Join(dir, "compose.yaml"), "services:\n  app:\n    image: nginx:latest\n")

	files, warnings, err := ResolveInputFiles(nil, dir)
	if err != nil {
		t.Fatalf("ResolveInputFiles returned error: %v", err)
	}
	if len(files) != 1 || filepath.Base(files[0]) != "docker-compose.yaml" {
		t.Fatalf("expected docker-compose.yaml, got %v", files)
	}
	if len(warnings) != 1 || warnings[0].ID != "default-compose-collision" {
		t.Fatalf("expected collision warning, got %+v", warnings)
	}
}

func TestResolveInputFiles_RepeatableAndDuplicateWarnings(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.yaml")
	override := filepath.Join(dir, "override.yaml")
	mustWriteFile(t, base, "services:\n  app:\n    image: nginx:latest\n")
	mustWriteFile(t, override, "services:\n  app:\n    image: nginx:stable\n")

	files, warnings, err := ResolveInputFiles([]string{"base.yaml", "override.yaml", "base.yaml"}, dir)
	if err != nil {
		t.Fatalf("ResolveInputFiles returned error: %v", err)
	}
	if len(files) != 3 {
		t.Fatalf("expected 3 files, got %v", files)
	}
	if len(warnings) != 1 || warnings[0].ID != "duplicate-compose-file" {
		t.Fatalf("expected duplicate warning, got %+v", warnings)
	}
}

func TestLoad_MergeOverrideOrder(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.yaml")
	override := filepath.Join(dir, "override.yaml")
	mustWriteFile(t, base, `services:
  app:
    image: nginx:latest
    environment:
      APP_ENV: dev
      TOKEN: one
    ports:
      - "80:80"
`)
	mustWriteFile(t, override, `services:
  app:
    image: nginx:stable
    environment:
      TOKEN: two
      FEATURE_FLAG: enabled
    ports:
      - "8080:80"
`)

	project, warnings, err := Load([]string{base, override}, dir)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got %+v", warnings)
	}
	app := project.Services["app"]
	if app.Image != "nginx:stable" {
		t.Fatalf("expected override image, got %s", app.Image)
	}
	if app.Environment["TOKEN"].Value != "two" {
		t.Fatalf("expected TOKEN override, got %+v", app.Environment["TOKEN"])
	}
	if app.Environment["FEATURE_FLAG"].Value != "enabled" {
		t.Fatalf("expected FEATURE_FLAG merged, got %+v", app.Environment["FEATURE_FLAG"])
	}
	if len(app.Ports) != 1 || app.Ports[0] != "8080:80" {
		t.Fatalf("expected ports override, got %v", app.Ports)
	}
}

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
