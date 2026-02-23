package compose

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveInputFiles_NoDefaultAndMissingProvided(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := ResolveInputFiles(nil, dir); err == nil {
		t.Fatalf("expected error when no defaults exist")
	}

	if _, _, err := ResolveInputFiles([]string{"missing.yaml"}, dir); err == nil {
		t.Fatalf("expected missing file error")
	}
}

func TestLoad_ParseAndStructureErrors(t *testing.T) {
	dir := t.TempDir()
	invalid := filepath.Join(dir, "invalid.yaml")
	mustWriteFile(t, invalid, "services: [")
	if _, _, err := Load([]string{invalid}, dir); err == nil {
		t.Fatalf("expected parse error")
	}

	noServices := filepath.Join(dir, "nosvc.yaml")
	mustWriteFile(t, noServices, "name: demo\n")
	if _, _, err := Load([]string{noServices}, dir); err == nil {
		t.Fatalf("expected no services error")
	}

	badService := filepath.Join(dir, "badsvc.yaml")
	mustWriteFile(t, badService, "services:\n  app: 42\n")
	if _, _, err := Load([]string{badService}, dir); err == nil {
		t.Fatalf("expected service object error")
	}
}

func TestLoad_WarningsForUnsupportedFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "compose.yaml")
	mustWriteFile(t, path, `x-root: true
services:
  app:
    image: nginx
    build: .
`)

	project, warnings, err := Load([]string{path}, dir)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if project.Services["app"].Image != "nginx" {
		t.Fatalf("unexpected project parse: %+v", project.Services["app"])
	}
	if len(warnings) < 2 {
		t.Fatalf("expected root+service unsupported warnings, got %+v", warnings)
	}
}

func TestParseHelpers(t *testing.T) {
	cmd := parseCommandSpec([]any{"echo", "hello"})
	if len(cmd.List) != 2 || cmd.String != "" {
		t.Fatalf("unexpected command spec: %+v", cmd)
	}
	if parseCommandSpec(nil).IsSet() {
		t.Fatalf("nil command should not be set")
	}

	if got := parseStringList([]any{"a", 2, true, ""}); len(got) != 3 {
		t.Fatalf("unexpected parsed string list: %v", got)
	}
	if got := parseStringList("single"); len(got) != 1 || got[0] != "single" {
		t.Fatalf("unexpected single string list: %v", got)
	}

	envMap := parseEnvironment(map[string]any{"A": "1", "B": nil, "C": 2})
	if !envMap["A"].HasValue || envMap["B"].HasValue || envMap["C"].Value != "2" {
		t.Fatalf("unexpected env map parse: %+v", envMap)
	}
	envList := parseEnvironment([]any{"X=1", "Y"})
	if !envList["X"].HasValue || envList["Y"].HasValue {
		t.Fatalf("unexpected env list parse: %+v", envList)
	}

	deps := parseDependsOn(map[string]any{"db": map[string]any{"condition": "service_started"}})
	if len(deps) != 1 || deps[0] != "db" {
		t.Fatalf("unexpected deps: %v", deps)
	}
	if parseDependsOn(nil) != nil {
		t.Fatalf("expected nil deps for nil input")
	}

	nets := parseNetworks(map[string]any{"front": map[string]any{}, "back": map[string]any{}})
	if len(nets) != 2 {
		t.Fatalf("unexpected nets: %v", nets)
	}
	if parseNetworks(nil) != nil {
		t.Fatalf("expected nil networks for nil input")
	}

	if _, ok := asMap(3); ok {
		t.Fatalf("asMap should fail for scalar")
	}
	if m, ok := asMap(map[any]any{"k": map[any]any{"x": 1}}); !ok || m["k"] == nil {
		t.Fatalf("asMap should convert map[any]any, got %v", m)
	}

	if s, ok := asString(1); !ok || s != "1" {
		t.Fatalf("asString int conversion failed: %q %v", s, ok)
	}
	if s, ok := asString(int64(2)); !ok || s != "2" {
		t.Fatalf("asString int64 conversion failed: %q %v", s, ok)
	}
	if s, ok := asString(3.0); !ok || s != "3" {
		t.Fatalf("asString float int conversion failed: %q %v", s, ok)
	}
	if s, ok := asString(3.5); !ok || s != "3.5" {
		t.Fatalf("asString float conversion failed: %q %v", s, ok)
	}
	if s, ok := asString(true); !ok || s != "true" {
		t.Fatalf("asString bool conversion failed: %q %v", s, ok)
	}
	if s, ok := asString(struct{}{}); ok || s != "" {
		t.Fatalf("asString should fail for unsupported type")
	}

	n := normalizeAny(map[any]any{"k": map[any]any{"x": 1}})
	if _, ok := n.(map[string]any); !ok {
		t.Fatalf("normalizeAny should convert map[any]any")
	}
}

func TestParseFile_ReadError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "compose.yaml")
	mustWriteFile(t, path, "services:\n  app:\n    image: nginx\n")
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove file: %v", err)
	}
	if _, _, err := parseFile(path); err == nil {
		t.Fatalf("expected read error")
	}
}

func TestResolveInputFilesWithOptions_DefaultCandidates(t *testing.T) {
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "custom-compose.yaml"), "services:\n  app:\n    image: nginx:latest\n")

	files, warnings, err := ResolveInputFilesWithOptions(nil, dir, ResolveOptions{
		DefaultCandidates: []string{"custom-compose.yaml", "compose.yaml"},
	})
	if err != nil {
		t.Fatalf("ResolveInputFilesWithOptions returned error: %v", err)
	}
	if len(files) != 1 || filepath.Base(files[0]) != "custom-compose.yaml" {
		t.Fatalf("expected custom-compose.yaml, got %v", files)
	}
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got %+v", warnings)
	}
}

func TestLoadWithOptions_UsesCustomDefaults(t *testing.T) {
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "custom.yaml"), "services:\n  app:\n    image: nginx:latest\n")

	project, warnings, err := LoadWithOptions(nil, dir, LoadOptions{
		Resolve: ResolveOptions{DefaultCandidates: []string{"custom.yaml"}},
	})
	if err != nil {
		t.Fatalf("LoadWithOptions returned error: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got %+v", warnings)
	}
	if _, ok := project.Services["app"]; !ok {
		t.Fatalf("expected app service loaded from custom default candidates")
	}
}
