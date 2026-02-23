package compose

import "testing"

func TestCommandSpecCloneAndIsSet(t *testing.T) {
	c := CommandSpec{List: []string{"a", "b"}}
	if !c.IsSet() {
		t.Fatalf("expected IsSet true")
	}
	clone := c.Clone()
	clone.List[0] = "x"
	if c.List[0] != "a" {
		t.Fatalf("clone should deep-copy list")
	}
}

func TestServiceCloneDeepCopy(t *testing.T) {
	s := &Service{
		Name: "app",
		Environment: map[string]EnvValue{
			"A": {Value: "1", HasValue: true},
		},
		EnvFiles:      []string{".env"},
		Ports:         []string{"80:80"},
		Volumes:       []string{"v:/v"},
		DependsOn:     []string{"db"},
		Networks:      []string{"n1"},
		UnknownFields: []string{"x"},
	}
	cp := s.Clone()
	cp.Environment["A"] = EnvValue{Value: "2", HasValue: true}
	cp.EnvFiles[0] = "changed"
	if s.Environment["A"].Value != "1" || s.EnvFiles[0] != ".env" {
		t.Fatalf("expected deep clone, source mutated: %+v", s)
	}
}

func TestProjectMergeValidateAndHelpers(t *testing.T) {
	p := NewProject()
	if err := p.Validate(); err == nil {
		t.Fatalf("expected validate error for empty services")
	}

	base := NewProject()
	base.Name = "demo"
	base.Services["app"] = &Service{Name: "app", Image: "nginx", UnknownFields: []string{"z"}}
	base.Networks["net"] = map[string]any{"driver": "bridge"}

	override := NewProject()
	override.Services["app"] = &Service{
		Name:          "app",
		Image:         "nginx:stable",
		Environment:   map[string]EnvValue{"TOKEN": {Value: "x", HasValue: true}},
		UnknownFields: []string{"a", "z"},
	}
	override.Volumes["data"] = map[string]any{"name": "data"}

	base.Merge(override)
	if base.Services["app"].Image != "nginx:stable" {
		t.Fatalf("expected merged image, got %s", base.Services["app"].Image)
	}
	if got := base.Services["app"].UnknownFields; len(got) != 2 || got[0] != "a" || got[1] != "z" {
		t.Fatalf("expected deduped/sorted unknown fields, got %v", got)
	}

	if err := base.Validate(); err != nil {
		t.Fatalf("expected valid project, got %v", err)
	}

	bad := NewProject()
	bad.Services["bad"] = &Service{Name: "bad"}
	if err := bad.Validate(); err == nil {
		t.Fatalf("expected missing image validation error")
	}

	names := base.ServiceNames()
	if len(names) != 1 || names[0] != "app" {
		t.Fatalf("unexpected service names: %v", names)
	}
}

func TestUniqueStringsAndCloneMap(t *testing.T) {
	vals := uniqueStrings([]string{"b", "a", "b"})
	if len(vals) != 2 || vals[0] != "a" || vals[1] != "b" {
		t.Fatalf("unexpected unique strings: %v", vals)
	}
	if uniqueStrings(nil) != nil {
		t.Fatalf("expected nil for empty input")
	}

	m := map[string]any{"k": "v"}
	cp := cloneMap(m)
	cp["k"] = "x"
	if m["k"] != "v" {
		t.Fatalf("cloneMap should copy map")
	}
	if cloneMap(nil) != nil {
		t.Fatalf("cloneMap(nil) should be nil")
	}
}

func TestMergeService_FullOverrideBranches(t *testing.T) {
	base := &Service{
		Name:          "app",
		Image:         "nginx:latest",
		ContainerName: "app-base",
		Command:       CommandSpec{String: "echo base"},
		Entrypoint:    CommandSpec{String: "/bin/sh"},
		Environment:   map[string]EnvValue{"A": {Value: "1", HasValue: true}},
		EnvFiles:      []string{"base.env"},
		Ports:         []string{"80:80"},
		Volumes:       []string{"/a:/a"},
		WorkingDir:    "/base",
		Restart:       "no",
		DependsOn:     []string{"db"},
		Networks:      []string{"net1"},
		UnknownFields: []string{"x"},
	}
	override := &Service{
		Name:          "app",
		Image:         "nginx:stable",
		ContainerName: "app-new",
		Command:       CommandSpec{List: []string{"echo", "override"}},
		Entrypoint:    CommandSpec{List: []string{"/bin/bash", "-lc"}},
		Environment:   map[string]EnvValue{"B": {Value: "2", HasValue: true}},
		EnvFiles:      []string{"override.env"},
		Ports:         []string{"8080:80"},
		Volumes:       []string{"/b:/b"},
		WorkingDir:    "/override",
		Restart:       "always",
		DependsOn:     []string{"cache"},
		Networks:      []string{"net2"},
		UnknownFields: []string{"y", "x"},
	}

	mergeService(base, override)

	if base.Image != "nginx:stable" || base.ContainerName != "app-new" {
		t.Fatalf("override not applied: %+v", base)
	}
	if base.Command.String != "" || len(base.Command.List) != 2 {
		t.Fatalf("command override failed: %+v", base.Command)
	}
	if base.Entrypoint.String != "" || len(base.Entrypoint.List) != 2 {
		t.Fatalf("entrypoint override failed: %+v", base.Entrypoint)
	}
	if base.Environment["A"].Value != "1" || base.Environment["B"].Value != "2" {
		t.Fatalf("environment merge failed: %+v", base.Environment)
	}
	if len(base.EnvFiles) != 1 || base.EnvFiles[0] != "override.env" {
		t.Fatalf("env_files override failed: %v", base.EnvFiles)
	}
	if len(base.Ports) != 1 || base.Ports[0] != "8080:80" {
		t.Fatalf("ports override failed: %v", base.Ports)
	}
	if len(base.Volumes) != 1 || base.Volumes[0] != "/b:/b" {
		t.Fatalf("volumes override failed: %v", base.Volumes)
	}
	if base.WorkingDir != "/override" || base.Restart != "always" {
		t.Fatalf("scalar override failed: wd=%s restart=%s", base.WorkingDir, base.Restart)
	}
	if len(base.DependsOn) != 1 || base.DependsOn[0] != "cache" {
		t.Fatalf("depends_on override failed: %v", base.DependsOn)
	}
	if len(base.Networks) != 1 || base.Networks[0] != "net2" {
		t.Fatalf("networks override failed: %v", base.Networks)
	}
	if got := base.UnknownFields; len(got) != 2 || got[0] != "x" || got[1] != "y" {
		t.Fatalf("unknown fields merge failed: %v", got)
	}
}
