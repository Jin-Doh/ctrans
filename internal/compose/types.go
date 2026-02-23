package compose

import (
	"fmt"
	"sort"
)

// CommandSpec stores string or list command formats from compose.
type CommandSpec struct {
	String string
	List   []string
}

func (c CommandSpec) IsSet() bool {
	return c.String != "" || len(c.List) > 0
}

func (c CommandSpec) Clone() CommandSpec {
	cp := CommandSpec{String: c.String}
	if len(c.List) > 0 {
		cp.List = append([]string(nil), c.List...)
	}
	return cp
}

// EnvValue supports KEY and KEY=value forms.
type EnvValue struct {
	Value    string
	HasValue bool
}

// Service is a reduced compose service model used by transformer.
type Service struct {
	Name          string
	Image         string
	ContainerName string
	Command       CommandSpec
	Entrypoint    CommandSpec
	Environment   map[string]EnvValue
	EnvFiles      []string
	Ports         []string
	Volumes       []string
	WorkingDir    string
	Restart       string
	DependsOn     []string
	Networks      []string
	UnknownFields []string
}

func (s *Service) Clone() *Service {
	if s == nil {
		return nil
	}
	cp := &Service{
		Name:          s.Name,
		Image:         s.Image,
		ContainerName: s.ContainerName,
		Command:       s.Command.Clone(),
		Entrypoint:    s.Entrypoint.Clone(),
		WorkingDir:    s.WorkingDir,
		Restart:       s.Restart,
	}
	if len(s.Environment) > 0 {
		cp.Environment = make(map[string]EnvValue, len(s.Environment))
		for k, v := range s.Environment {
			cp.Environment[k] = v
		}
	}
	if len(s.EnvFiles) > 0 {
		cp.EnvFiles = append([]string(nil), s.EnvFiles...)
	}
	if len(s.Ports) > 0 {
		cp.Ports = append([]string(nil), s.Ports...)
	}
	if len(s.Volumes) > 0 {
		cp.Volumes = append([]string(nil), s.Volumes...)
	}
	if len(s.DependsOn) > 0 {
		cp.DependsOn = append([]string(nil), s.DependsOn...)
	}
	if len(s.Networks) > 0 {
		cp.Networks = append([]string(nil), s.Networks...)
	}
	if len(s.UnknownFields) > 0 {
		cp.UnknownFields = append([]string(nil), s.UnknownFields...)
	}
	return cp
}

// Project is a merged compose model.
type Project struct {
	Name     string
	Files    []string
	Services map[string]*Service
	Networks map[string]map[string]any
	Volumes  map[string]map[string]any
}

func NewProject() *Project {
	return &Project{
		Services: map[string]*Service{},
		Networks: map[string]map[string]any{},
		Volumes:  map[string]map[string]any{},
	}
}

func (p *Project) ServiceNames() []string {
	names := make([]string, 0, len(p.Services))
	for name := range p.Services {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (p *Project) Merge(other *Project) {
	if other == nil {
		return
	}
	if other.Name != "" {
		p.Name = other.Name
	}
	p.Files = append(p.Files, other.Files...)

	for name, svc := range other.Services {
		if existing, ok := p.Services[name]; ok {
			mergeService(existing, svc)
			continue
		}
		p.Services[name] = svc.Clone()
	}
	for name, net := range other.Networks {
		p.Networks[name] = cloneMap(net)
	}
	for name, vol := range other.Volumes {
		p.Volumes[name] = cloneMap(vol)
	}
}

func mergeService(base, override *Service) {
	if override.Image != "" {
		base.Image = override.Image
	}
	if override.ContainerName != "" {
		base.ContainerName = override.ContainerName
	}
	if override.Command.IsSet() {
		base.Command = override.Command.Clone()
	}
	if override.Entrypoint.IsSet() {
		base.Entrypoint = override.Entrypoint.Clone()
	}
	if len(override.Environment) > 0 {
		if base.Environment == nil {
			base.Environment = map[string]EnvValue{}
		}
		for k, v := range override.Environment {
			base.Environment[k] = v
		}
	}
	if len(override.EnvFiles) > 0 {
		base.EnvFiles = append([]string(nil), override.EnvFiles...)
	}
	if len(override.Ports) > 0 {
		base.Ports = append([]string(nil), override.Ports...)
	}
	if len(override.Volumes) > 0 {
		base.Volumes = append([]string(nil), override.Volumes...)
	}
	if override.WorkingDir != "" {
		base.WorkingDir = override.WorkingDir
	}
	if override.Restart != "" {
		base.Restart = override.Restart
	}
	if len(override.DependsOn) > 0 {
		base.DependsOn = append([]string(nil), override.DependsOn...)
	}
	if len(override.Networks) > 0 {
		base.Networks = append([]string(nil), override.Networks...)
	}
	if len(override.UnknownFields) > 0 {
		base.UnknownFields = uniqueStrings(append(base.UnknownFields, override.UnknownFields...))
	}
}

func cloneMap(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, v := range values {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func (p *Project) Validate() error {
	if len(p.Services) == 0 {
		return fmt.Errorf("compose 파일에서 services를 찾을 수 없습니다")
	}
	for name, svc := range p.Services {
		if svc.Image == "" {
			return fmt.Errorf("service %q 에 image가 없습니다 (build 기반 서비스는 아직 미지원)", name)
		}
	}
	return nil
}
