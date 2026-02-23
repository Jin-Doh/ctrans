package compose

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"compose_to_run/internal/report"
	"gopkg.in/yaml.v3"
)

var (
	defaultComposeCandidates = []string{"docker-compose.yaml", "compose.yaml"}

	supportedRootKeys = map[string]struct{}{
		"version":  {},
		"name":     {},
		"services": {},
		"networks": {},
		"volumes":  {},
	}

	supportedServiceKeys = map[string]struct{}{
		"image":          {},
		"container_name": {},
		"command":        {},
		"entrypoint":     {},
		"environment":    {},
		"env_file":       {},
		"ports":          {},
		"volumes":        {},
		"working_dir":    {},
		"restart":        {},
		"depends_on":     {},
		"networks":       {},
	}
)

// ResolveOptions controls default compose file discovery behavior.
type ResolveOptions struct {
	DefaultCandidates []string
}

// LoadOptions controls compose loading behavior.
type LoadOptions struct {
	Resolve ResolveOptions
}

// Load reads compose files and merges them in order.
func Load(inputFiles []string, cwd string) (*Project, []report.Finding, error) {
	return LoadWithOptions(inputFiles, cwd, LoadOptions{})
}

// LoadWithOptions reads compose files and merges them in order.
func LoadWithOptions(inputFiles []string, cwd string, opts LoadOptions) (*Project, []report.Finding, error) {
	files, warnings, err := ResolveInputFilesWithOptions(inputFiles, cwd, opts.Resolve)
	if err != nil {
		return nil, nil, err
	}

	merged := NewProject()
	for _, file := range files {
		p, w, err := parseFile(file)
		if err != nil {
			return nil, warnings, err
		}
		merged.Merge(p)
		warnings = append(warnings, w...)
	}

	if err := merged.Validate(); err != nil {
		return nil, warnings, err
	}
	return merged, warnings, nil
}

// ResolveInputFiles returns input files following repeatable -f and default lookup rules.
func ResolveInputFiles(inputFiles []string, cwd string) ([]string, []report.Finding, error) {
	return ResolveInputFilesWithOptions(inputFiles, cwd, ResolveOptions{})
}

// ResolveInputFilesWithOptions returns input files following repeatable -f and default lookup rules.
func ResolveInputFilesWithOptions(inputFiles []string, cwd string, opts ResolveOptions) ([]string, []report.Finding, error) {
	if cwd == "" {
		cwd = "."
	}

	warnings := []report.Finding{}
	resolved := []string{}

	if len(inputFiles) > 0 {
		seen := map[string]struct{}{}
		for _, file := range inputFiles {
			full := file
			if !filepath.IsAbs(full) {
				full = filepath.Join(cwd, file)
			}
			if _, err := os.Stat(full); err != nil {
				if errors.Is(err, os.ErrNotExist) {
					return nil, warnings, fmt.Errorf("compose 파일을 찾을 수 없습니다: %s", file)
				}
				return nil, warnings, fmt.Errorf("compose 파일을 읽을 수 없습니다 %s: %w", file, err)
			}
			clean := filepath.Clean(full)
			if _, ok := seen[clean]; ok {
				warnings = append(warnings, report.Finding{
					ID:       "duplicate-compose-file",
					Severity: report.SeverityWarn,
					Field:    "file",
					Message:  fmt.Sprintf("compose 파일 %q 이(가) 중복 지정되었습니다", file),
				})
			}
			seen[clean] = struct{}{}
			resolved = append(resolved, clean)
		}
		return resolved, warnings, nil
	}

	candidates := opts.DefaultCandidates
	if len(candidates) == 0 {
		candidates = defaultComposeCandidates
	}

	existing := []string{}
	for _, candidate := range candidates {
		full := filepath.Join(cwd, candidate)
		if _, err := os.Stat(full); err == nil {
			existing = append(existing, full)
		}
	}

	switch len(existing) {
	case 0:
		return nil, warnings, fmt.Errorf("compose 파일이 지정되지 않았고 기본 파일도 없습니다 (%s)", strings.Join(candidates, ", "))
	case 1:
		return existing, warnings, nil
	default:
		preferred := existing[0]
		warnings = append(warnings, report.Finding{
			ID:             "default-compose-collision",
			Severity:       report.SeverityWarn,
			Field:          "file",
			Message:        fmt.Sprintf("%s 파일들이 모두 존재하여 첫 번째 발견 후보(%s)를 우선 사용합니다", strings.Join(candidates, ", "), filepath.Base(preferred)),
			Recommendation: "중복 후보 파일을 정리하거나 -f 순서를 명시해서 병합 순서를 제어하세요",
		})
		return []string{preferred}, warnings, nil
	}
}

func parseFile(path string) (*Project, []report.Finding, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("compose 파일 읽기 실패 %s: %w", path, err)
	}

	var raw map[string]any
	if err := yaml.Unmarshal(payload, &raw); err != nil {
		return nil, nil, fmt.Errorf("yaml 파싱 실패 %s: %w", path, err)
	}
	raw = normalizeMap(raw)

	warnings := []report.Finding{}
	project := NewProject()
	project.Files = append(project.Files, path)

	for key := range raw {
		if _, ok := supportedRootKeys[key]; !ok {
			warnings = append(warnings, report.Finding{
				ID:             "unsupported-root-field",
				Severity:       report.SeverityWarn,
				Field:          key,
				Message:        fmt.Sprintf("루트 필드 %q 는 현재 MVP에서 지원하지 않습니다", key),
				Recommendation: "필드를 제거하거나 배포 스크립트에서 수동 처리하세요",
			})
		}
	}

	if name, ok := asString(raw["name"]); ok {
		project.Name = name
	}

	servicesMap, ok := asMap(raw["services"])
	if !ok {
		return nil, warnings, fmt.Errorf("compose 파일 %s 에 유효한 services 섹션이 없습니다", path)
	}

	for svcName, value := range servicesMap {
		svcMap, ok := asMap(value)
		if !ok {
			return nil, warnings, fmt.Errorf("%s 의 service %q 는 객체 형태여야 합니다", path, svcName)
		}
		svc, svcWarnings := parseService(svcName, svcMap)
		warnings = append(warnings, svcWarnings...)
		project.Services[svcName] = svc
	}

	if networks, ok := asMap(raw["networks"]); ok {
		for name, value := range networks {
			if netMap, ok := asMap(value); ok {
				project.Networks[name] = netMap
				continue
			}
			project.Networks[name] = map[string]any{}
		}
	}
	if volumes, ok := asMap(raw["volumes"]); ok {
		for name, value := range volumes {
			if volMap, ok := asMap(value); ok {
				project.Volumes[name] = volMap
				continue
			}
			project.Volumes[name] = map[string]any{}
		}
	}

	return project, warnings, nil
}

func parseService(name string, in map[string]any) (*Service, []report.Finding) {
	svc := &Service{
		Name:        name,
		Environment: map[string]EnvValue{},
	}
	warnings := []report.Finding{}

	for key := range in {
		if _, ok := supportedServiceKeys[key]; ok {
			continue
		}
		svc.UnknownFields = append(svc.UnknownFields, key)
		warnings = append(warnings, report.Finding{
			ID:             "unsupported-service-field",
			Severity:       report.SeverityWarn,
			Service:        name,
			Field:          key,
			Message:        fmt.Sprintf("service 필드 %q 는 현재 MVP에서 지원하지 않습니다", key),
			Recommendation: "필드를 제거하거나 런타임 플래그로 수동 매핑하세요",
		})
	}
	sort.Strings(svc.UnknownFields)

	if image, ok := asString(in["image"]); ok {
		svc.Image = image
	}
	if containerName, ok := asString(in["container_name"]); ok {
		svc.ContainerName = containerName
	}
	svc.Command = parseCommandSpec(in["command"])
	svc.Entrypoint = parseCommandSpec(in["entrypoint"])
	svc.Environment = parseEnvironment(in["environment"])
	svc.EnvFiles = parseStringList(in["env_file"])
	svc.Ports = parseStringList(in["ports"])
	svc.Volumes = parseStringList(in["volumes"])
	if wd, ok := asString(in["working_dir"]); ok {
		svc.WorkingDir = wd
	}
	if restart, ok := asString(in["restart"]); ok {
		svc.Restart = restart
	}
	svc.DependsOn = parseDependsOn(in["depends_on"])
	svc.Networks = parseNetworks(in["networks"])

	return svc, warnings
}

func normalizeMap(in map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range in {
		out[k] = normalizeAny(v)
	}
	return out
}

func normalizeAny(in any) any {
	switch t := in.(type) {
	case map[string]any:
		return normalizeMap(t)
	case map[any]any:
		out := map[string]any{}
		for k, v := range t {
			out[fmt.Sprint(k)] = normalizeAny(v)
		}
		return out
	case []any:
		out := make([]any, 0, len(t))
		for _, v := range t {
			out = append(out, normalizeAny(v))
		}
		return out
	default:
		return t
	}
}

func asMap(v any) (map[string]any, bool) {
	if v == nil {
		return nil, false
	}
	switch t := v.(type) {
	case map[string]any:
		return t, true
	case map[any]any:
		out := map[string]any{}
		for k, val := range t {
			out[fmt.Sprint(k)] = normalizeAny(val)
		}
		return out, true
	default:
		return nil, false
	}
}

func asString(v any) (string, bool) {
	if v == nil {
		return "", false
	}
	switch t := v.(type) {
	case string:
		return t, true
	case int:
		return fmt.Sprintf("%d", t), true
	case int64:
		return fmt.Sprintf("%d", t), true
	case float64:
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t)), true
		}
		return fmt.Sprintf("%v", t), true
	case bool:
		return fmt.Sprintf("%t", t), true
	default:
		return "", false
	}
}

func parseCommandSpec(v any) CommandSpec {
	if v == nil {
		return CommandSpec{}
	}
	if s, ok := asString(v); ok {
		return CommandSpec{String: s}
	}
	items := parseStringList(v)
	if len(items) == 0 {
		return CommandSpec{}
	}
	return CommandSpec{List: items}
}

func parseStringList(v any) []string {
	if v == nil {
		return nil
	}
	if arr, ok := v.([]any); ok {
		out := make([]string, 0, len(arr))
		for _, item := range arr {
			s, ok := asString(item)
			if !ok {
				continue
			}
			if strings.TrimSpace(s) == "" {
				continue
			}
			out = append(out, s)
		}
		return out
	}
	if s, ok := asString(v); ok {
		if strings.TrimSpace(s) == "" {
			return nil
		}
		return []string{s}
	}
	return nil
}

func parseEnvironment(v any) map[string]EnvValue {
	out := map[string]EnvValue{}
	if v == nil {
		return out
	}

	if m, ok := asMap(v); ok {
		for key, raw := range m {
			if raw == nil {
				out[key] = EnvValue{HasValue: false}
				continue
			}
			if s, ok := asString(raw); ok {
				out[key] = EnvValue{Value: s, HasValue: true}
				continue
			}
			out[key] = EnvValue{Value: fmt.Sprint(raw), HasValue: true}
		}
		return out
	}

	items := parseStringList(v)
	for _, item := range items {
		parts := strings.SplitN(item, "=", 2)
		if len(parts) == 1 {
			out[parts[0]] = EnvValue{HasValue: false}
			continue
		}
		out[parts[0]] = EnvValue{Value: parts[1], HasValue: true}
	}
	return out
}

func parseDependsOn(v any) []string {
	if v == nil {
		return nil
	}
	if list := parseStringList(v); len(list) > 0 {
		return uniqueStrings(list)
	}
	m, ok := asMap(v)
	if !ok {
		return nil
	}
	deps := make([]string, 0, len(m))
	for dep := range m {
		deps = append(deps, dep)
	}
	sort.Strings(deps)
	return deps
}

func parseNetworks(v any) []string {
	if v == nil {
		return nil
	}
	if list := parseStringList(v); len(list) > 0 {
		return uniqueStrings(list)
	}
	m, ok := asMap(v)
	if !ok {
		return nil
	}
	nets := make([]string, 0, len(m))
	for net := range m {
		nets = append(nets, net)
	}
	sort.Strings(nets)
	return nets
}
