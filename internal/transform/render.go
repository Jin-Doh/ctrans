package transform

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"compose_to_run/internal/compose"
	"compose_to_run/internal/report"
	"compose_to_run/internal/security"
)

var sensitiveKeyPattern = regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key)`)

// Options controls rendering behavior.
type Options struct {
	Runtime        string
	ProjectName    string
	Mask           bool
	TargetServices []string
	ExtraEnvFiles  []string
}

// ServicePlan describes one rendered runtime command.
type ServicePlan struct {
	Name      string   `json:"name"`
	Order     int      `json:"order"`
	Command   string   `json:"command"`
	DependsOn []string `json:"depends_on,omitempty"`
}

// Plan is the rendered execution plan.
type Plan struct {
	Runtime  string           `json:"runtime"`
	Services []ServicePlan    `json:"services"`
	Warnings []report.Finding `json:"warnings,omitempty"`
}

// BuildPlan builds run commands from a merged compose project.
func BuildPlan(project *compose.Project, opts Options) (Plan, error) {
	runtime := strings.TrimSpace(opts.Runtime)
	if runtime == "" {
		runtime = "docker"
	}
	if runtime != "docker" && runtime != "podman" {
		return Plan{}, fmt.Errorf("지원하지 않는 runtime %q (docker 또는 podman 사용)", runtime)
	}

	selected, err := selectServices(project, opts.TargetServices)
	if err != nil {
		return Plan{}, err
	}

	order, warnings := topologicalOrder(project, selected)
	plans := make([]ServicePlan, 0, len(order))

	for idx, name := range order {
		svc := project.Services[name]
		command, commandWarnings, err := renderService(runtime, project.Name, svc, opts)
		if err != nil {
			return Plan{}, err
		}
		warnings = append(warnings, commandWarnings...)
		plans = append(plans, ServicePlan{
			Name:      name,
			Order:     idx + 1,
			Command:   command,
			DependsOn: append([]string(nil), svc.DependsOn...),
		})
	}

	return Plan{Runtime: runtime, Services: plans, Warnings: warnings}, nil
}

func renderService(runtime, projectName string, svc *compose.Service, opts Options) (string, []report.Finding, error) {
	if svc.Image == "" {
		return "", nil, fmt.Errorf("service %q 에 image가 없습니다", svc.Name)
	}

	warnings := []report.Finding{}
	args := []string{runtime, "run", "-d"}

	containerName := strings.TrimSpace(svc.ContainerName)
	if containerName == "" {
		if strings.TrimSpace(projectName) != "" {
			containerName = fmt.Sprintf("%s-%s", projectName, svc.Name)
		} else {
			containerName = svc.Name
		}
	}
	args = append(args, "--name", containerName)

	if svc.Restart != "" {
		args = append(args, "--restart", svc.Restart)
	}
	if svc.WorkingDir != "" {
		args = append(args, "-w", svc.WorkingDir)
	}
	for _, envFile := range opts.ExtraEnvFiles {
		args = append(args, "--env-file", envFile)
	}
	for _, envFile := range svc.EnvFiles {
		args = append(args, "--env-file", envFile)
	}

	envKeys := make([]string, 0, len(svc.Environment))
	for key := range svc.Environment {
		envKeys = append(envKeys, key)
	}
	sort.Strings(envKeys)

	for _, key := range envKeys {
		env := svc.Environment[key]
		if env.HasValue && looksEnvRef(env.Value) {
			args = append(args, "-e", key)
			warnings = append(warnings, report.Finding{
				ID:             "env-ref-requires-runtime-value",
				Severity:       report.SeverityWarn,
				Service:        svc.Name,
				Field:          fmt.Sprintf("environment.%s", key),
				Message:        "compose 변수 참조값은 렌더된 커맨드에서 생략되었습니다",
				Recommendation: "실행 호스트에서 해당 변수를 export 한 뒤 스크립트를 실행하세요",
			})
			continue
		}
		if env.HasValue && sensitiveKeyPattern.MatchString(key) && !looksEnvRef(env.Value) {
			args = append(args, "-e", key)
			warnings = append(warnings, report.Finding{
				ID:             "sensitive-env-redacted",
				Severity:       report.SeverityWarn,
				Service:        svc.Name,
				Field:          fmt.Sprintf("environment.%s", key),
				Message:        "민감한 인라인 환경변수 값은 렌더된 커맨드에서 생략되었습니다",
				MaskedValue:    security.MaskValue(env.Value),
				Recommendation: "이 값은 SSH/세션 환경변수로 런타임 주입하세요",
			})
			continue
		}
		if env.HasValue {
			args = append(args, "-e", fmt.Sprintf("%s=%s", key, env.Value))
			continue
		}
		args = append(args, "-e", key)
	}

	for _, port := range svc.Ports {
		args = append(args, "-p", port)
	}
	for _, vol := range svc.Volumes {
		args = append(args, "-v", vol)
	}

	if len(svc.Networks) > 0 {
		args = append(args, "--network", svc.Networks[0])
		if len(svc.Networks) > 1 {
			warnings = append(warnings, report.Finding{
				ID:             "multi-network-truncated",
				Severity:       report.SeverityWarn,
				Service:        svc.Name,
				Field:          "networks",
				Message:        "복수 네트워크가 정의되어 첫 번째 네트워크만 docker/podman run 에 적용됩니다",
				Recommendation: "추가 네트워크는 runtime network connect 명령으로 수동 연결하세요",
			})
		}
	}

	if svc.Entrypoint.IsSet() {
		entry := commandSpecString(svc.Entrypoint)
		args = append(args, "--entrypoint", entry)
	}

	args = append(args, svc.Image)
	if svc.Command.IsSet() {
		if svc.Command.String != "" {
			args = append(args, svc.Command.String)
		} else {
			args = append(args, svc.Command.List...)
		}
	}

	quoted := make([]string, 0, len(args))
	for _, arg := range args {
		quoted = append(quoted, shellQuote(arg))
	}
	return strings.Join(quoted, " "), warnings, nil
}

func commandSpecString(spec compose.CommandSpec) string {
	if spec.String != "" {
		return spec.String
	}
	return strings.Join(spec.List, " ")
}

func looksEnvRef(v string) bool {
	trimmed := strings.TrimSpace(v)
	return strings.HasPrefix(trimmed, "${") || strings.Contains(trimmed, "$${")
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	if strings.IndexFunc(s, func(r rune) bool {
		switch r {
		case ' ', '\t', '\n', '\r', '\'', '"', '$', '`', '\\', '!', ';', '&', '|', '<', '>', '(', ')', '[', ']', '{', '}', '*', '?':
			return true
		default:
			return false
		}
	}) == -1 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

func selectServices(project *compose.Project, targets []string) (map[string]bool, error) {
	selected := map[string]bool{}
	if len(targets) == 0 {
		for name := range project.Services {
			selected[name] = true
		}
		return selected, nil
	}

	stack := append([]string(nil), targets...)
	for len(stack) > 0 {
		n := len(stack) - 1
		name := strings.TrimSpace(stack[n])
		stack = stack[:n]
		if name == "" {
			continue
		}
		svc, ok := project.Services[name]
		if !ok {
			return nil, fmt.Errorf("대상 서비스 %q 을(를) 찾을 수 없습니다", name)
		}
		if selected[name] {
			continue
		}
		selected[name] = true
		stack = append(stack, svc.DependsOn...)
	}
	return selected, nil
}

func topologicalOrder(project *compose.Project, selected map[string]bool) ([]string, []report.Finding) {
	warnings := []report.Finding{}
	indegree := map[string]int{}
	adj := map[string][]string{}

	for name := range selected {
		indegree[name] = 0
	}
	for name := range selected {
		svc := project.Services[name]
		for _, dep := range svc.DependsOn {
			if !selected[dep] {
				if _, exists := project.Services[dep]; !exists {
					warnings = append(warnings, report.Finding{
						ID:             "missing-dependency",
						Severity:       report.SeverityWarn,
						Service:        name,
						Field:          "depends_on",
						Message:        fmt.Sprintf("depends_on 대상 %q 이 services에 정의되어 있지 않습니다", dep),
						Recommendation: "의존성을 제거하거나 해당 서비스를 추가하세요",
					})
				}
				continue
			}
			adj[dep] = append(adj[dep], name)
			indegree[name]++
		}
	}

	queue := make([]string, 0)
	for name, d := range indegree {
		if d == 0 {
			queue = append(queue, name)
		}
	}
	sort.Strings(queue)

	order := make([]string, 0, len(selected))
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		order = append(order, name)

		nexts := append([]string(nil), adj[name]...)
		sort.Strings(nexts)
		for _, next := range nexts {
			indegree[next]--
			if indegree[next] == 0 {
				queue = append(queue, next)
				sort.Strings(queue)
			}
		}
	}

	if len(order) == len(selected) {
		return order, warnings
	}

	remaining := make([]string, 0)
	for name, d := range indegree {
		if d > 0 {
			remaining = append(remaining, name)
		}
	}
	sort.Strings(remaining)
	warnings = append(warnings, report.Finding{
		ID:             "dependency-cycle",
		Severity:       report.SeverityWarn,
		Field:          "depends_on",
		Message:        "depends_on 순환 의존이 감지되어 남은 서비스를 사전순으로 추가합니다",
		Recommendation: "결정적인 기동 순서를 위해 depends_on 순환을 해소하세요",
	})
	order = append(order, remaining...)
	return order, warnings
}
