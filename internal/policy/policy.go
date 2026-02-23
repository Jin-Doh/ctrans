package policy

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	DefaultPath                     = "configs/policy.default.yaml"
	defaultSensitiveKeyPatternExpr  = `(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key)`
	defaultSensitivePathPatternExpr = `(?i)(^|/)(id_rsa|id_ed25519|.*\\.pem|.*\\.key)$`
)

// Config describes runtime/scan/compose policy inputs.
type Config struct {
	Runtime RuntimeConfig `yaml:"runtime"`
	Secrets SecretsConfig `yaml:"secrets"`
	Compose ComposeConfig `yaml:"compose"`
}

type RuntimeConfig struct {
	Default   string   `yaml:"default"`
	Supported []string `yaml:"supported"`
}

type SecretsConfig struct {
	Mask                  bool     `yaml:"mask"`
	FailOn                string   `yaml:"fail_on"`
	SensitiveKeyPatterns  []string `yaml:"sensitive_key_patterns"`
	SensitivePathPatterns []string `yaml:"sensitive_path_patterns"`
	ScanEnvFiles          bool     `yaml:"scan_env_files"`
}

type ComposeConfig struct {
	DefaultCandidates []string `yaml:"default_candidates"`
	DefaultCollision  string   `yaml:"default_collision"`
}

type rawConfig struct {
	Runtime struct {
		Default   string   `yaml:"default"`
		Supported []string `yaml:"supported"`
	} `yaml:"runtime"`
	Secrets struct {
		Mask                  *bool    `yaml:"mask"`
		FailOn                string   `yaml:"fail_on"`
		SensitiveKeyPatterns  []string `yaml:"sensitive_key_patterns"`
		SensitivePathPatterns []string `yaml:"sensitive_path_patterns"`
		ScanEnvFiles          *bool    `yaml:"scan_env_files"`
	} `yaml:"secrets"`
	Compose struct {
		DefaultCandidates []string `yaml:"default_candidates"`
		DefaultCollision  string   `yaml:"default_collision"`
	} `yaml:"compose"`
}

func Default() Config {
	return Config{
		Runtime: RuntimeConfig{
			Default:   "docker",
			Supported: []string{"docker", "podman"},
		},
		Secrets: SecretsConfig{
			Mask:                  true,
			FailOn:                "error",
			SensitiveKeyPatterns:  []string{defaultSensitiveKeyPatternExpr},
			SensitivePathPatterns: []string{defaultSensitivePathPatternExpr},
			ScanEnvFiles:          true,
		},
		Compose: ComposeConfig{
			DefaultCandidates: []string{"docker-compose.yaml", "compose.yaml"},
			DefaultCollision:  "prefer_docker_compose_yaml",
		},
	}
}

func Load(path string) (Config, error) {
	cfg := Default()
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return cfg, nil
	}

	payload, err := os.ReadFile(trimmed)
	if err != nil {
		return cfg, fmt.Errorf("policy 파일 읽기 실패 %s: %w", trimmed, err)
	}

	var raw rawConfig
	if err := yaml.Unmarshal(payload, &raw); err != nil {
		return cfg, fmt.Errorf("policy yaml 파싱 실패 %s: %w", trimmed, err)
	}

	if s := strings.TrimSpace(raw.Runtime.Default); s != "" {
		cfg.Runtime.Default = s
	}
	if len(raw.Runtime.Supported) > 0 {
		cfg.Runtime.Supported = normalizeStringList(raw.Runtime.Supported)
	}

	if raw.Secrets.Mask != nil {
		cfg.Secrets.Mask = *raw.Secrets.Mask
	}
	if s := strings.TrimSpace(raw.Secrets.FailOn); s != "" {
		cfg.Secrets.FailOn = s
	}
	if len(raw.Secrets.SensitiveKeyPatterns) > 0 {
		cfg.Secrets.SensitiveKeyPatterns = normalizeStringList(raw.Secrets.SensitiveKeyPatterns)
	}
	if len(raw.Secrets.SensitivePathPatterns) > 0 {
		cfg.Secrets.SensitivePathPatterns = normalizeStringList(raw.Secrets.SensitivePathPatterns)
	}
	if raw.Secrets.ScanEnvFiles != nil {
		cfg.Secrets.ScanEnvFiles = *raw.Secrets.ScanEnvFiles
	}

	if len(raw.Compose.DefaultCandidates) > 0 {
		cfg.Compose.DefaultCandidates = normalizeStringList(raw.Compose.DefaultCandidates)
	}
	if s := strings.TrimSpace(raw.Compose.DefaultCollision); s != "" {
		cfg.Compose.DefaultCollision = s
	}

	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	supported := normalizeStringList(c.Runtime.Supported)
	if len(supported) == 0 {
		return fmt.Errorf("policy 검증 실패: runtime.supported 값이 비어 있습니다")
	}
	runtimeDefault := strings.TrimSpace(c.Runtime.Default)
	if runtimeDefault == "" {
		return fmt.Errorf("policy 검증 실패: runtime.default 값이 비어 있습니다")
	}
	if !contains(supported, runtimeDefault) {
		return fmt.Errorf("policy 검증 실패: runtime.default(%s)가 runtime.supported에 없습니다", runtimeDefault)
	}

	switch strings.TrimSpace(c.Secrets.FailOn) {
	case "none", "warn", "error":
	default:
		return fmt.Errorf("policy 검증 실패: secrets.fail_on 값은 none|warn|error 여야 합니다")
	}

	if len(c.Secrets.SensitiveKeyPatterns) == 0 {
		return fmt.Errorf("policy 검증 실패: secrets.sensitive_key_patterns 값이 비어 있습니다")
	}
	if len(c.Secrets.SensitivePathPatterns) == 0 {
		return fmt.Errorf("policy 검증 실패: secrets.sensitive_path_patterns 값이 비어 있습니다")
	}
	for _, p := range c.Secrets.SensitiveKeyPatterns {
		if _, err := regexp.Compile(p); err != nil {
			return fmt.Errorf("policy 검증 실패: invalid secrets.sensitive_key_patterns regex %q: %w", p, err)
		}
	}
	for _, p := range c.Secrets.SensitivePathPatterns {
		if _, err := regexp.Compile(p); err != nil {
			return fmt.Errorf("policy 검증 실패: invalid secrets.sensitive_path_patterns regex %q: %w", p, err)
		}
	}

	if len(c.Compose.DefaultCandidates) == 0 {
		return fmt.Errorf("policy 검증 실패: compose.default_candidates 값이 비어 있습니다")
	}
	if strings.TrimSpace(c.Compose.DefaultCollision) == "" {
		return fmt.Errorf("policy 검증 실패: compose.default_collision 값이 비어 있습니다")
	}
	if strings.TrimSpace(c.Compose.DefaultCollision) != "prefer_docker_compose_yaml" {
		return fmt.Errorf("policy 검증 실패: compose.default_collision 지원 값은 prefer_docker_compose_yaml 입니다")
	}

	return nil
}

func normalizeStringList(items []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(items))
	for _, item := range items {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

func contains(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
