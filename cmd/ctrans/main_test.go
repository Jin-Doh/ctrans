package main

import (
	"encoding/json"
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"compose_to_run/internal/report"
	"compose_to_run/internal/transform"
)

func TestMultiFlagAndHelpers(t *testing.T) {
	var mf multiFlag
	if err := mf.Set("a"); err != nil {
		t.Fatalf("Set returned error: %v", err)
	}
	if err := mf.Set("b"); err != nil {
		t.Fatalf("Set returned error: %v", err)
	}
	if mf.String() != "a,b" {
		t.Fatalf("unexpected multiFlag string: %s", mf.String())
	}

	if !parseMask("on") || parseMask("off") || parseMask("false") || parseMask("0") {
		t.Fatalf("unexpected parseMask behavior")
	}
	if parseMask("weird") != true {
		t.Fatalf("unexpected default parseMask behavior")
	}
	if !parseWarnings("on") || parseWarnings("off") || parseWarnings("false") || parseWarnings("0") {
		t.Fatalf("unexpected parseWarnings behavior")
	}
	if parseWarnings("weird") != true {
		t.Fatalf("unexpected default parseWarnings behavior")
	}
	if !parseAllowInlineSensitive("on") || !parseAllowInlineSensitive("true") || parseAllowInlineSensitive("off") {
		t.Fatalf("unexpected parseAllowInlineSensitive behavior")
	}

	csv := splitCSV("a, b,,c")
	if len(csv) != 3 || csv[1] != "b" {
		t.Fatalf("unexpected splitCSV result: %v", csv)
	}
	if splitCSV("   ") != nil {
		t.Fatalf("blank splitCSV should return nil")
	}
}

func TestDecisionHelpers(t *testing.T) {
	if got := normalizeFailThreshold("none"); got != "none" {
		t.Fatalf("unexpected fail threshold normalize result: %s", got)
	}
	if got := normalizeFailThreshold("warn"); got != "warn" {
		t.Fatalf("unexpected fail threshold normalize result: %s", got)
	}
	if got := normalizeFailThreshold("weird"); got != "error" {
		t.Fatalf("unexpected fail threshold normalize default: %s", got)
	}

	findings := []report.Finding{
		{Severity: report.SeverityWarn, Recommendation: "rec1"},
		{Severity: report.SeverityWarn, Recommendation: "rec1"},
		{Severity: report.SeverityError, Recommendation: "rec2"},
	}
	recs := collectRecommendations(findings, 2)
	if len(recs) != 2 || recs[0] != "rec1" || recs[1] != "rec2" {
		t.Fatalf("unexpected recommendation collection: %v", recs)
	}

	d1 := buildDecision(nil, "error")
	if d1.FinalStatus != "ok" || !d1.CanProceed {
		t.Fatalf("unexpected ok decision: %+v", d1)
	}

	d2 := buildDecision([]report.Finding{{Severity: report.SeverityWarn, Recommendation: "do this"}}, "error")
	if d2.FinalStatus != "warn" || !d2.CanProceed || !strings.Contains(d2.RecommendedAction, "do this") {
		t.Fatalf("unexpected warn decision: %+v", d2)
	}

	d3 := buildDecision([]report.Finding{{Severity: report.SeverityWarn, Recommendation: "do this"}}, "warn")
	if d3.FinalStatus != "blocked" || d3.CanProceed {
		t.Fatalf("unexpected blocked decision: %+v", d3)
	}
}

func TestRenderScriptSortsByOrder(t *testing.T) {
	plan := transform.Plan{
		Runtime: "docker",
		Warnings: []report.Finding{{
			Severity: report.SeverityWarn,
			Message:  "warn",
		}},
		Services: []transform.ServicePlan{
			{Name: "b", Order: 2, Command: "echo b"},
			{Name: "a", Order: 1, Command: "echo a"},
		},
	}

	script := renderScript(plan, []report.Finding{{Severity: report.SeverityWarn, Message: "warn"}}, decision{
		FinalStatus:       "warn",
		CanProceed:        true,
		RecommendedAction: "do something",
		FailThreshold:     "error",
	}, true)
	if !strings.Contains(script, "# 경고/오류 목록:") {
		t.Fatalf("expected warnings section")
	}
	if !strings.Contains(script, "# final_status: warn") {
		t.Fatalf("expected decision section in script: %s", script)
	}
	if strings.Index(script, "# 서비스: a") > strings.Index(script, "# 서비스: b") {
		t.Fatalf("expected services sorted by order: %s", script)
	}
}

func TestPrintAndUsageFunctions(t *testing.T) {
	stdout := captureFileOutput(t, true, func() {
		printFindingsText(
			[]string{"a.yaml"},
			[]report.Finding{{Severity: report.SeverityWarn, Message: "w"}},
			decision{FinalStatus: "warn", CanProceed: true, RecommendedAction: "fix", FailThreshold: "error"},
			true,
		)
	})
	if !strings.Contains(stdout, "summary: warn=1 error=0") {
		t.Fatalf("unexpected findings output: %s", stdout)
	}
	if !strings.Contains(stdout, "final_status: warn") {
		t.Fatalf("expected decision output in findings text: %s", stdout)
	}

	stderr := captureFileOutput(t, false, func() {
		printRootUsage()
	})
	if !strings.Contains(stderr, "usage: ctrans") {
		t.Fatalf("unexpected usage output: %s", stderr)
	}
}

func TestWriteJSON(t *testing.T) {
	file := filepath.Join(t.TempDir(), "out.json")
	fp, err := os.Create(file)
	if err != nil {
		t.Fatalf("create file: %v", err)
	}
	if err := writeJSON(fp, map[string]string{"a": "b"}); err != nil {
		t.Fatalf("writeJSON error: %v", err)
	}
	if err := fp.Close(); err != nil {
		t.Fatalf("close file: %v", err)
	}

	payload, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	var decoded map[string]string
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if decoded["a"] != "b" {
		t.Fatalf("unexpected payload: %v", decoded)
	}
}

func TestRunScanAndVerify(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "compose.yaml"), `services:
  app:
    image: nginx
    environment:
      DB_PASSWORD: plain
`)

	withDir(t, dir, func() {
		scanJSON := captureFileOutput(t, true, func() {
			if err := runScan([]string{"--format", "json", "--fail-on", "none"}); err != nil {
				t.Fatalf("runScan should succeed: %v", err)
			}
		})
		if !strings.Contains(scanJSON, "\"decision\"") || !strings.Contains(scanJSON, "\"final_status\": \"warn\"") {
			t.Fatalf("expected decision payload in scan json output: %s", scanJSON)
		}
		scanJSONNoWarn := captureFileOutput(t, true, func() {
			if err := runScan([]string{"--format", "json", "--warnings", "off", "--fail-on", "none"}); err != nil {
				t.Fatalf("runScan should succeed with warnings off: %v", err)
			}
		})
		var scanOut struct {
			Decision map[string]any   `json:"decision"`
			Findings []report.Finding `json:"findings"`
		}
		if err := json.Unmarshal([]byte(scanJSONNoWarn), &scanOut); err != nil {
			t.Fatalf("scan json unmarshal failed: %v, payload=%s", err, scanJSONNoWarn)
		}
		if scanOut.Decision == nil || len(scanOut.Findings) != 0 {
			t.Fatalf("expected decision present and findings hidden, got: %+v", scanOut)
		}
		if err := runScan([]string{"--format", "unknown"}); err == nil {
			t.Fatalf("runScan should fail for unsupported format")
		}
		if err := runScan([]string{"--fail-on", "warn"}); err == nil {
			t.Fatalf("runScan should fail on warn threshold")
		}

		if err := runVerify([]string{"--fail-on", "none"}); err != nil {
			t.Fatalf("runVerify should succeed with fail-on none: %v", err)
		}
		if err := runVerify([]string{"--strict", "--fail-on", "error"}); err == nil {
			t.Fatalf("runVerify strict should fail by promoted warning")
		}
	})
}

func TestRunRender(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.yaml")
	override := filepath.Join(dir, "override.yaml")
	mustWrite(t, base, `name: demo
services:
  app:
    image: nginx
    environment:
      SECRET_TOKEN: plain
`)
	mustWrite(t, override, `services:
  app:
    image: nginx:stable
`)

	withDir(t, dir, func() {
		scriptOut := filepath.Join(dir, "deploy.sh")
		err := runRender([]string{"-f", base, "-f", override, "--output", "script", "--out", scriptOut, "--fail-on", "none", "--env", ".env.shared"})
		if err != nil {
			t.Fatalf("runRender script should succeed: %v", err)
		}
		content, err := os.ReadFile(scriptOut)
		if err != nil {
			t.Fatalf("read render script: %v", err)
		}
		if !strings.Contains(string(content), "--env-file .env.shared") {
			t.Fatalf("expected extra env file in script: %s", string(content))
		}

		jsonOut := filepath.Join(dir, "plan.json")
		err = runRender([]string{"-f", base, "--output", "json", "--out", jsonOut, "--warnings", "off", "--fail-on", "none"})
		if err != nil {
			t.Fatalf("runRender json should succeed: %v", err)
		}
		payload, err := os.ReadFile(jsonOut)
		if err != nil {
			t.Fatalf("expected json output file: %v", err)
		}
		if !strings.Contains(string(payload), "\"decision\"") {
			t.Fatalf("expected decision in render json output: %s", string(payload))
		}
		var renderOut struct {
			Plan struct {
				Warnings []report.Finding `json:"warnings"`
			} `json:"plan"`
			SecurityReport struct {
				Findings []report.Finding `json:"findings"`
			} `json:"security_report"`
		}
		if err := json.Unmarshal(payload, &renderOut); err != nil {
			t.Fatalf("render json unmarshal failed: %v, payload=%s", err, string(payload))
		}
		if len(renderOut.Plan.Warnings) != 0 || len(renderOut.SecurityReport.Findings) != 0 {
			t.Fatalf("expected warnings/findings hidden in render json output: %+v", renderOut)
		}

		if err := runRender([]string{"-f", base, "--output", "unknown", "--fail-on", "none"}); err == nil {
			t.Fatalf("runRender should fail for unsupported output")
		}
		if err := runRender([]string{"-f", base, "--output", "script", "--out", dir, "--fail-on", "none"}); err == nil {
			t.Fatalf("runRender should fail when --out points to directory")
		}
		if err := runRender([]string{"-f", base, "--output", "script", "--fail-on", "warn"}); err == nil {
			t.Fatalf("runRender should fail when findings exceed warn threshold")
		}
	})
}

func TestRunDeployPlan(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "compose.yaml")
	mustWrite(t, path, `services:
  db:
    image: postgres:16
  app:
    image: nginx
    environment:
      TZ: ${TIMEZONE:-Asia/Seoul}
    depends_on:
      - db
`)

	withDir(t, dir, func() {
		out := filepath.Join(dir, "deploy-plan.json")
		err := runDeployPlan([]string{"--fail-on", "none", "--warnings", "off", "--target-service", "app", "--out", out})
		if err != nil {
			t.Fatalf("runDeployPlan should succeed: %v", err)
		}
		payload, err := os.ReadFile(out)
		if err != nil {
			t.Fatalf("read deploy-plan file: %v", err)
		}
		if !strings.Contains(string(payload), "\"plan\"") || !strings.Contains(string(payload), "\"decision\"") {
			t.Fatalf("unexpected deploy-plan payload: %s", string(payload))
		}
		var deployOut struct {
			Plan struct {
				Warnings []report.Finding `json:"warnings"`
			} `json:"plan"`
			Findings []report.Finding `json:"findings"`
		}
		if err := json.Unmarshal(payload, &deployOut); err != nil {
			t.Fatalf("deploy-plan json unmarshal failed: %v, payload=%s", err, string(payload))
		}
		if len(deployOut.Plan.Warnings) != 0 || len(deployOut.Findings) != 0 {
			t.Fatalf("expected warnings/findings hidden in deploy-plan output: %+v", deployOut)
		}

		if err := runDeployPlan([]string{"--target-service", "missing", "--fail-on", "none"}); err == nil {
			t.Fatalf("runDeployPlan should fail for missing target")
		}
		if err := runDeployPlan([]string{"--out", dir, "--fail-on", "none"}); err == nil {
			t.Fatalf("runDeployPlan should fail when --out points to directory")
		}
	})
}

func TestLoadAndScanAndRegisterFlags(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "compose.yaml")
	mustWrite(t, path, `services:
  app:
    image: nginx
`)

	withDir(t, dir, func() {
		project, findings, _, err := loadAndScan(commonFlags{files: multiFlag{"compose.yaml"}, mask: "on"})
		if err != nil {
			t.Fatalf("loadAndScan should succeed: %v", err)
		}
		if len(project.Services) != 1 || findings == nil {
			t.Fatalf("unexpected loadAndScan result: services=%d findings=%v", len(project.Services), findings)
		}
	})

	var cf commonFlags
	fs := flagSetForTest()
	registerCommonFlags(fs, &cf)
	if err := fs.Parse([]string{"-f", "a.yaml", "--env", ".env", "--runtime", "podman", "--project-name", "demo", "--mask", "off", "--warnings", "off", "--fail-on", "warn", "--policy", "custom-policy.yaml", "--allow-inline-sensitive", "on"}); err != nil {
		t.Fatalf("flag parse failed: %v", err)
	}
	if len(cf.files) != 1 || len(cf.envFiles) != 1 || cf.runtime != "podman" || cf.projectName != "demo" || cf.mask != "off" || cf.warnings != "off" || cf.failOn != "warn" || cf.policyPath != "custom-policy.yaml" || cf.allowInlineSensitive != "on" {
		t.Fatalf("unexpected common flags parse: %+v", cf)
	}
}

func TestLoadPolicyFallbackAndExplicitWarning(t *testing.T) {
	dir := t.TempDir()

	cfg, warnings, err := loadPolicy(dir, "")
	if err != nil {
		t.Fatalf("loadPolicy fallback should not fail: %v", err)
	}
	if cfg.Runtime.Default == "" {
		t.Fatalf("expected fallback default policy")
	}
	if len(warnings) != 0 {
		t.Fatalf("implicit default path missing should not emit warning, got %+v", warnings)
	}

	cfg, warnings, err = loadPolicy(dir, "custom.yaml")
	if err != nil {
		t.Fatalf("loadPolicy explicit missing should fallback with warning: %v", err)
	}
	if cfg.Runtime.Default == "" || len(warnings) != 1 || warnings[0].ID != "policy-file-missing" {
		t.Fatalf("unexpected explicit missing policy result: cfg=%+v warnings=%+v", cfg, warnings)
	}

	invalid := filepath.Join(dir, "invalid.yaml")
	mustWrite(t, invalid, "runtime: [")
	if _, _, err := loadPolicy(dir, invalid); err == nil {
		t.Fatalf("invalid policy yaml should return error")
	}
}

func TestSubcommandHelpReturnsNil(t *testing.T) {
	if err := runScan([]string{"--help"}); err != nil {
		t.Fatalf("runScan --help should not fail: %v", err)
	}
	if err := runRender([]string{"--help"}); err != nil {
		t.Fatalf("runRender --help should not fail: %v", err)
	}
	if err := runVerify([]string{"--help"}); err != nil {
		t.Fatalf("runVerify --help should not fail: %v", err)
	}
	if err := runDeployPlan([]string{"--help"}); err != nil {
		t.Fatalf("runDeployPlan --help should not fail: %v", err)
	}
}

func captureFileOutput(t *testing.T, stdout bool, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	if stdout {
		old := os.Stdout
		os.Stdout = w
		defer func() { os.Stdout = old }()
	} else {
		old := os.Stderr
		os.Stderr = w
		defer func() { os.Stderr = old }()
	}

	fn()
	if err := w.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	payload, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read pipe: %v", err)
	}
	return string(payload)
}

func withDir(t *testing.T, dir string, fn func()) {
	t.Helper()
	old, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir temp dir: %v", err)
	}
	defer func() {
		_ = os.Chdir(old)
	}()
	fn()
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func flagSetForTest() *flag.FlagSet {
	return flag.NewFlagSet("test", flag.ContinueOnError)
}

func TestMainHelperProcess(t *testing.T) {
	if os.Getenv("CTRANS_TEST_HELPER_PROCESS") != "1" {
		return
	}
	raw := os.Getenv("CTRANS_TEST_ARGS")
	args := []string{}
	if raw != "" {
		args = strings.Split(raw, "\x1f")
	}
	os.Args = append([]string{"ctrans"}, args...)
	main()
	os.Exit(0)
}

func TestMainEntrypoints(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "compose.yaml"), `services:
  app:
    image: nginx
`)

	tests := []struct {
		name      string
		args      []string
		wantCode  int
		wantInOut string
	}{
		{name: "no args", args: nil, wantCode: 2, wantInOut: "usage: ctrans"},
		{name: "help", args: []string{"help"}, wantCode: 0, wantInOut: "usage: ctrans"},
		{name: "help flag", args: []string{"--help"}, wantCode: 0, wantInOut: "usage: ctrans"},
		{name: "render help", args: []string{"render", "--help"}, wantCode: 0, wantInOut: "Usage of render:"},
		{name: "scan help", args: []string{"scan", "--help"}, wantCode: 0, wantInOut: "Usage of scan:"},
		{name: "unknown", args: []string{"unknown"}, wantCode: 1, wantInOut: "알 수 없는 서브커맨드"},
		{name: "scan ok", args: []string{"scan", "--fail-on", "none"}, wantCode: 0, wantInOut: "summary:"},
		{name: "implicit render from flags", args: []string{"-f", "compose.yaml", "--fail-on", "none"}, wantCode: 0, wantInOut: "#!/usr/bin/env bash"},
		{name: "scan bad format", args: []string{"scan", "--format", "bad"}, wantCode: 1, wantInOut: "지원하지 않는 --format 값"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, output := runMainSubprocess(t, dir, tc.args...)
			if code != tc.wantCode {
				t.Fatalf("unexpected exit code: got=%d want=%d output=%s", code, tc.wantCode, output)
			}
			if !strings.Contains(output, tc.wantInOut) {
				t.Fatalf("expected output to contain %q, got %s", tc.wantInOut, output)
			}
		})
	}
}

func runMainSubprocess(t *testing.T, dir string, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=TestMainHelperProcess")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"CTRANS_TEST_HELPER_PROCESS=1",
		"CTRANS_TEST_ARGS="+strings.Join(args, "\x1f"),
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return 0, string(out)
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode(), string(out)
	}
	t.Fatalf("failed to run subprocess: %v", err)
	return 1, string(out)
}
