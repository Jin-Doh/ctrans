package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"compose_to_run/internal/compose"
	"compose_to_run/internal/report"
	"compose_to_run/internal/security"
	"compose_to_run/internal/transform"
)

type multiFlag []string

func (m *multiFlag) String() string {
	return strings.Join(*m, ",")
}

func (m *multiFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

type commonFlags struct {
	files       multiFlag
	envFiles    multiFlag
	runtime     string
	projectName string
	mask        string
	failOn      string
	warnings    string
}

type decision struct {
	FinalStatus       string `json:"final_status"`
	CanProceed        bool   `json:"can_proceed"`
	RecommendedAction string `json:"recommended_action"`
	FailThreshold     string `json:"fail_threshold"`
}

func main() {
	if len(os.Args) < 2 {
		printRootUsage()
		os.Exit(2)
	}

	args := os.Args[1:]
	if isRootHelp(args[0]) {
		printRootUsage()
		return
	}
	// 서브커맨드 없이 플래그만 전달되면 render를 기본 동작으로 사용한다.
	if strings.HasPrefix(args[0], "-") {
		args = append([]string{"render"}, args...)
	}

	var err error
	switch args[0] {
	case "scan":
		err = runScan(args[1:])
	case "render":
		err = runRender(args[1:])
	case "verify":
		err = runVerify(args[1:])
	case "deploy-plan":
		err = runDeployPlan(args[1:])
	default:
		err = fmt.Errorf("알 수 없는 서브커맨드: %s", args[0])
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var common commonFlags
	format := fs.String("format", "text", "출력 형식: text|json")
	registerCommonFlags(fs, &common)
	if err := fs.Parse(args); err != nil {
		return err
	}

	project, findings, err := loadAndScan(common)
	if err != nil {
		return err
	}
	showWarnings := parseWarnings(common.warnings)
	dec := buildDecision(findings, common.failOn)
	reportOut := security.Report{
		Files:    append([]string(nil), project.Files...),
		Findings: visibleFindings(findings, showWarnings),
		Summary:  report.BuildSummary(findings),
	}

	switch strings.ToLower(*format) {
	case "json":
		out := struct {
			Files    []string         `json:"files"`
			Findings []report.Finding `json:"findings"`
			Summary  report.Summary   `json:"summary"`
			Decision decision         `json:"decision"`
		}{
			Files:    reportOut.Files,
			Findings: reportOut.Findings,
			Summary:  reportOut.Summary,
			Decision: dec,
		}
		if err := writeJSON(os.Stdout, out); err != nil {
			return err
		}
	case "text":
		printFindingsText(reportOut.Files, findings, dec, showWarnings)
	default:
		return fmt.Errorf("지원하지 않는 --format 값: %q", *format)
	}

	if report.Fail(findings, common.failOn) {
		return errors.New("scan 결과가 fail-on 임계치를 초과했습니다")
	}
	return nil
}

func runRender(args []string) error {
	fs := flag.NewFlagSet("render", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var common commonFlags
	output := fs.String("output", "script", "render 출력 형식: script|json")
	outPath := fs.String("out", "", "선택 출력 파일 경로")
	registerCommonFlags(fs, &common)
	if err := fs.Parse(args); err != nil {
		return err
	}

	project, findings, err := loadAndScan(common)
	if err != nil {
		return err
	}
	showWarnings := parseWarnings(common.warnings)

	plan, err := transform.BuildPlan(project, transform.Options{
		Runtime:       common.runtime,
		ProjectName:   common.projectName,
		Mask:          parseMask(common.mask),
		ExtraEnvFiles: common.envFiles,
	})
	if err != nil {
		return err
	}
	findings = append(findings, plan.Warnings...)
	dec := buildDecision(findings, common.failOn)
	if report.Fail(findings, common.failOn) {
		printFindingsText(project.Files, findings, dec, showWarnings)
		return errors.New("render 결과가 fail-on 임계치를 초과했습니다")
	}

	switch strings.ToLower(*output) {
	case "script":
		content := renderScript(plan, findings, dec, showWarnings)
		if *outPath != "" {
			if err := os.WriteFile(*outPath, []byte(content), 0o755); err != nil {
				return fmt.Errorf("write --out file: %w", err)
			}
			fmt.Fprintf(os.Stdout, "스크립트 파일 생성 완료: %s\n", *outPath)
			printDecisionText(dec)
			return nil
		}
		fmt.Fprintln(os.Stdout, content)
		return nil
	case "json":
		planOut := plan
		planOut.Warnings = visibleFindings(plan.Warnings, showWarnings)
		out := struct {
			Plan           transform.Plan  `json:"plan"`
			SecurityReport security.Report `json:"security_report"`
			Decision       decision        `json:"decision"`
		}{
			Plan: planOut,
			SecurityReport: security.Report{
				Files:    append([]string(nil), project.Files...),
				Findings: visibleFindings(findings, showWarnings),
				Summary:  report.BuildSummary(findings),
			},
			Decision: dec,
		}
		if *outPath != "" {
			payload, err := json.MarshalIndent(out, "", "  ")
			if err != nil {
				return err
			}
			payload = append(payload, '\n')
			if err := os.WriteFile(*outPath, payload, 0o644); err != nil {
				return fmt.Errorf("write --out file: %w", err)
			}
			fmt.Fprintf(os.Stdout, "JSON 계획 파일 생성 완료: %s\n", *outPath)
			return nil
		}
		return writeJSON(os.Stdout, out)
	default:
		return fmt.Errorf("지원하지 않는 --output 값: %q", *output)
	}
}

func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var common commonFlags
	strict := fs.Bool("strict", false, "경고를 오류로 승격")
	registerCommonFlags(fs, &common)
	if err := fs.Parse(args); err != nil {
		return err
	}

	project, findings, err := loadAndScan(common)
	if err != nil {
		return err
	}
	showWarnings := parseWarnings(common.warnings)
	plan, err := transform.BuildPlan(project, transform.Options{
		Runtime:       common.runtime,
		ProjectName:   common.projectName,
		Mask:          parseMask(common.mask),
		ExtraEnvFiles: common.envFiles,
	})
	if err != nil {
		return err
	}
	findings = append(findings, plan.Warnings...)
	if *strict {
		findings = security.PromoteWarningsToErrors(findings)
	}
	dec := buildDecision(findings, common.failOn)

	printFindingsText(project.Files, findings, dec, showWarnings)
	if report.Fail(findings, common.failOn) {
		return errors.New("verify 결과가 fail-on 임계치를 초과했습니다")
	}
	return nil
}

func runDeployPlan(args []string) error {
	fs := flag.NewFlagSet("deploy-plan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var common commonFlags
	targetService := fs.String("target-service", "", "대상 서비스 목록(쉼표 구분)")
	outPath := fs.String("out", "", "선택 출력 파일 경로")
	registerCommonFlags(fs, &common)
	if err := fs.Parse(args); err != nil {
		return err
	}

	project, findings, err := loadAndScan(common)
	if err != nil {
		return err
	}
	showWarnings := parseWarnings(common.warnings)

	plan, err := transform.BuildPlan(project, transform.Options{
		Runtime:        common.runtime,
		ProjectName:    common.projectName,
		Mask:           parseMask(common.mask),
		TargetServices: splitCSV(*targetService),
		ExtraEnvFiles:  common.envFiles,
	})
	if err != nil {
		return err
	}
	findings = append(findings, plan.Warnings...)
	dec := buildDecision(findings, common.failOn)
	if report.Fail(findings, common.failOn) {
		printFindingsText(project.Files, findings, dec, showWarnings)
		return errors.New("deploy-plan 결과가 fail-on 임계치를 초과했습니다")
	}
	planOut := plan
	planOut.Warnings = visibleFindings(plan.Warnings, showWarnings)

	out := struct {
		Plan     transform.Plan   `json:"plan"`
		Findings []report.Finding `json:"findings,omitempty"`
		Summary  report.Summary   `json:"summary"`
		Decision decision         `json:"decision"`
	}{
		Plan:     planOut,
		Findings: visibleFindings(findings, showWarnings),
		Summary:  report.BuildSummary(findings),
		Decision: dec,
	}

	if *outPath != "" {
		payload, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return err
		}
		payload = append(payload, '\n')
		if err := os.WriteFile(*outPath, payload, 0o644); err != nil {
			return fmt.Errorf("write --out file: %w", err)
		}
		fmt.Fprintf(os.Stdout, "배포 계획 파일 생성 완료: %s\n", *outPath)
		return nil
	}

	return writeJSON(os.Stdout, out)
}

func registerCommonFlags(fs *flag.FlagSet, common *commonFlags) {
	common.runtime = "docker"
	common.mask = "on"
	common.failOn = "error"
	common.warnings = "on"
	fs.Var(&common.files, "f", "compose 파일 경로 (반복 가능, 지정 순서로 병합)")
	fs.Var(&common.files, "file", "compose 파일 경로 (반복 가능, 지정 순서로 병합)")
	fs.Var(&common.envFiles, "env", "추가 env-file 경로 (반복 가능)")
	fs.StringVar(&common.runtime, "runtime", "docker", "런타임: docker|podman")
	fs.StringVar(&common.projectName, "project-name", "", "컨테이너 이름 prefix용 프로젝트 이름")
	fs.StringVar(&common.mask, "mask", "on", "민감값 마스킹: on|off")
	fs.StringVar(&common.failOn, "fail-on", "error", "실패 임계치: none|warn|error")
	fs.StringVar(&common.warnings, "warnings", "on", "경고 상세 출력: on|off")
}

func loadAndScan(common commonFlags) (*compose.Project, []report.Finding, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, nil, fmt.Errorf("resolve cwd: %w", err)
	}
	project, loadWarnings, err := compose.Load(common.files, cwd)
	if err != nil {
		return nil, nil, err
	}

	scan := security.Scan(project, loadWarnings, security.Config{Mask: parseMask(common.mask)})
	return project, scan.Findings, nil
}

func parseMask(mask string) bool {
	switch strings.ToLower(strings.TrimSpace(mask)) {
	case "off", "false", "0":
		return false
	default:
		return true
	}
}

func parseWarnings(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "off", "false", "0":
		return false
	default:
		return true
	}
}

func splitCSV(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func renderScript(plan transform.Plan, findings []report.Finding, dec decision, showWarnings bool) string {
	lines := []string{
		"#!/usr/bin/env bash",
		"set -euo pipefail",
		"",
		fmt.Sprintf("# ctrans 생성 스크립트 (runtime=%s)", plan.Runtime),
		"# 최종 판단:",
		fmt.Sprintf("# final_status: %s", dec.FinalStatus),
		fmt.Sprintf("# can_proceed: %t", dec.CanProceed),
		fmt.Sprintf("# recommended_action: %s", dec.RecommendedAction),
		fmt.Sprintf("# fail_threshold: %s", dec.FailThreshold),
	}
	if showWarnings && len(findings) > 0 {
		lines = append(lines, "# 경고/오류 목록:")
		for _, f := range findings {
			lines = append(lines, "# - "+f.String())
		}
	} else if len(findings) > 0 {
		lines = append(lines, "# 경고/오류 상세는 --warnings off 로 숨김 처리되었습니다")
	}
	lines = append(lines, "")

	sortedPlans := append([]transform.ServicePlan(nil), plan.Services...)
	sort.Slice(sortedPlans, func(i, j int) bool {
		return sortedPlans[i].Order < sortedPlans[j].Order
	})
	for _, svc := range sortedPlans {
		lines = append(lines, fmt.Sprintf("# 서비스: %s", svc.Name))
		lines = append(lines, svc.Command)
		lines = append(lines, "")
	}
	return strings.Join(lines, "\n")
}

func printFindingsText(files []string, findings []report.Finding, dec decision, showWarnings bool) {
	fmt.Fprintf(os.Stdout, "files: %s\n", strings.Join(files, ", "))
	summary := report.BuildSummary(findings)
	fmt.Fprintf(os.Stdout, "summary: warn=%d error=%d\n", summary.Warn, summary.Error)
	if showWarnings {
		for _, f := range findings {
			fmt.Fprintf(os.Stdout, "- %s\n", f.String())
		}
	} else if len(findings) > 0 {
		fmt.Fprintln(os.Stdout, "- 경고/오류 상세 출력이 비활성화되었습니다 (--warnings off)")
	}
	printDecisionText(dec)
}

func printDecisionText(dec decision) {
	fmt.Fprintf(os.Stdout, "final_status: %s\n", dec.FinalStatus)
	fmt.Fprintf(os.Stdout, "can_proceed: %t\n", dec.CanProceed)
	fmt.Fprintf(os.Stdout, "recommended_action: %s\n", dec.RecommendedAction)
	fmt.Fprintf(os.Stdout, "fail_threshold: %s\n", dec.FailThreshold)
}

func writeJSON(target *os.File, value any) error {
	encoder := json.NewEncoder(target)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func printRootUsage() {
	fmt.Fprintln(os.Stderr, "ctrans: compose 스캔 및 compose-to-run 변환 도구")
	fmt.Fprintln(os.Stderr, "usage: ctrans <scan|render|verify|deploy-plan> [options]")
	fmt.Fprintln(os.Stderr, "       ctrans [render options]   # 서브커맨드 생략 시 render 기본 동작")
	fmt.Fprintln(os.Stderr, "공통 옵션: -f <file>(반복 가능), --runtime docker|podman, --fail-on none|warn|error, --warnings on|off")
	fmt.Fprintln(os.Stderr, "결과 값: final_status(ok|warn|blocked), can_proceed(true|false)")
	fmt.Fprintln(os.Stderr, "fail-on 정책: none=차단 없음, error=오류 시 차단, warn=경고/오류 시 차단")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "명령 설명:")
	fmt.Fprintln(os.Stderr, "  scan        : compose 파일의 보안/지원 여부를 점검합니다")
	fmt.Fprintln(os.Stderr, "  render      : compose를 docker/podman run 스크립트/JSON으로 변환합니다")
	fmt.Fprintln(os.Stderr, "  verify      : scan + render 결과를 정책(fail-on, strict) 기준으로 검증합니다")
	fmt.Fprintln(os.Stderr, "  deploy-plan : 대상 서비스 기준 실행 계획(JSON)을 생성합니다")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "실무 예시:")
	fmt.Fprintln(os.Stderr, "  ctrans render -f compose.yaml")
	fmt.Fprintln(os.Stderr, "  ctrans scan -f compose.yaml --format json --warnings off --fail-on none")
	fmt.Fprintln(os.Stderr, "  ctrans deploy-plan -f compose.yaml --target-service app --warnings off --fail-on none")
}

func isRootHelp(arg string) bool {
	switch arg {
	case "help", "-h", "--help":
		return true
	default:
		return false
	}
}

func normalizeFailThreshold(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "none":
		return "none"
	case "warn":
		return "warn"
	default:
		return "error"
	}
}

func buildDecision(findings []report.Finding, failOn string) decision {
	threshold := normalizeFailThreshold(failOn)
	summary := report.BuildSummary(findings)
	blocked := report.Fail(findings, threshold)
	recs := collectRecommendations(findings, 2)

	if blocked {
		msg := "findings를 해결하거나 fail-on 정책을 완화한 뒤 다시 실행하세요"
		if len(recs) > 0 {
			msg = "진행 전 조치 필요: " + strings.Join(recs, "; ")
		}
		return decision{
			FinalStatus:       "blocked",
			CanProceed:        false,
			RecommendedAction: msg,
			FailThreshold:     threshold,
		}
	}

	if summary.Warn > 0 {
		msg := "경고 내용을 확인하고 권장 조치를 반영한 뒤 진행하세요"
		if len(recs) > 0 {
			msg = "주의 후 진행: " + strings.Join(recs, "; ")
		}
		return decision{
			FinalStatus:       "warn",
			CanProceed:        true,
			RecommendedAction: msg,
			FailThreshold:     threshold,
		}
	}

	return decision{
		FinalStatus:       "ok",
		CanProceed:        true,
		RecommendedAction: "생성된 결과를 그대로 실행해도 됩니다",
		FailThreshold:     threshold,
	}
}

func collectRecommendations(findings []report.Finding, limit int) []string {
	if limit <= 0 {
		return nil
	}
	seen := map[string]struct{}{}
	recs := make([]string, 0, limit)
	for _, f := range findings {
		rec := strings.TrimSpace(f.Recommendation)
		if rec == "" {
			continue
		}
		if _, ok := seen[rec]; ok {
			continue
		}
		seen[rec] = struct{}{}
		recs = append(recs, rec)
		if len(recs) >= limit {
			return recs
		}
	}
	return recs
}

func visibleFindings(findings []report.Finding, showWarnings bool) []report.Finding {
	if !showWarnings {
		return []report.Finding{}
	}
	if len(findings) == 0 {
		return []report.Finding{}
	}
	out := make([]report.Finding, 0, len(findings))
	out = append(out, findings...)
	return out
}
