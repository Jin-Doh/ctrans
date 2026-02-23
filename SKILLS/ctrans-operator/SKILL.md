---
name: ctrans-operator
description: Use /usr/local/bin/ctrans to scan, render, verify, and generate deploy plans from compose files, with JSON-first integration patterns for automation.
metadata:
  short-description: ctrans 실행/통합 스킬
---

# ctrans Operator

## 언제 사용하나

다음 요구가 있을 때 이 스킬을 사용한다.

- compose 파일을 `docker run`/`podman run` 명령으로 변환해야 할 때
- 배포 전 보안/지원 가능 여부 점검(`scan`, `verify`)이 필요할 때
- 자동화 파이프라인에서 JSON 파싱 가능한 결과(`decision`, `summary`)가 필요할 때

## 전제 조건

- `/usr/local/bin/ctrans` 바이너리가 이미 존재하고 실행 가능해야 한다.
- compose 파일 경로는 명시적으로 `-f`로 전달하거나, 기본 검색 규칙(`docker-compose.yaml`, `compose.yaml`)을 따른다.

## 기본 동작 규칙

- 서브커맨드 생략 시 기본 동작은 `render`다.
- 기본 정책은 `--fail-on error`다.
- 기본 정책 파일은 `configs/policy.default.yaml`이며, 필요 시 `--policy <path>`로 교체한다.
- 결과 판단 값은 항상 `final_status`, `can_proceed`, `recommended_action`, `fail_threshold`를 기준으로 해석한다.

## 표준 실행 절차

1. JSON 점검(파이프라인 친화)

```bash
/usr/local/bin/ctrans scan -f <compose-file> --format json --warnings off --fail-on none --policy configs/policy.default.yaml
```

2. 실행 스크립트 생성

```bash
/usr/local/bin/ctrans render -f <compose-file> --output script --fail-on none --allow-inline-sensitive off --policy configs/policy.default.yaml
```

3. 배포 계획(JSON) 생성

```bash
/usr/local/bin/ctrans deploy-plan -f <compose-file> --warnings off --fail-on none --policy configs/policy.default.yaml
```

4. 엄격 검증(차단 게이트)

```bash
/usr/local/bin/ctrans verify -f <compose-file> --strict --fail-on warn
```

## JSON 통합 규칙

자동화 파이프라인에서 파싱할 때는 다음 원칙을 따른다.

- 권장 플래그: `--warnings off --fail-on none`
- 파싱 대상 핵심 필드:
  - `summary.warn`
  - `summary.error`
  - `decision.final_status`
  - `decision.can_proceed`
  - `decision.recommended_action`

`--warnings off`를 사용하면 경고 상세 배열(`findings`, `plan.warnings`)이 빈 배열로 출력되며, 게이트 판정에는 `summary`와 `decision`을 사용한다.

## 결과 해석

- `final_status=ok`: 즉시 진행 가능
- `final_status=warn`: 진행 가능하나 권장 조치 반영 필요
- `final_status=blocked`: 현재 정책 기준 차단, 조치 후 재실행 필요

## Makefile 통합 예시

```bash
make deploy-plan COMPOSE_FILES="<compose-file>" WARNINGS=off FAIL_ON=none
```

```bash
make verify-compose COMPOSE_FILES="<compose-file>" FAIL_ON=warn STRICT=1
```

## 운영 가드레일

- 경고를 숨겨도(`--warnings off`) 차단 판단은 `summary`/`decision`으로 반드시 수행한다.
- 비밀값은 인라인으로 커밋하지 않고 런타임 환경변수 주입을 우선한다.
- `final_status=blocked` 상태에서 자동 배포를 진행하지 않는다.
