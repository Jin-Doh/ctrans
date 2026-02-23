# ctrans (compose-to-run)

`ctrans` scans compose files for secret exposure risks and renders `docker run` or `podman run` commands for local+SSH deployment flows.

## Features

- Repeatable `-f/--file` compose inputs (ordered override merge)
- Default file lookup when no `-f` is provided:
  - `docker-compose.yaml`
  - `compose.yaml`
- Collision rule when both defaults exist:
  - Use `docker-compose.yaml`
  - Emit warning for `compose.yaml`
- Secret-oriented scan:
  - sensitive env keys
  - private key path mounts
  - suspicious env file names
- Final decision output for every command:
  - `final_status`: `ok | warn | blocked`
  - `can_proceed`: `true | false`
  - `recommended_action`
  - `fail_threshold`
- Render `run` command plan in script or JSON
- Makefile + git hooks integration

## Build/Test

```bash
make test
make build
make coverage-gate THRESHOLD=90
```

## CLI

```bash
# Subcommand 생략 시 기본 동작은 render
go run ./cmd/ctrans -f examples/compose/base.yaml

# Scan (text)
go run ./cmd/ctrans scan -f examples/compose/base.yaml
# => final_status / can_proceed / recommended_action / fail_threshold 출력

# Scan (json)
go run ./cmd/ctrans scan -f examples/compose/base.yaml --format json
# => JSON 루트에 decision 필드 포함

# Scan (json, 경고 상세 숨김 - 파이프 파싱용)
go run ./cmd/ctrans scan -f examples/compose/base.yaml --format json --warnings off --fail-on none

# Render script from layered compose files
go run ./cmd/ctrans render \
  -f examples/compose/base.yaml \
  -f examples/compose/override.yaml \
  --env ./.env.runtime \
  --runtime docker --output script

# Verify with strict mode (warn -> error)
go run ./cmd/ctrans verify -f examples/compose/base.yaml --strict --fail-on warn

# Deploy plan (target service + dependency closure)
go run ./cmd/ctrans deploy-plan -f examples/compose/base.yaml --target-service app
# => JSON에 decision 필드 포함
```

## Makefile integration

```bash
# Default compose lookup (docker-compose.yaml / compose.yaml)
make scan-compose

# Use explicit compose files
make render-run COMPOSE_FILES="examples/compose/base.yaml examples/compose/override.yaml"

# Inject additional env-file while rendering
make render-run COMPOSE_FILES="examples/compose/base.yaml" ENV_FILES=".env.runtime"

# Strict verification
make verify-compose COMPOSE_FILES="examples/compose/base.yaml" STRICT=1 FAIL_ON=warn

# Generate deploy plan json
make deploy-plan COMPOSE_FILES="examples/compose/base.yaml"

# JSON 통합용: 경고 상세 숨김 + 차단 완화
make deploy-plan COMPOSE_FILES="examples/compose/base.yaml" WARNINGS=off FAIL_ON=none

# Coverage gate
make coverage-gate THRESHOLD=90
```

## CI Gate

- GitHub Actions workflow: `.github/workflows/ci.yml`
- PR/Push 시 아래를 수행합니다.
  - `make test`
  - `make coverage-gate THRESHOLD=90`

## SKILLS (Agent용)

- 경로: `SKILLS/ctrans-operator/SKILL.md`
- 전제: `/usr/local/bin/ctrans`가 시스템에 이미 설치되어 있어야 합니다.
- 목적: 에이전트가 `ctrans`를 표준 절차(점검/렌더/검증/배포계획)로 일관되게 실행하도록 가이드합니다.

핵심 사용 패턴:

```bash
/usr/local/bin/ctrans scan -f <compose-file> --format json --warnings off --fail-on none
/usr/local/bin/ctrans deploy-plan -f <compose-file> --warnings off --fail-on none
```

Makefile 통합 패턴:

```bash
make deploy-plan COMPOSE_FILES="<compose-file>" WARNINGS=off FAIL_ON=none
```

## Git hooks

```bash
make hooks-install
```

- `pre-commit`: `make scan-compose FAIL_ON=error`
- `pre-push`: `make verify-compose FAIL_ON=warn STRICT=1`

## SSH deployment

```bash
make deploy-ssh HOST=user@server COMPOSE_FILES="examples/compose/base.yaml"
```

This sends generated run commands only (`dist/deploy.sh`) over SSH and avoids shipping full compose files in deployment step.
