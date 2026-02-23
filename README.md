# ctrans (compose-to-run)

`ctrans`는 Docker Compose 파일을 스캔해 보안 노출 가능성을 점검하고, 실제 배포에 사용할 `docker run` 또는 `podman run` 명령으로 변환하는 CLI 도구입니다.

로컬 `Makefile + git hooks + SSH` 기반 배포 흐름에서 compose 원문 파일 전송을 줄이고, 배포 시점에는 실행 커맨드만 전달하도록 설계되었습니다.

## 왜 필요한가

- compose 파일 안의 민감 설정(환경변수/키 경로/의심 env 파일)을 사전 점검
- `-f` 다중 입력(override 병합)으로 기존 운영 습관 유지
- 배포 단계에서 compose 파일 대신 생성된 run 스크립트만 사용
- 자동화 파이프라인에서 파싱 가능한 JSON 결과 제공

## 주요 기능

- `-f/--file` 반복 입력 기반 compose 병합 (순서 보장)
- `-f` 미지정 시 기본 파일 자동 조회
  - `docker-compose.yaml`
  - `compose.yaml`
- 보안 스캔 항목
  - 민감 키워드 환경변수
  - 개인키/비밀키로 추정되는 마운트
  - 의심스러운 env 파일명
- 변환 출력
  - `docker run` / `podman run`
  - Script / JSON 포맷
- 모든 명령에 공통 의사결정 필드 제공
  - `final_status`: `ok | warn | blocked`
  - `can_proceed`: `true | false`
  - `recommended_action`
  - `fail_threshold`

## 빌드/테스트

```bash
make build
make test
make coverage-gate THRESHOLD=90
```

- 바이너리: `./bin/ctrans`

## 빠른 시작

```bash
# 서브커맨드 생략 시 기본 동작은 render
./bin/ctrans -f examples/compose/base.yaml

# 보안 스캔
./bin/ctrans scan -f examples/compose/base.yaml

# JSON 출력 (파이프라인/스크립트 연동)
./bin/ctrans scan -f examples/compose/base.yaml --format json --warnings off --fail-on none
```

## 명령어

### 1) `scan`
compose 파일의 보안 이슈를 점검합니다.

```bash
./bin/ctrans scan -f examples/compose/base.yaml --format text
./bin/ctrans scan -f examples/compose/base.yaml --format json --warnings off --fail-on none
```

### 2) `render`
compose를 `run` 명령 계획으로 변환합니다. (기본 동작)

```bash
./bin/ctrans render \
  -f examples/compose/base.yaml \
  -f examples/compose/override.yaml \
  --runtime docker \
  --output script \
  --out dist/deploy.sh
```

### 3) `verify`
스캔 + 변환을 함께 검증합니다.

```bash
./bin/ctrans verify -f examples/compose/base.yaml --strict --fail-on warn
```

### 4) `deploy-plan`
대상 서비스(및 의존성) 기준 배포 계획 JSON을 생성합니다.

```bash
./bin/ctrans deploy-plan \
  -f examples/compose/base.yaml \
  --target-service app \
  --out dist/deploy-plan.json
```

## 공통 옵션

- `-f, --file <path>`: compose 파일 (반복 가능, 순차 병합)
- `--env <path>`: 추가 env-file (반복 가능)
- `--runtime docker|podman`
- `--fail-on none|warn|error`
- `--mask on|off`
- `--warnings on|off`
- `--policy <path>`: 정책 YAML 파일 경로
- `--allow-inline-sensitive on|off`: 민감 가능 값의 인라인 렌더 허용 여부 (기본 `off`)
- `--project-name <name>`

## 결과 해석 규약

- `ok`: 경고/오류 없음
- `warn`: 경고 있음 (정책상 진행 가능할 수 있음)
- `blocked`: 현재 `fail-on` 정책 기준 배포 차단

`--warnings off`를 사용하면 상세 warning 배열을 숨겨 JSON 파싱 안정성을 높일 수 있습니다.

## Makefile 연동

```bash
# 기본 compose 조회(docker-compose.yaml, compose.yaml)
make scan-compose

# 다중 compose 렌더
make render-run COMPOSE_FILES="examples/compose/base.yaml examples/compose/override.yaml"

# JSON 연동(경고 상세 숨김)
make deploy-plan COMPOSE_FILES="examples/compose/base.yaml" WARNINGS=off FAIL_ON=none

# SSH 배포(생성된 deploy.sh만 전송)
make deploy-ssh HOST=user@server COMPOSE_FILES="examples/compose/base.yaml"

# SSH 안전 배포(sha256 검증 후 실행)
make deploy-ssh-safe HOST=user@server COMPOSE_FILES="examples/compose/base.yaml"
```

## Git Hooks

```bash
make hooks-install
```

- `pre-commit`: `make scan-compose FAIL_ON=error`
- `pre-push`: `make verify-compose FAIL_ON=warn STRICT=1`

## GitHub Actions

### CI
- 파일: `.github/workflows/ci.yml`
- 수행 항목
  - `make test`
  - `make coverage-gate THRESHOLD=90`

### Release (Linux/Darwin 자동 배포)
- 파일: `.github/workflows/release.yml`
- 동작 요약
  - `CI` 워크플로우가 `main`에서 성공한 커밋만 릴리스 후보로 평가
  - 대상 커밋 메시지를 Conventional Commit 규칙으로 판정
  - 릴리스 대상 타입(`feat`, `fix`, `perf`, `refactor`)일 때만 진행
  - `VERSION` 파일 값을 태그(`v<version>`)로 사용
  - 산출물: `linux/darwin x amd64/arm64` tar.gz + checksum
  - `VERSION`에 `-`가 포함되면 GitHub pre-release로 생성
  - 동일 태그가 이미 존재하면 릴리스를 건너뜀 (버전 갱신 필요)

릴리스 갱신 절차:

1. `VERSION` 값을 새 버전으로 업데이트
2. 커밋 메시지를 Conventional Commit(`feat:`, `fix:` 등) 형식으로 작성
3. `main`에 push 후 CI가 성공하면 Release workflow가 자동으로 아티팩트를 발행

## 오픈소스 안내

### License
이 프로젝트는 MIT License를 따릅니다. 자세한 조항은 [`LICENSE`](./LICENSE)를 참고하세요.

MIT 라이선스 특성상 소프트웨어는 `AS IS`로 제공되며, 사용으로 인한 책임은 사용자에게 있습니다.

### 기여 가이드 (요약)
- 커밋 메시지는 Conventional Commit 형식 권장
- PR 전 최소 검증
  - `make test`
  - `make coverage-gate THRESHOLD=90`
- 시크릿/토큰/키는 이슈/PR/로그에 포함하지 않습니다.

### 보안 이슈 제보
보안 취약점 제보 시 실제 시크릿 값을 포함하지 말고, 재현 가능한 최소 정보만 공유해 주세요.

## Agent Skill

- 경로: `SKILLS/ctrans-operator/SKILL.md`
- 전제: `/usr/local/bin/ctrans`가 설치되어 있어야 함

예시:

```bash
/usr/local/bin/ctrans scan -f <compose-file> --format json --warnings off --fail-on none
/usr/local/bin/ctrans deploy-plan -f <compose-file> --warnings off --fail-on none
```
