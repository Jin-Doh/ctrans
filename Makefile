GO_ENV ?= GOCACHE=/tmp/go-build GOSUMDB=off
CTRANS ?= go run ./cmd/ctrans
RUNTIME ?= docker
COMPOSE_FILES ?=
ENV_FILES ?=
FAIL_ON ?= error
MASK ?= on
WARNINGS ?= on
POLICY ?= configs/policy.default.yaml
ALLOW_INLINE_SENSITIVE ?= off
PROJECT_NAME ?=
STRICT ?=
OUT_DIR ?= dist
HOST ?=
SSH_OPTS ?=
SSH_BASE_OPTS ?= -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o LogLevel=ERROR
THRESHOLD ?= 90
COVER_PROFILE ?= coverage.out

compose_flags = $(foreach f,$(COMPOSE_FILES),-f $(f))
env_flags = $(foreach f,$(ENV_FILES),--env $(f))
policy_flag = $(if $(POLICY),--policy $(POLICY),)
allow_inline_flag = --allow-inline-sensitive $(ALLOW_INLINE_SENSITIVE)
project_flag = $(if $(PROJECT_NAME),--project-name $(PROJECT_NAME),)
strict_flag = $(if $(STRICT),--strict,)

.PHONY: help build test coverage coverage-gate scan-compose render-run verify-compose deploy-plan deploy-ssh deploy-ssh-safe hooks-install

help:
	@echo "ctrans Make 도움말"
	@echo ""
	@echo "사용법:"
	@echo "  make <타깃> [옵션=값 ...]"
	@echo ""
	@echo "빠른 실행 플로우:"
	@echo "  1) make scan-compose"
	@echo "  2) make render-run"
	@echo "  3) make verify-compose"
	@echo "  4) make deploy-ssh HOST=user@server"
	@echo ""
	@echo "결과 상태(final_status) 해석:"
	@echo "  ok      : 경고/오류 없음, 그대로 진행 가능"
	@echo "  warn    : 경고 있음, recommendation 반영 후 진행 권장"
	@echo "  blocked : 현재 정책(FAIL_ON) 기준 차단, 조치 후 재실행 필요"
	@echo ""
	@echo "FAIL_ON 정책:"
	@echo "  FAIL_ON=none  : 경고/오류가 있어도 차단하지 않음"
	@echo "  FAIL_ON=error : 오류(error)만 차단 (기본값)"
	@echo "  FAIL_ON=warn  : 경고/오류 모두 차단"
	@echo ""
	@echo "주요 타깃:"
	@echo "  help           : 이 도움말을 출력합니다."
	@echo "  build          : ./bin/ctrans 바이너리를 빌드합니다."
	@echo "  test           : 전체 Go 테스트를 실행합니다."
	@echo "  coverage       : 커버리지 리포트(coverage.out + total %)를 생성합니다."
	@echo "  coverage-gate  : 총 커버리지가 THRESHOLD 이상인지 검사합니다."
	@echo "  scan-compose   : compose 파일 보안 스캔을 수행합니다."
	@echo "  render-run     : run 스크립트(dist/deploy.sh)를 생성합니다."
	@echo "  verify-compose : 스캔+변환 검증을 수행합니다."
	@echo "  deploy-plan    : 배포 계획 JSON(dist/deploy-plan.json)을 생성합니다."
	@echo "  deploy-ssh     : 생성된 deploy.sh를 SSH 원격 호스트에서 실행합니다."
	@echo "  deploy-ssh-safe: deploy.sh 해시 검증 후 SSH 원격 호스트에서 실행합니다."
	@echo "  hooks-install  : git hooks(pre-commit, pre-push)를 설치합니다."
	@echo ""
	@echo "자주 쓰는 옵션:"
	@echo "  COMPOSE_FILES=\"a.yaml b.yaml\" : -f 플래그로 순서 병합할 compose 파일 목록"
	@echo "  ENV_FILES=\".env.runtime\"       : --env 로 추가할 env 파일 목록"
	@echo "  RUNTIME=docker|podman           : 컨테이너 런타임 선택 (기본: docker)"
	@echo "  FAIL_ON=none|warn|error         : 실패 임계치 (기본: error)"
	@echo "  MASK=on|off                     : 민감값 마스킹 여부 (기본: on)"
	@echo "  WARNINGS=on|off                 : 경고 상세 출력 여부 (JSON 파싱용 off 권장)"
	@echo "  POLICY=configs/policy.default.yaml : 정책 YAML 경로"
	@echo "  ALLOW_INLINE_SENSITIVE=on|off   : 민감 인라인 env 허용 여부 (기본: off)"
	@echo "  PROJECT_NAME=demo               : 컨테이너 이름 prefix"
	@echo "  STRICT=1                        : verify 시 warn을 error로 승격"
	@echo "  HOST=user@server                : deploy-ssh 대상 호스트"
	@echo "  SSH_OPTS=\"-p 2222\"             : ssh 추가 옵션"
	@echo "  SSH_BASE_OPTS=\"...\"            : ssh 기본 보안 옵션 (기본: BatchMode+HostKeyChecking)"
	@echo "  THRESHOLD=90                    : coverage-gate 기준 퍼센트"
	@echo "  COVER_PROFILE=coverage.out      : 커버리지 프로파일 경로"
	@echo ""
	@echo "실무 예시:"
	@echo "  make scan-compose COMPOSE_FILES=\"examples/compose/base.yaml\""
	@echo "  make render-run COMPOSE_FILES=\"examples/compose/base.yaml examples/compose/override.yaml\" FAIL_ON=none"
	@echo "  make verify-compose COMPOSE_FILES=\"examples/compose/base.yaml\" FAIL_ON=warn STRICT=1"
	@echo "  make deploy-plan COMPOSE_FILES=\"examples/compose/base.yaml\" WARNINGS=off FAIL_ON=none"
	@echo "  make deploy-ssh HOST=user@server COMPOSE_FILES=\"examples/compose/base.yaml\""
	@echo "  make deploy-ssh-safe HOST=user@server COMPOSE_FILES=\"examples/compose/base.yaml\""

build:
	$(GO_ENV) go build -o ./bin/ctrans ./cmd/ctrans

test:
	$(GO_ENV) go test ./...

coverage:
	$(GO_ENV) go test ./... -coverprofile=$(COVER_PROFILE)
	@$(GO_ENV) go tool cover -func=$(COVER_PROFILE) | tail -n 1

coverage-gate: coverage
	@total=`$(GO_ENV) go tool cover -func=$(COVER_PROFILE) | awk '/^total:/ {gsub("%","",$$3); print $$3}'`; \
	echo "coverage total=$$total% (threshold=$(THRESHOLD)%)"; \
	awk -v total="$$total" -v threshold="$(THRESHOLD)" 'BEGIN { exit ((total+0) >= (threshold+0)) ? 0 : 1 }' || \
	( echo "coverage gate failed: $$total% < $(THRESHOLD)%"; exit 1 )

scan-compose:
	$(GO_ENV) $(CTRANS) scan $(compose_flags) $(env_flags) $(policy_flag) --runtime $(RUNTIME) --fail-on $(FAIL_ON) --mask $(MASK) --warnings $(WARNINGS) $(allow_inline_flag)

render-run:
	mkdir -p $(OUT_DIR)
	$(GO_ENV) $(CTRANS) render $(compose_flags) $(env_flags) $(policy_flag) --runtime $(RUNTIME) --fail-on $(FAIL_ON) --mask $(MASK) --warnings $(WARNINGS) $(allow_inline_flag) $(project_flag) --output script --out $(OUT_DIR)/deploy.sh

verify-compose:
	$(GO_ENV) $(CTRANS) verify $(compose_flags) $(env_flags) $(policy_flag) --runtime $(RUNTIME) --fail-on $(FAIL_ON) --mask $(MASK) --warnings $(WARNINGS) $(allow_inline_flag) $(project_flag) $(strict_flag)

deploy-plan:
	mkdir -p $(OUT_DIR)
	$(GO_ENV) $(CTRANS) deploy-plan $(compose_flags) $(env_flags) $(policy_flag) --runtime $(RUNTIME) --fail-on $(FAIL_ON) --mask $(MASK) --warnings $(WARNINGS) $(allow_inline_flag) $(project_flag) --out $(OUT_DIR)/deploy-plan.json

deploy-ssh: render-run
	@test -n "$(HOST)" || (echo "HOST is required. e.g. make deploy-ssh HOST=user@server" && exit 1)
	cat $(OUT_DIR)/deploy.sh | ssh $(SSH_BASE_OPTS) $(SSH_OPTS) $(HOST) 'bash -s'

deploy-ssh-safe: render-run
	@test -n "$(HOST)" || (echo "HOST is required. e.g. make deploy-ssh-safe HOST=user@server" && exit 1)
	@sha=`shasum -a 256 $(OUT_DIR)/deploy.sh | awk '{print $$1}'`; \
	echo "deploy.sh sha256=$$sha"; \
	ssh $(SSH_BASE_OPTS) $(SSH_OPTS) $(HOST) "cat > /tmp/ctrans-deploy.sh && (command -v sha256sum >/dev/null 2>&1 && echo '$$sha  /tmp/ctrans-deploy.sh' | sha256sum -c - || echo '$$sha  /tmp/ctrans-deploy.sh' | shasum -a 256 -c -) && bash /tmp/ctrans-deploy.sh" < $(OUT_DIR)/deploy.sh

hooks-install:
	@test -d .git || (echo "Not a git repository (.git missing)" && exit 1)
	cp hooks/pre-commit .git/hooks/pre-commit
	cp hooks/pre-push .git/hooks/pre-push
	chmod +x .git/hooks/pre-commit .git/hooks/pre-push
	@echo "Installed hooks: pre-commit, pre-push"
