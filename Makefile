VERSION            ?= $(shell git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0")
COMMIT             := $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE               := $(shell date +%Y-%m-%dT%H:%M:%S%Z)
GO_VERSION         := $(shell go env GOVERSION 2>/dev/null | sed 's/go//')
LINT_TIMEOUT       ?= $(shell yq -r '.quality.lint_timeout' .settings.yaml 2>/dev/null || echo "5m")
TEST_TIMEOUT       ?= $(shell yq -r '.quality.test_timeout' .settings.yaml 2>/dev/null || echo "10m")
BUILD_TIMEOUT      ?= $(shell yq -r '.quality.build_timeout' .settings.yaml 2>/dev/null || echo "10m0s")
COVERAGE_THRESHOLD ?= $(shell yq -r '.quality.coverage_threshold' .settings.yaml 2>/dev/null || echo "45")
GOLANGCI_VERSION   ?= $(shell yq -r '.linting.golangci_lint' .settings.yaml 2>/dev/null || echo "v2.12.1")

# Local development connection + shared blob store dir (so serve and scan share
# one SBOM store without GCS).
DEV_DB       := postgres://devradar:devradar@localhost:5432/devradar?sslmode=disable
LOCAL_SBOMS  := .sboms
LDFLAGS      := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)
LOCAL_ENV    := DATABASE_URL="$(DEV_DB)" DEVRADAR_DEBUG=true DEVRADAR_DEV_MODE=true DEVRADAR_LOCAL_SBOMS=1 DEVRADAR_LOCAL_SBOM_DIR="$(LOCAL_SBOMS)"

all: help

# =============================================================================
# Info
# =============================================================================

.PHONY: info
info: ## Prints current project info
	@echo "version: $(VERSION)"
	@echo "commit:  $(COMMIT)"
	@echo "date:    $(DATE)"
	@echo "go:      $(GO_VERSION)"

# =============================================================================
# Code formatting & dependencies
# =============================================================================

.PHONY: tidy
tidy: ## Formats code, tidies deps, and refreshes the vendor tree
	go fmt ./...
	go mod tidy
	go mod vendor

.PHONY: upgrade
upgrade: ## Upgrades all dependencies to latest and refreshes vendor
	go get -u ./...
	go mod tidy
	go mod vendor

# =============================================================================
# Quality
# =============================================================================

.PHONY: lint
lint: lint-go lint-yaml ## Lints Go + YAML (same as CI)

.PHONY: lint-go
lint-go: ## Lints Go code (go vet + golangci-lint)
	go vet ./...
	@command -v golangci-lint >/dev/null 2>&1 || { \
		echo "ERROR: golangci-lint not installed (CI pins $(GOLANGCI_VERSION)); install: https://golangci-lint.run"; exit 1; }
	golangci-lint run --timeout=$(LINT_TIMEOUT)

.PHONY: lint-yaml
lint-yaml: ## Lints YAML files (yamllint); skipped if yamllint absent
	@command -v yamllint >/dev/null 2>&1 && yamllint -c .yamllint.yaml . || echo "yamllint not installed; skipping YAML lint"
	@tools/check-deploy-workflow

.PHONY: test
test: ## Runs unit + integration tests (integration needs 'make db-up')
	DATABASE_URL="$(DEV_DB)" go test -count=1 -race -timeout=$(TEST_TIMEOUT) -covermode=atomic -coverprofile=cover.out ./...
	@echo ""; go tool cover -func=cover.out | grep total

.PHONY: test-unit
test-unit: ## Runs tests without a database (integration tests skip)
	go test -count=1 -race -timeout=$(TEST_TIMEOUT) ./...

.PHONY: test-coverage
test-coverage: test ## Runs tests and enforces the coverage threshold
	@coverage=$$(go tool cover -func=cover.out | grep total | awk '{print $$3}' | sed 's/%//'); \
	echo "Coverage: $$coverage% (threshold: $(COVERAGE_THRESHOLD)%)"; \
	if [ $$(echo "$$coverage < $(COVERAGE_THRESHOLD)" | bc) -eq 1 ]; then \
		echo "ERROR: coverage $$coverage% below threshold $(COVERAGE_THRESHOLD)%"; exit 1; fi; \
	echo "Coverage check passed"

.PHONY: vulncheck
vulncheck: ## Scans for known vulnerabilities (govulncheck)
	govulncheck ./...

.PHONY: qualify
qualify: test-coverage lint ## Full local quality gate (test + coverage + lint)
	@echo "Qualification complete"

# =============================================================================
# Local development
# =============================================================================

.PHONY: db-up
db-up: ## Starts local Postgres (docker compose)
	docker compose up -d
	@echo "Waiting for Postgres..."
	@until docker compose exec -T db pg_isready -U devradar >/dev/null 2>&1; do sleep 1; done
	@echo "Postgres ready: $(DEV_DB)"

.PHONY: db-down
db-down: ## Stops local Postgres
	docker compose down

.PHONY: db-connect
db-connect: ## Opens a psql shell to local Postgres
	psql "$(DEV_DB)"

.PHONY: seed
seed: ## Seeds a test tenant and prints an API token
	DATABASE_URL="$(DEV_DB)" go run ./tools/seed-tenant

.PHONY: serve
serve: ## Runs the ingest/read API + UI locally (local blob store, no GCS)
	@mkdir -p $(LOCAL_SBOMS)
	$(LOCAL_ENV) go run -ldflags "$(LDFLAGS)" ./cmd/devradar-serve

.PHONY: scan
scan: ## Runs the daily scan job once against local Postgres + blob store
	@mkdir -p $(LOCAL_SBOMS)
	$(LOCAL_ENV) go run -ldflags "$(LDFLAGS)" ./cmd/devradar-scan

.PHONY: deliver
deliver: ## Delivers one local email outbox batch (requires DEVRADAR_DELIVERY_KEY)
	@test -n "$$DEVRADAR_DELIVERY_KEY" || { echo "set DEVRADAR_DELIVERY_KEY to the serve process key"; exit 1; }
	$(LOCAL_ENV) go run -ldflags "$(LDFLAGS)" ./cmd/devradar-deliver

.PHONY: submit
submit: ## Submits by image (SBOM auto-generated) or file. Usage: make submit IMAGE=repo:tag | SBOM=file [REF=img@sha256:..]
	@test -n "$(DR_TOKEN)" || { echo "set DR_TOKEN (see 'make seed')"; exit 1; }
	@test -n "$(IMAGE)$(SBOM)" || { echo "usage: make submit IMAGE=<repo:tag> | SBOM=<file> [REF=<image@sha256:...>]"; exit 1; }
	DR_TOKEN="$(DR_TOKEN)" go run ./tools/sbom-submit "$(if $(IMAGE),$(IMAGE),$(SBOM))" "$(REF)"

# =============================================================================
# Build & release
# =============================================================================

.PHONY: build
build: ## Builds all binaries for the current platform (goreleaser snapshot)
	goreleaser build --clean --single-target --snapshot --timeout $(BUILD_TIMEOUT)
	@echo "Binaries in ./dist"

.PHONY: release
release: ## Runs a snapshot release (serve/deliver via ko, scan via Dockerfile)
	goreleaser release --snapshot --clean --timeout $(BUILD_TIMEOUT)

.PHONY: scan-image
scan-image: ## Builds the scan-job container locally (scanners baked in)
	docker build -f Dockerfile.scan -t devradar-scan:local .

.PHONY: bump-major
bump-major: ## Tags + pushes the next major version (v1.2.3 -> v2.0.0), triggering release
	tools/bump major

.PHONY: bump-minor
bump-minor: ## Tags + pushes the next minor version (v1.2.3 -> v1.3.0), triggering release
	tools/bump minor

.PHONY: bump-patch
bump-patch: ## Tags + pushes the next patch version (v1.2.3 -> v1.2.4), triggering release
	tools/bump patch

# =============================================================================
# Infrastructure (Terraform) — see infra/saas
# =============================================================================

TF_DIR := infra/saas

.PHONY: tf-init
tf-init: ## Initializes Terraform (infra/saas)
	terraform -chdir=$(TF_DIR) init

.PHONY: tf-plan
tf-plan: ## Plans infra changes
	terraform -chdir=$(TF_DIR) plan

.PHONY: tf-apply
tf-apply: ## Applies infra changes (run by hand for the first deploy)
	terraform -chdir=$(TF_DIR) apply

.PHONY: tf-fmt
tf-fmt: ## Formats Terraform
	terraform -chdir=$(TF_DIR) fmt -recursive

.PHONY: tf-validate
tf-validate: ## Validates Terraform without backend/creds
	terraform -chdir=$(TF_DIR) init -backend=false >/dev/null && terraform -chdir=$(TF_DIR) validate

# =============================================================================
# Cleanup
# =============================================================================

.PHONY: clean
clean: ## Removes build artifacts and the local blob store
	rm -rf ./dist ./cover.out $(LOCAL_SBOMS)
	go clean ./...

.PHONY: clean-all
clean-all: clean ## Deep clean including the Go module cache
	go clean -modcache

# =============================================================================
# Help
# =============================================================================

.PHONY: help
help: ## Displays available commands
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk \
		'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-16s\033[0m %s\n", $$1, $$2}'
