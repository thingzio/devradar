# AGENTS.md

Repository guidance for coding agents working on DevRadar.

_Last validated: 2026-07-12 against `main` at v0.13.5._

## Current State and Source of Truth

DevRadar v1 is implemented and runnable end to end: ingest → recurring scan → read API/UI. Terraform and CI exist; the first production `terraform apply` remains an explicit operator action.

- Code under `pkg/` and `cmd/` is authoritative when older documentation samples differ.
- `README.md` explains the product and local workflow.
- `DEVELOPMENT.md` records implementation architecture, invariants, and engineering guidance.
- `DEPLOYMENT.md` is the manual first-apply and routine deployment runbook.
- `.settings.yaml` is the version and quality-threshold source of truth.
- `docs/scalability.md` records measured scaling limits and the triggers that signal a design or sizing change; `docs/cost-optimization.md` tracks cost actions.
- `ROADMAP.md` is the stack-ranked unshipped roadmap; it is not an implementation specification.

Browser alerts, the deterministic work queue, digest comparison, fleet/repository trends, admin health, and optional attestation verification are shipped. Production infrastructure hardening, email/webhooks, SBOM quality assessment, and CI assurance gates are next.

## Non-Negotiable Product Boundaries

- Never pull images. SBOM evidence crosses the trust boundary; registry credentials and image bytes do not.
- Treat SBOMs as attacker-controlled: bound raw and decompressed input, validate schemas, and fail closed when the subject digest cannot be resolved.
- Preserve immutable, digest-pinned inventory and explicit `image` / `db` / `tooling` causality.
- Preserve the scanner abstraction and subprocess isolation. Never import or depend on `github.com/mchmarny/vimp`.
- Pin scanner binaries in `.settings.yaml`; refresh vulnerability databases lazily only when scan work exists, freeze them for the run, and record every version axis.
- Keep alert evaluation outside `ApplyScan`; alert failure must never block scan persistence.
- Never infer runtime deployment, compatibility, reachability, or universal image safety from SBOM data.

## Architecture

- Go with `pkg/`-only layout; no `internal/`.
- Thin entrypoints: `cmd/devradar-serve` and `cmd/devradar-scan` call `Run(ctx, Options{Version, Commit, Date})`.
- Config is environment-only through typed accessors in `pkg/config`; service variables use `DEVRADAR_`.
- Postgres uses `database/sql` + `github.com/lib/pq`, wrapped by `pkg/data/postgres.Store`.
- All SQL lives in `pkg/data/postgres`; every tenant-scoped method takes `tenantID` first and includes explicit tenant filtering. There is no RLS.
- Embedded `NNN_*.sql` migrations run at startup under a Postgres advisory lock and apply transactionally.
- HTTP uses stdlib `net/http.ServeMux`, hardened timeouts, recovery/security middleware, `/health` liveness, and `/ready` database readiness.
- UI uses `html/template` and embedded assets.
- API clients authenticate with hashed `dr_` bearer tokens. Browser sessions use verified identity from magic links or optional GitHub OAuth.
- Logging is structured `log/slog` JSON. Platform metrics and alerts come from Cloud Run/Cloud Monitoring rather than app-level OTel/Prometheus.
- Optional Anthropic integration lives in `pkg/claude`; it must never become a hard dependency in deterministic scan or alert paths.

## Domain Invariants

- SBOM identity is tenant-scoped content addressing: `sha256(tenant_id + bytes)`.
- Finding identity is `data.Vulnerability.GetID()` = `sha256(exposure/package/version)`.
- Current state is bounded in `devradar_finding`; history is append-only in monthly-partitioned `devradar_finding_event`.
- `ApplyScan` is idempotent and serialized per `(sbom, scanner)`; Cloud Run Jobs retry.
- Frozen license inventory is captured at ingest in `devradar_sbom_package`; taxonomy and policy evaluation remain Go read-time overlays.
- OpenVEX suppression is a read-time overlay and never mutates findings.
- Unknown severity remains visible where existing endpoint semantics require it.
- Scanner agreement is metadata, not proof; canonical finding identity must prevent double-counting.
- Per-SBOM/per-scanner failures are persisted in `devradar_scan_failure`, not only logged.

## Scanner and Build Constraints

- Grype and Trivy scan the canonical CycloneDX SBOM via subprocesses.
- Converters use `gabs`; preserve CVSS source precedence and V3-over-V2 behavior.
- `devradar-serve` is built with `ko` through GoReleaser.
- `devradar-scan` uses the multi-stage `Dockerfile.scan` because scanner binaries must be present at runtime.
- Dependencies are vendored; use normal module commands without forcing `-mod=mod`.

## Development and Validation

Local loop:

```text
make db-up
make seed
make serve
make scan
make test
```

Useful gates:

- `make test-unit` — race-enabled tests without requiring Postgres.
- `make test` — race-enabled unit and integration tests; requires local Postgres.
- `make qualify` — coverage, vet, lint, and tests; must pass before completion.
- `make tf-validate` — Terraform validation without backend credentials.
- `go build ./...` — direct compile check.

Use test-driven development for behavior changes. Never skip or disable tests. Preserve unrelated work in a dirty tree. Commit focused changes directly to `main`, signed with `git commit -S`; never add sign-offs, co-author trailers, or generated-by text.

## Migration and Release Safety

- Migrations must be forward-only, transactional where Postgres permits, and safe under concurrent startup.
- Add migration integration tests and cross-tenant isolation tests for every tenant-scoped table or query.
- Before a release with migrations, restore a production database backup into an isolated environment and validate migration apply, application behavior, query performance, and the documented rollback procedure.
- Do not deploy, tag, push, run `terraform apply`, or enable a production feature without explicit owner approval.
- New alert kinds or delivery channels must run in shadow/test mode before tenant exposure; verify deterministic output and zero duplicates under retry.
- The owner must validate the complete workflow locally before any beta or release.

## Working Style

- Read before writing and follow existing patterns.
- Prefer incremental, independently testable slices over cross-cutting rewrites.
- Prefer testability, readability, consistency, simplicity, then reversibility—in that order.
- Prefer self-documenting code to explanatory comments.
- After three failed fix attempts, stop and reassess the design.
- At the end of each plan, list unresolved questions.
