# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

_Last updated: 2026-07-05._

## Repository Status

**v1 implemented and runnable.** The full pipeline works end-to-end locally (ingest → scan → read API) and the deploy layer (Terraform + CI) exists but has not had its first `terraform apply`.

- `README.md` — high-level design (HLD) + a "Run It Locally" guide.
- `IMPLEMENTATION.md` — implementation reference: API, data model + DDL, scanner/converter design, infra contract. (Some inline code samples predate the code; the code under `pkg/`/`cmd/` is the source of truth where they differ.)
- `DEPLOYMENT.md` — initial GCP setup runbook (manual first apply) + routine update flow.

Layout: `pkg/`-only (no `internal/`), binaries `cmd/devradar-serve` (ingest API + magic-link UI) and `cmd/devradar-scan` (daily job). Deps are **vendored** (`vendor/`); build with the module's default mode. Infra in `infra/saas/` (validated; not yet applied).

**Deferred (not gaps):** push/email alerting and scan concurrency/pooling — foundations built, clean upgrade paths documented.

Dev loop: `make db-up`, `make seed`, `make serve`, `make scan`, `make test` (needs the DB); `make tf-validate` for infra. See the README for the full local walkthrough.

## What DevRadar Is (v1)

The container-vulnerability layer of the Thingz OSS-intelligence platform (siblings: DevPulse = project health, DevTrace = contributor trust). DevRadar tracks how an image's vulnerabilities change **over time** by rescanning its **SBOM** daily — it never pulls images.

A tenant submits an SBOM (pinned to an image digest) via an authenticated API. A daily Cloud Run Job rescans every active SBOM with Grype and Trivy, normalizes results into a scanner-agnostic schema, and records every change as an append-only event. The product is the **delta over time**, not point-in-time scan results.

**License inventory + compliance (also v1).** The same SBOM already carries a per-package license for every catalogued component, so DevRadar captures it **at ingest** (no extra scan) into a frozen per-digest inventory (`devradar_sbom_package`). Licenses are classified into an obligation taxonomy (permissive / weak-copyleft / strong-copyleft / proprietary / unknown) and evaluated against an opt-in per-tenant policy (`devradar_license_policy`) — both done in **Go at read time** over the raw stored IDs, so a taxonomy or policy change re-applies instantly without touching frozen data. Surfaced via `GET /v1/licenses` (fleet rollup), `GET /v1/sboms/{id}/licenses` (per-package, classified + policy verdict), and a `/licenses` UI page (category donut + license-family treemap + policy editor). Design inspired by [disco](https://github.com/mchmarny/disco) (same author) — learnings, not code; DevRadar fixes disco's first-license-wins collapse (multi-license sets are preserved and SPDX `OR`/`AND` expressions evaluated) and its fragile SQL license-family string-splitting (families/categories are derived in Go). Change-over-time license *events* in the alerting model are deferred (additive; reuses the existing event/causality machinery).

## Core Architecture (the "big picture")

Four components, all Cloud Run, **no VMs, no queue, no registry access**:

1. **Ingest API + minimal UI** (Cloud Run service `devradar-saas-serve`) — authenticated `POST /v1/sboms` (API token). Validates untrusted SBOM input, extracts the subject image digest, content-addresses **per tenant** (`id = sha256(tenant_id + bytes)` — a global hash would collide across tenants submitting the same public SBOM and break isolation), stores bytes in GCS + a row in `devradar_sbom`. Also serves a small **passwordless (magic-link) UI** for minting/revoking API tokens.
2. **Daily Scan Job** (Cloud Run Job `devradar-saas-scan`, pure CPU) — for each active SBOM, runs Grype + Trivy on the SBOM file, normalizes, writes current state + change events.
3. **Read API + UI (v1: pull)** — tenants retrieve current findings + change history (`/v1/images`, `/v1/images/timeline?ref=` for cross-digest history, `/v1/sboms/{id}` metadata, `DELETE /v1/sboms/{id}` to archive, `/v1/sboms/{id}/findings`, `/events`), filtered by a **severity threshold** (tenant `min_severity`, default `medium`; per-request `?min_severity=` override, independent per endpoint; `unknown` always included; `/findings` & `/events` omit sub-threshold rows, `/v1/images` keeps every image but trims each `counts` breakdown to >= threshold with `total` still overall). Push alerts (email/webhook) + Claude narratives are **post-MVP**; the event log that powers them is built in v1.
4. **Store** — shared Cloud SQL Postgres (`thingz` DB, `devradar_` tables).

Three ideas unlock the whole design:

1. **Scan the SBOM, not the image.** The tenant's CI already produces the SBOM; DevRadar consumes it. This deletes registries, auth, rate limits, egress, and the VM fleet — and **unlocks private-registry coverage** (the SBOM crosses the trust boundary, not credentials). This is the headline capability.

2. **Frozen inventory → clean causality.** An SBOM is immutable once submitted, so the only variable across daily scans is the scanner's vuln DB. A new finding on an unchanged digest is DB-driven; a new finding requires a new SBOM (new digest) to be image-driven. The digest boundary is explicit in the data.

3. **Store change, not snapshots.** Day-over-day findings on a fixed SBOM are ~99% identical. DevRadar keeps *current state* (`devradar_finding`, UPSERT) plus an append-only *change log* (`devradar_finding_event`). The change log **is** the delta history — no nightly diff job, no per-day snapshot table.

## SBOM Scanning Accuracy (the "is SBOM scanning as good as image scanning" question)

Split scanning into **matching** (packages → CVEs) and **cataloging** (image → packages). Matching is **identical** for SBOM vs image — same matcher, same DB — so accuracy reduces entirely to cataloging, which is a property of the SBOM *generator*, not of SBOM-vs-image. For an **all-layers** SBOM: zero gap when generated by the scanner's own cataloger family (Syft SBOM → Grype is bit-identical), a small bidirectional gap cross-tool (Syft SBOM → Trivy), and a real-but-shared weakness for static binaries / unmanifested vendored deps (direct image scanning is barely better). DevRadar-specific caveat: **cataloging is frozen per digest** (a newer cataloger's finds arrive only with a new digest), but **matching stays live daily** — which is exactly what gives clean change causality. Recommend Syft-generated CycloneDX, all layers. Trivy is a deliberate cross-check (Grype/Trivy divergence = cataloger-disagreement signal). Generator provenance is recorded at ingest in `devradar_sbom.tool` / `devradar_sbom.tool_version` to keep the cataloging boundary auditable. Full treatment in `IMPLEMENTATION.md` "SBOM Scanning Accuracy".

## Trust Model (important — don't overclaim)

**Trust-on-submission.** DevRadar guarantees **determinism** (same SBOM + same scanner DB → same findings) and **clean change causality** — NOT **authenticity** (that the SBOM faithfully represents its claimed digest). A wrong/stale SBOM yields wrong results; that's on the submitter, by design. The `devradar_sbom.verification_status` field (`unverified` in v1) reserves space for signed-attestation verification later without migration.

## Data Model

Shared Cloud SQL Postgres (`thingzio-pg`, database `thingz`); DevRadar connects as user `devradar` and **prefixes every table `devradar_`**. Full DDL in `IMPLEMENTATION.md`. Tables: `devradar_tenant` / `devradar_session` / `devradar_api_token` (identity/auth, shapes mirror `devtrace_*`), `devradar_sbom` (content-addressed, digest-pinned, immutable), `devradar_scan_run` (proof-of-scan + `db_version`), `devradar_finding` (**current state**, UPSERT, bounded), `devradar_finding_event` (**append-only change log**, the product), `devradar_scan_failure` (failure surface), `devradar_sbom_package` (**frozen per-digest license inventory**, written once at ingest, keyed `(sbom_id, package, version)`, `licenses TEXT[]`), `devradar_license_policy` (per-tenant opt-in compliance policy).

- **Licenses are ingest-captured, not scan-derived.** `devradar_sbom_package` is populated once when a new SBOM is stored (like `devradar_cve_enrichment` is a read-time overlay — it does **not** flow through `ApplyScan`, since licenses are immutable per digest and don't change day-over-day). Extraction is best-effort and must never fail the submission. Classification (taxonomy) and policy evaluation live in Go (`pkg/data/license.go`), never in SQL.

- `devradar_finding_event` is **partitioned monthly by `occurred_at`** from day one and **retained forever** in v1. Retention tiers and roll-ups are later, additive concerns (a policy or a derived read-model, never a migration).
- Finding identity/dedup/join key is `data.Vulnerability.GetID()` = `sha256(exposure/package/version)`.
- **Four version axes, one cause.** A finding set is determined by SBOM inventory (`devradar_sbom.id`/digest), vuln DB (`db_version`), scanner binary (`scanner_version` — the matcher logic), and canonicalizer (`canonicalizer_version`). All are recorded on `devradar_scan_run`. Every `devradar_finding_event` carries a `cause` (`image` | `db` | `tooling`); alerting filters `cause IN ('image','db')` so a grype/trivy upgrade never pages a tenant for a tooling-driven delta. This completes the "clean causality" model — see IMPLEMENTATION.md "ApplyScan → Cause classification".
- **Tenant isolation is application-level** (`WHERE tenant_id = $1` on every tenant-scoped read), mirroring DevTrace — **not** DevPulse's RLS. Reason: the scan job is inherently cross-tenant, so a per-connection `app.tenant_id` GUC would fight the batch writer. Guardrail: all raw SQL lives in the `data/postgres` Store, every scoped method takes `tenantID` first, integration tests assert cross-tenant reads are empty. RLS remains a reversible later upgrade for the read tables if compliance demands it.

## Scanner / Converter Design (vimp pattern — NO dependency on vimp)

The multi-scanner design follows the **patterns proven in [vimp](https://github.com/mchmarny/vimp)** (same author): a `Scanner` interface (run the tool) and a `Converter` interface (normalize its JSON), both behind a registry with format auto-detection. **Critical: DevRadar takes lessons from vimp, not code — there is no `github.com/mchmarny/vimp` import, and there must never be one.** `pkg/scanner`, `pkg/converter`, `pkg/parser`, `pkg/data` are reimplemented natively in this module. DevRadar changes the scanner **input from an image ref to an SBOM file** and adds the time-series event model.

- **Normalized type** follows vimp's minimal `data.Vulnerability` (`Exposure, Package, Version, Severity, Score, IsFixed`) — deliberately lowest-common-denominator so no scanner's quirks leak into the schema (reimplemented, not imported).
- **Converters parse with `gabs`** (not typed structs), which is what lets CVSS score resolution walk a **source-precedence list** (`nvd` → `redhat` → …, V3 over V2) instead of hardcoding one provider. This is the fix for the "Trivy vendor-CVSS silently stored as 0.0" bug — preserve it.
- v1 ships **Grype + Trivy together** (running two prevents overfitting the schema to one). More scanners = register another converter, no other changes.

### Scanner execution: shell out, don't import

**v1 shells out to scanner binaries** (`grype sbom:<file>`, `trivy sbom <file>`) rather than importing them as Go libraries. Rationale (see `IMPLEMENTATION.md` "Scanner Execution Model"): pinned binaries keep scanner versions out of DevRadar's `go.mod` and make `db_version` auditable; two scanners in one process would collide on shared `github.com/anchore/...` transitive deps; subprocess boundaries isolate faults from untrusted SBOM input; Trivy's library API is explicitly unstable. The **`Scanner` interface is the seam** — an in-process Grype backend (load the DB once, reuse across all SBOMs) can drop in later with zero change to normalization/storage. Don't collapse that seam.

## Platform Alignment (shared Thingz conventions)

DevRadar is the third service on the shared platform (`thingzio/infra`) and mirrors DevPulse/DevTrace. Full detail in `IMPLEMENTATION.md` "Platform Alignment" and "Shared-Infrastructure Contract". The non-negotiable conventions:

- **Layout:** `pkg/`-only (no `internal/`); two thin `cmd/` entrypoints (`devradar-serve`, `devradar-scan`), each `main` → `Run(ctx, Options{Version,Commit,Date})` with ldflags-injected version vars.
- **Config:** env vars only, typed accessor funcs in `pkg/config/env.go`, `DEVRADAR_` prefix for service tunables. No config file, no flags.
- **DB:** `database/sql` + `github.com/lib/pq` (**not pgx**). `Store` over `*sql.DB`; embedded `sql/migrations/NNN_*.sql` run by a home-grown **advisory-lock** runner tracked in `devradar_schema_version`; 001 is a squashed idempotent schema; migrations run at startup.
- **Server:** stdlib `net/http.ServeMux` with method patterns; `recoverPanics(securityHeaders(mux))`; hardened timeouts; `GET /health` only; `{"error":...}` JSON envelope; `html/template` + embedded assets for the UI.
- **Auth (two surfaces, passwordless):** API tokens (`dr_`+hex, stored SHA-256, `Bearer`, `RequireAPIToken`) for CI submission; **magic-link** for the UI — tenant identity is a **verified email** (`devradar_tenant.email` UNIQUE, no passwords, no OAuth). `POST /auth/login` issues a single-use `devradar_login_token` (hashed, 15-min TTL) emailed as a link via Resend (`pkg/net`, `SEND_API_KEY`); `GET /auth/verify?token` consumes it (single-use, delete-and-return), upserts+verifies the tenant, and mints a SHA-256-hashed session cookie (`RequireAuth`, 7-day TTL). No email sender configured → the link is logged (dev). Sign-up and sign-in are one flow.
- **Build/CI:** `ko` via GoReleaser (no Dockerfile); `.settings.yaml` is the version/threshold SoT consumed by Make + CI via `yq`; deploy via Workload Identity Federation; vendored deps.
- **Logging:** `log/slog` JSON to stderr, tagged `version`+`source`; no app-level OTel/Prometheus.
- **Claude:** nil-safe hand-rolled Anthropic Messages client (`pkg/claude`), Haiku for batch; optional, never a hard dependency. Post-MVP (delta narratives ride on push alerting, which is deferred) — plus opt-in OpenVEX stubbing (Sonnet).
- **Infra:** references shared `thingzio-pg` + `thingzio-vpc`; creates only its own SQL user `devradar`, `devradar-saas-*` secrets, run/deployer SAs + WIF, Cloud Run service+job, GCS bucket `devradar-saas-sboms`, Artifact Registry `devradar-saas-images`; TF state prefix `devradar`.

## Conventions & Constraints (project-specific)

- **Never pull images.** If a design idea requires registry access, auth, or egress, it belongs in the roadmap ("SBOM source #2"), not v1.
- **Untrusted input.** The SBOM is attacker-controllable: enforce body size caps (`http.MaxBytesReader`), decompression-bomb limits, schema validation, and fail closed if the subject digest can't be resolved.
- **Subject-digest extraction is format-specific and fiddly** (CycloneDX `metadata.component` hashes/PURL vs SPDX root `DESCRIBES` package checksums/externalRefs). It gets its own normalization step; reject SBOMs whose digest can't be resolved.
- **Pin scanner binaries** in `.settings.yaml` and bake them into the scan-job image (fixed matcher = reproducible findings); **refresh the vuln DB lazily** at job start via `Scanner.EnsureDB` then freeze it for the run (one run = one `db_version`) — do NOT bake the DB. Record `db_version` on every `devradar_scan_run`. Never `latest`.
- **Idempotency everywhere** — ingest dedupes by content hash; `ApplyScan` re-runs produce zero new events; event inserts guarded by a natural unique key. Cloud Run Jobs retry.
- **Don't swallow failures** — per-SBOM/per-scanner errors go to `devradar_scan_failure`, not just logs.
- **Tenancy** flows from SBOM → tenant → alert destination (`devradar_tenant.email`); app-level `tenant_id` scoping, see Data Model.

## Language / Tooling (once code exists)

Go, `pkg/`-only layout. Entry points `cmd/devradar-serve` and `cmd/devradar-scan`. No `go.mod`, Makefile, or CI exists yet — when adding the first code, copy the sibling skeleton (DevTrace is the closest match: app-level tenancy, API tokens), establish `go build ./...` / `go test ./...` / `go vet ./...`, adopt `.settings.yaml` as the version/threshold SoT, and use `ko`+GoReleaser (no Dockerfile).
