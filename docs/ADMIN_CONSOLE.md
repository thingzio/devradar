# DevRadar: Operator Admin Console

_Design doc. Draft 2026-07-09._

An operator/owner console for running and monitoring the DevRadar service,
mirroring the admin sections already shipped in DevPulse and DevTrace. It is an
internal surface — unlinked from user navigation, gated to a small email
allowlist — for the person who runs the service, not for tenants.

## Governing principle: match the siblings, adapt the one thing that differs

DevPulse and DevTrace ship an almost-identical operator console. DevRadar adopts
that pattern wholesale so a single operator gets a consistent console across all
three Thingz services. Everything below is the sibling convention **except** the
one place DevRadar's domain diverges: it has no GitHub App token pool. DevRadar
never pulls images and holds no per-tenant registry credentials, so the siblings'
"Tokens" page has no analog. Its operational risk lives entirely in the **Scan
Job** — is the cron firing, is the vuln DB fresh, is the scannable backlog
draining, are scanners failing — so that page is replaced by a **Scan Health**
page. That substitution is the whole DevRadar-specific delta.

## Inherited conventions (identical to DevPulse / DevTrace)

| Concern | Convention |
|---|---|
| Mount | `/admin/*`, server-rendered (`html/template`), unlinked from user nav |
| Access | Env allowlist, **no `is_admin` DB column** |
| Deny | Return **404** (not 403) to hide route existence |
| CSRF | Double-submit cookie, `Path=/admin`, constant-time compare, on every mutating POST |
| Audit | `slog.Warn("admin action", …)` — **log-only, not a table** |
| Body cap | `http.MaxBytesReader` on all POSTs |
| Metrics | GCP Monitoring API + Claude health summary (`pkg/claude`, Haiku) |

### Access control

Admin identity is an **env allowlist keyed on verified email** (DevRadar's
identity is email, not a GitHub username):

- `DEVRADAR_ADMIN_USERS` — comma-separated emails, case-insensitive, loaded once
  at startup. Empty ⇒ nobody is admin.
- `middleware.RequireAdmin(db)` layers on the existing session-cookie auth:
  resolve the session → `IsAdmin(tenant.Email)` → inject tenant into context.
  Any failure (no cookie, invalid session, not on the list) returns **404** so
  the console's existence is not disclosed. A denied attempt logs
  `slog.Warn("admin access denied", …)`.
- No DB role/flag. Adding an admin is a config change + redeploy — reversible,
  no migration. This matches both siblings.

### Cross-tenant reads

The console is inherently cross-tenant. DevRadar uses **application-level
tenancy** (`WHERE tenant_id = $1`), *not* RLS, so — unlike DevPulse — there is no
per-connection GUC to clear and no dedicated `adminConn`. Admin queries are just
un-scoped `Store` methods. They live together in `pkg/data/postgres`, are named
with an `Admin` prefix, and deliberately omit the tenant filter. This is the one
place in the codebase where a query legitimately reads across tenants; keeping
them prefixed and co-located makes that auditable.

### CSRF

No CSRF middleware exists in DevRadar today (the existing UI forms are all
same-origin session POSTs; OAuth uses a separate state cookie). The console adds
one, ported from the sibling pattern: a `csrf_token` cookie scoped to
`Path=/admin` (Secure/HttpOnly/SameSite=Strict), a hidden form field, and
`ValidateCSRF` doing a constant-time compare on every mutating POST.

## Pages

Shared 4-item nav: **Dashboard · Scans · Tenants · Metrics**.

### 1. `GET /admin` — Platform dashboard

Operator's first glance. **Live current-state tiles** (see "Live aggregation"
below for why deltas are omitted in v1):

- Tenants — total, by plan (free/paid), by status (active/suspended)
- SBOMs — active / archived; unique image digests
- **Scan heartbeat** — last `scan_run` age, scannable-now count
  (`ListScannableSBOMs`), scans in last 24h. Reuses the exact staleness predicate
  the tenant UI heartbeat already shows.
- Findings — total open, broken down by severity
- Finding-events in last 24h, broken down by `cause` (image / db / tooling)
- **Scan failures (24h)** — count + table from `devradar_scan_failure` (project
  rule: failures must surface, never live only in logs)
- License policy violations (fleet), VEX statements count

### 2. `GET /admin/scans` — Scan health (replaces siblings' "Tokens")

The DevRadar-native operational page:

- **Recent `scan_run` history** — per run: sbom, scanner (grype/trivy),
  `db_version`, `scanner_version`, `canonicalizer_version`, duration, findings
  written, timestamp.
- **Vuln DB freshness** — current `db_version` per scanner and age since last
  refresh; catches a stuck `EnsureDB`.
- **Scannable backlog** — count + oldest submitted SBOM still due; flags a scan
  job that has fallen behind cadence.
- **Scan failures** — full `devradar_scan_failure` surface, filterable by
  scanner, with error text.
- `GET /admin/scans/history` — JSON time-series (scans/hr, findings/hr) feeding a
  small Chart.js panel, mirroring the siblings' `tokens/quota-history` endpoint.

### 3. `GET /admin/tenants` — Tenant list

Search (`?q=` ILIKE on email), paginated (10/page). Columns: email, plan,
status, min_severity, SBOM count, last scan activity, created, last sign-in.
Plus an **Invite tenant** form (insert a minimal verified tenant by email).

### 4. `GET /admin/tenant/{id}` — Tenant detail

Profile (email, plan, status, min_severity, avatar, created, last sign-in); their
SBOM / digest / findings summary; API tokens (list + last-used). Forms: change
plan, active↔suspended, set min_severity. **Danger zone**: delete tenant
(cascade), revoke a specific API token.

### 5. `GET /admin/metrics` — Infra metrics + AI analysis

Direct port of the sibling pattern. GCP Monitoring for the Cloud Run **service**
(`devradar-saas-serve`) *and* **job** (`devradar-saas-scan` — execution count,
duration, failures), plus DB metrics, summarized by Claude (Haiku). `?days=`
selector; disabled-state when `GCP_PROJECT_ID` is unset.

## Actions

All CSRF-protected, audited via `slog`, body-capped with `MaxBytesReader`, and
redirect (303) back to the originating page.

| Method + path | Effect |
|---|---|
| `POST /admin/tenant/{id}/plan` | Change plan (validated) |
| `POST /admin/tenant/{id}/status` | active ↔ suspended |
| `POST /admin/tenant/{id}/min-severity` | Set read-API default severity |
| `POST /admin/tenant/{id}/delete` | Delete tenant (cascade) |
| `POST /admin/tenant/{id}/token/{tid}/revoke` | Revoke one API token |
| `POST /admin/invite` | Create a minimal verified tenant by email |
| `POST /admin/scans/reset-failure/{id}` | Clear a resolved `devradar_scan_failure` row |
| `POST /admin/scans/rescan/{sbomID}` | **Force rescan** — mark one SBOM due immediately |

### Force rescan

DevRadar-specific, and intentionally included even though the siblings omit a
manual job trigger. Work selection is driven by `ListScannableSBOMs`, whose
staleness predicate is "no `scan_run` newer than the window." To force a rescan
we do **not** invoke the scan job from the serve process (they are separate Cloud
Run resources and the serve image has no scanner binaries). Instead the action
makes the SBOM *due* on the next scheduler tick — the simplest, safest
implementation is a small `devradar_scan_run`-independent marker the scannable
query already respects, or (v1) a nudge that clears the SBOM from the "recently
scanned" window. Because the scheduler runs frequently (default 15 min), "due
now" is picked up on the next tick with low latency and no privileged
cross-process job invocation. Exact mechanism is an implementation detail settled
in the plan; the operator-facing contract is "this SBOM will be rescanned on the
next tick."

### Deliberately out of scope (v1)

Matching the siblings' restraint: impersonation, and digest send (alerting is
post-MVP in DevRadar, so there is nothing to send).

## Live aggregation vs. deltas

The dashboard uses **live queries, no snapshot table** (the DevTrace model:
fan out a handful of concurrent queries per load). This is cheap because the
supporting indexes already exist:

- current counts (tenants/SBOMs/tokens) — small tables, `idx_devradar_sbom_active`
- open findings by severity — `idx_devradar_finding_severity`
- scan heartbeat — `idx_devradar_scan_run_sbom (…, scanned_at DESC)`
- 24h events by cause / 24h failures — `idx_devradar_fe_tenant_time`,
  `idx_devradar_scan_failure_time` (both `occurred_at DESC`)

Cold-load latency is well under a second.

**Deltas (DoD/WoW/MoM) are omitted in v1.** They split into two classes:

- *Cumulative-by-`created_at`* metrics (tenants created, SBOMs ever submitted)
  are live-computable and exact — these can carry a delta if desired.
- *Point-in-time-state* metrics (SBOMs *active* 7d ago, findings *open* 7d ago)
  are **not** reconstructable from current state. `devradar_finding` is
  UPSERT-current-state only; it has no history. Replaying
  `devradar_finding_event` to reconstruct a past open-set is a partition-spanning
  aggregate over the product's largest table on every load — not worth it.

DevPulse's `devpulse_platform_stats` snapshot table exists precisely to serve
honest point-in-time deltas. DevRadar can add an analogous
`devradar_platform_stats` **later, additively** (snapshot on dashboard visit +
once per scan-job run). v1 ships live current tiles; deltas are a follow-up when
the operator actually wants them.

## Implementation outline

- `middleware.RequireAdmin(db)` + `IsAdmin(email)` + CSRF helpers in `pkg/middleware`.
- `config.AdminUsers()` reads `DEVRADAR_ADMIN_USERS` (typed accessor, `env.go`).
- `registerAdminRoutes` group in `pkg/server/server.go`, wrapped
  `RequireAdmin(db)` (mutations additionally `ValidateCSRF`).
- Handlers in `pkg/server/handler_admin.go`; templates `pkg/server/templates/admin_*.html`.
- Un-scoped `Admin*` read methods + admin mutations in `pkg/data/postgres`
  (tenant list/detail/search, scan-run history, DB freshness, backlog, failures,
  invite, delete, token revoke, force-rescan, reset-failure).
- Metrics page ports the sibling GCP-Monitoring + `pkg/claude` summary code,
  covering both the serve service and the scan job.

## Decisions (locked)

1. **Allowlist** — env var `DEVRADAR_ADMIN_USERS`, no DB role. (Matches siblings.)
2. **Force rescan** — included.
3. **Audit** — log-only (`slog.Warn`), no table. (Matches siblings.)
4. **Aggregation** — live current tiles in v1; `devradar_platform_stats` snapshot
   deferred until point-in-time deltas are wanted.

## Open questions

- **Force-rescan mechanism** — cleanest way to mark one SBOM "due now" without
  invoking the scan job cross-process (nudge the staleness window vs. a dedicated
  due-marker column). Settled in the implementation plan.
- **Metrics page cost** — the sibling metrics handler can block for tens of
  seconds on GCP + Anthropic calls. Keep synchronous (simple) or add a timeout /
  cache? Recommend a hard context timeout, matching siblings' behavior, for v1.
