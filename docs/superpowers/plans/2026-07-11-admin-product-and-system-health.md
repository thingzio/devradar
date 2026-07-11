# Admin Product and System Health Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add aggregate product/pipeline health to `/admin` and Cloud Run/Cloud SQL saturation signals to `/admin/metrics`.

**Architecture:** Keep cross-tenant application aggregates in one auditable `AdminProductHealth` store read and render them as a best-effort section on the existing dashboard. Keep infrastructure series in the existing concurrent Cloud Monitoring collector; extend its configuration with the shared Cloud SQL instance and add only raw infrastructure queries.

**Tech Stack:** Go 1.26, PostgreSQL 16, `database/sql`, `html/template`, Google Cloud Monitoring REST API.

## Global Constraints

- `/admin` is database-backed product/adoption/pipeline health; `/admin/metrics` is infrastructure-only Cloud Monitoring data.
- New product signals are aggregate-only and expose no tenant identity or drill-down.
- No custom Prometheus, OpenTelemetry, application exporter, schema migration, or per-tenant loop.
- Evaluator health uses pending count and oldest-pending age; stale cursor age alone is not an incident.
- Canonical exposures deduplicate scanner agreement by tenant, active SBOM, and finding identity and respect VEX suppression.
- Cloud SQL filters include project and instance identity; default instance is `thingzio-pg`.
- New dashboard data is best-effort and must not hide existing admin sections.
- No safe/compatible/reachable/compliant claim, deployment, or release.

---

### Task 1: Aggregate product and pipeline health read

**Files:**
- Modify: `pkg/data/postgres/admin.go`
- Create: `pkg/data/postgres/admin_product_health_test.go`

**Interfaces:**
- Produces: `func (s *Store) AdminProductHealth(ctx context.Context) (*AdminProductHealth, error)`.
- Consumes: alert policy/alert/cursor/failure, active SBOM/finding/VEX/enrichment, posture snapshot, license policy tables.

- [ ] **Step 1: Write failing aggregate tests**

Seed two tenants plus foreign sentinel data and verify:

- enabled policies, alerts created in 24 hours, and unread alerts;
- pending event count strictly after the `browser-alerts-v1` cursor tuple, oldest pending timestamp, and failures in 24 hours;
- current-UTC-date posture coverage over tenants with active SBOMs only;
- scanner twins collapse to one canonical exposure while fixed/KEV are `bool_or` unions;
- VEX-suppressed exposure is excluded;
- comparison readiness counts tenant/repository groups with two active distinct digests;
- license configured counts every persisted policy while enforcing requires denied categories or deny exceptions.

Assert only integer/time aggregates are returned; the model has no tenant ID/email field.

- [ ] **Step 2: Verify RED**

```bash
go test ./pkg/data/postgres -run TestAdminProductHealth -count=1
```

Expected: compile failure because the type and method do not exist.

- [ ] **Step 3: Define the aggregate model**

Add:

```go
type AdminProductHealth struct {
	EnabledAlertPolicies       int
	Alerts24h                  int
	UnreadAlerts               int
	EvaluatorBacklog           int
	OldestPendingAt            time.Time
	EvaluatorFailures24h       int
	SnapshotTenantsToday       int
	ActiveSBOMTenants          int
	CanonicalExposures         int
	CanonicalFixableExposures  int
	CanonicalKEVExposures      int
	ComparisonReadyRepositories int
	LicensePoliciesConfigured  int
	LicensePoliciesEnforcing   int
}
```

- [ ] **Step 4: Implement bounded set-based aggregates**

Use a small fixed sequence of `QueryRowContext` calls. The evaluator backlog query must use the full cursor tuple and default to epoch only if the consumer row is unexpectedly absent:

```sql
WITH position AS (
  SELECT COALESCE((SELECT last_occurred_at FROM devradar_alert_cursor WHERE consumer=$1), 'epoch') AS occurred_at,
         COALESCE((SELECT last_event_id FROM devradar_alert_cursor WHERE consumer=$1), 0) AS event_id
)
SELECT count(*), min(e.occurred_at)
FROM devradar_finding_event e CROSS JOIN position p
WHERE e.cause IN ('image','db')
  AND (e.occurred_at,e.id) > (p.occurred_at,p.event_id)
```

Use `sql.NullTime` for the oldest pending event. Canonical exposure SQL must mirror `SnapshotTenantPosture`: active SBOMs, VEX suppression, group by `(tenant_id,sbom_id,finding_id)`, `bool_or(is_fixed)`, and `bool_or(enrichment.kev)`. Comparison readiness groups by `(tenant_id,repository)` and requires `count(DISTINCT digest) >= 2`. License enforcement uses `cardinality(denied_categories) > 0 OR cardinality(deny_exceptions) > 0`.

Wrap each error with the metric group name. Do not return partial structs from the store method.

- [ ] **Step 5: Verify GREEN and commit**

Run:

```bash
go test -race ./pkg/data/postgres -run 'TestAdminProductHealth|TestScanFailureClassification' -count=1
```

Expected: PASS.

```bash
git add pkg/data/postgres/admin.go pkg/data/postgres/admin_product_health_test.go
git commit -S -m "feat(admin): aggregate product pipeline health"
```

### Task 2: Compact best-effort Admin dashboard section

**Files:**
- Modify: `pkg/server/handler_admin.go`
- Modify: `pkg/server/templates/admin_dashboard.html`
- Modify: `pkg/server/admin_test.go`
- Create: `pkg/server/admin_internal_test.go`

**Interfaces:**
- Consumes: `AdminProductHealth(ctx)`.
- Produces: render data `ProductHealth`, `ProductHealthUnavailable`, and a humanized oldest-pending age.

- [ ] **Step 1: Write failing rendering and degradation tests**

Extend the authenticated admin route test with seeded aggregate data and require:

```go
for _, want := range []string{
	"Product health", "Alert adoption", "Evaluator", "Posture coverage",
	"Actionable exposure", "Comparison readiness", "License policy adoption",
	"Caught up", "current UTC date",
} {
	if !strings.Contains(body, want) { t.Errorf("missing %q", want) }
}
```

Assert no tenant email/name from seeded tenants renders in the new section and reject `safe`, `compatible`, `reachable`, and `compliant` (case-insensitive).

Add an internal unit test around a focused loader/helper with a fake returning an error; assert it reports unavailable without changing the already-loaded core dashboard data. This tests the handler's best-effort branch without destructive DDL.

- [ ] **Step 2: Verify RED**

```bash
go test ./pkg/server -run 'TestAdmin_AdminSeesProductHealth|TestLoadAdminProductHealth' -count=1
```

Expected: failures because the section/helper does not exist.

- [ ] **Step 3: Add a narrow loader boundary and handler degradation**

Define:

```go
type adminProductHealthReader interface {
	AdminProductHealth(context.Context) (*postgres.AdminProductHealth, error)
}

func loadAdminProductHealth(ctx context.Context, reader adminProductHealthReader) (*postgres.AdminProductHealth, bool) {
	health, err := reader.AdminProductHealth(ctx)
	return health, err != nil
}
```

The handler logs the actual error itself (or return the error from the helper if needed for logging), passes `ProductHealthUnavailable: true`, and still renders existing counts/trends. When backlog is nonzero, derive a text age using the existing `humanizeSince` helper; when zero, render “Caught up.”

- [ ] **Step 4: Render compact aggregate cards**

Add a “Product health” heading after current platform/severity cards and before historical trend. Use existing `.stats`, `.stat`, `.card`, `.danger-n`, `.kev-n`, and `.muted` classes. Labels include exact populations/windows: “alerts created · 24h,” “evaluator failures · 24h,” “posture snapshots today · X / Y active tenants,” and “canonical active exposures.”

Do not link to tenant detail or emit identities. Empty states follow the approved spec exactly; failure renders `Product health temporarily unavailable.`

- [ ] **Step 5: Verify and commit**

```bash
go test -race ./pkg/server -run 'TestAdmin_|TestLoadAdminProductHealth' -count=1
git diff --check
```

Expected: PASS and no whitespace errors.

```bash
git add pkg/server/handler_admin.go pkg/server/templates/admin_dashboard.html pkg/server/admin_test.go pkg/server/admin_internal_test.go
git commit -S -m "feat(admin): surface aggregate product health"
```

### Task 3: Cloud Run and Cloud SQL saturation metrics

**Files:**
- Modify: `pkg/server/admin_metrics.go`
- Create: `pkg/server/admin_metrics_internal_test.go`

**Interfaces:**
- Consumes: `GCP_PROJECT_ID`, service/job names, and `DEVRADAR_CLOUD_SQL_INSTANCE`.
- Produces: five additional `metricQuery` values for serve CPU/memory and Cloud SQL CPU/connections/disk.

- [ ] **Step 1: Write failing exact-filter tests**

In package `server`, set `GCP_PROJECT_ID=project-test`, `DEVRADAR_SERVICE_NAME=serve-test`, `DEVRADAR_SCAN_JOB_NAME=scan-test`, and `DEVRADAR_CLOUD_SQL_INSTANCE=sql-test`. Assert config resolves those exact values. Inspect `adminMetricQueries` and require these metric/resource fragments:

```go
[]string{
	`run.googleapis.com/container/cpu/utilizations`,
	`run.googleapis.com/container/memory/utilizations`,
	`cloudsql.googleapis.com/database/cpu/utilization`,
	`cloudsql.googleapis.com/database/network/connections`,
	`cloudsql.googleapis.com/database/disk/utilization`,
	`resource.labels.database_id="project-test:sql-test"`,
}
```

Also assert the default SQL instance is `thingzio-pg` when the override is empty and that existing request/latency/job queries remain.

- [ ] **Step 2: Verify RED**

```bash
go test ./pkg/server -run 'TestAdminMetricsConfig|TestAdminMetricQueries' -count=1
```

Expected: compile/assertion failure because database config and queries are absent.

- [ ] **Step 3: Extend config and queries**

Add `database string` to `adminMetricsConfig` and resolve it with:

```go
database := config.GetEnv("DEVRADAR_CLOUD_SQL_INSTANCE", "thingzio-pg")
```

Add serve CPU/memory distribution queries scoped to the existing Cloud Run service, using hourly alignment and percentile utilization. Add Cloud SQL GAUGE queries filtered by:

```go
databaseID := cfg.projectID + ":" + cfg.database
fmt.Sprintf(`resource.type="cloudsql_database" AND resource.labels.database_id="%s" AND metric.type="..."`, databaseID)
```

Use mean alignment for CPU, max alignment for active connections and disk utilization, and preserve the concurrent fan-out/error-isolation behavior.

- [ ] **Step 4: Verify focused behavior**

```bash
go test -race ./pkg/server -run 'TestAdminMetricsConfig|TestAdminMetricQueries|TestAdmin_' -count=1
```

Expected: PASS.

- [ ] **Step 5: Run full qualification and commit**

Run `make qualify`, `go build ./...`, and `git diff --check`. Expected: all exit zero, coverage at least 45%, vet clean, lint zero issues.

```bash
git add pkg/server/admin_metrics.go pkg/server/admin_metrics_internal_test.go
git commit -S -m "feat(admin): add infrastructure saturation metrics"
```

## Unresolved Questions

None.
