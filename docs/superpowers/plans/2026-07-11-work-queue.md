# Deterministic Work Queue Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `/work`, a tenant-scoped remediation queue ordered by KEV, fix availability, severity, EPSS, blast radius, and finding age with visible reasons and scanner agreement.

**Architecture:** Extend the existing fleet-CVE aggregation because CVE is already DevRadar's remediation unit. Derive first-seen time from append-only `added` events and scanner count from current findings. Reuse VEX annotations and keyset pagination, then render a focused browser view.

**Tech Stack:** Go 1.26, PostgreSQL CTEs, existing sort/cursor helpers, stdlib HTTP/templates.

## Global Constraints

- No opaque user-facing risk score.
- Canonical finding identity prevents scanner double-counting; agreement is metadata only.
- Ordering is exactly KEV → fix available → severity → EPSS → image blast radius → oldest first.
- VEX context remains visible and fully suppressed work is de-emphasized.
- Tenant filtering is mandatory in current findings and first-seen event history.
- No deployment or release.

---

### Task 1: Ranking data and deterministic query

**Files:**
- Create: `pkg/data/postgres/sql/migrations/021_work_queue.sql`
- Modify: `pkg/data/postgres/read_cve.go`
- Modify: `pkg/data/postgres/read_test.go`

- [ ] Write a failing integration test with CVEs chosen so each priority dimension wins over the dimensions below it; assert first-seen age and scanner count.
- [ ] Run `go test ./pkg/data/postgres -run TestFleetCVEs_WorkQueueOrder -count=1` and confirm RED.
- [ ] Add a partitioned event index on `(tenant_id, finding_id, event_type, occurred_at)` for the scoped first-seen CTE.

```sql
CREATE INDEX IF NOT EXISTS idx_devradar_fe_tenant_finding_added
    ON devradar_finding_event (tenant_id, finding_id, event_type, occurred_at)
    WHERE event_type = 'added';
```

- [ ] Extend `FleetCVE` with `FirstSeen time.Time` and `ScannerCount int`.

```go
FirstSeen    time.Time `json:"first_seen"`
ScannerCount int       `json:"scanner_count"`
```

- [ ] Join a tenant-scoped `MIN(occurred_at)` for `event_type='added'`, falling back to `MIN(f.updated_at)` for legacy rows.

```sql
WITH first_seen AS (
    SELECT finding_id, MIN(occurred_at) AS first_seen
    FROM devradar_finding_event
    WHERE tenant_id = $1 AND event_type = 'added'
    GROUP BY finding_id
)
```

- [ ] Change default risk ordering to the approved lexicographic precedence using non-overlapping numeric bands; retain explicit alternate sorts.

Use a stable `numeric` key: KEV `1e22`, fixable `1e21`, severity `1e19`, EPSS `1e16`, each affected image `1e10`, then `4102444800 - first_seen_epoch` so older findings sort first without using `now()` and destabilizing keyset cursors.
- [ ] Run `go test -race ./pkg/data/postgres -count=1` and commit with `git commit -S -m "feat(work): add deterministic remediation ranking"`.

### Task 2: Browser work queue

**Files:**
- Create: `pkg/server/ui_work.go`
- Create: `pkg/server/templates/work.html`
- Modify: `pkg/server/ui.go`
- Modify: `pkg/server/templates/_chrome.html`
- Modify: `pkg/server/static/css/app.css`
- Create: `pkg/server/work_test.go`

- [ ] Write failing authenticated route and tenant-isolation tests for `/work`.
- [ ] Run `go test ./pkg/server -run TestWorkQueue -count=1` and confirm RED.
- [ ] Register `GET /work`, call `FleetCVEs` with the tenant threshold, and map each row to plain-language reasons.

```go
mux.Handle("GET /work", authed(http.HandlerFunc(s.handleWorkQueue)))
```
- [ ] Render KEV/fix/severity/EPSS/blast-radius/age facts and scanner agreement; link each item to `/cves/{cve}`.
- [ ] Add a Work nav tab and responsive queue styling using existing tokens.
- [ ] Run `go test -race ./pkg/server ./pkg/data/postgres -count=1 && go vet ./pkg/server ./pkg/data/postgres`.
- [ ] Commit with `git commit -S -m "feat(work): add actionable remediation queue"`.

## Unresolved Questions

None.
