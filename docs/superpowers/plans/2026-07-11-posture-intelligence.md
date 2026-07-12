# Posture Intelligence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Compare any two tenant-owned digests in one repository, provide conservative tracked-upgrade guidance, and record honest tenant posture snapshots for trends.

**Architecture:** Comparison reads immutable current evidence for two SBOMs and deduplicates scanner rows by finding identity. Posture trends use a new daily tenant snapshot table maintained after scan completion; the product does not pretend that event deltas or per-scanner run counts are exact historical fleet debt.

**Tech Stack:** Go 1.26, PostgreSQL, existing scan runner/store, stdlib HTTP/templates.

## Global Constraints

- Both compared SBOMs must belong to the tenant and the same repository.
- Scanner twins never double-count.
- Comparison reports evidence differences, not runtime safety or compatibility.
- Upgrade guidance says only that a newer tracked digest has fewer relevant findings under explicit criteria.
- Trends begin when snapshots ship; do not synthesize unsupported historical debt.
- No deployment or release.

---

### Task 1: Digest comparison store

**Files:**
- Create: `pkg/data/postgres/compare.go`
- Create: `pkg/data/postgres/compare_test.go`

**Interfaces:**

```go
func (s *Store) CompareSBOMs(ctx context.Context, tenantID, fromID, toID string) (*SBOMComparison, error)
```

- [ ] Write failing tests for ownership, same-repository validation, scanner deduplication, added/resolved/rerated/newly-fixable findings, package/license additions/removals, and improve/regress/unchanged verdicts.
- [ ] Verify RED with `go test ./pkg/data/postgres -run TestCompareSBOMs -count=1`.
- [ ] Load both SBOM metadata under one `tenant_id`; return `ErrNotFound` when either is absent and `ErrInvalidComparison` when repositories differ or IDs match.
- [ ] Aggregate each side by `finding_id` using worst severity, max score, and `bool_or(is_fixed)`; full-outer join sides to classify changes.
- [ ] Compare frozen package inventories by `(package,version,licenses)` and evaluate net posture lexicographically by KEV, critical, high, medium, then total counts.
- [ ] Run `go test -race ./pkg/data/postgres -count=1` and commit with `git commit -S -m "feat(posture): compare immutable SBOM digests"`.

### Task 2: Comparison browser workflow and upgrade guidance

**Files:**
- Create: `pkg/server/ui_compare.go`
- Create: `pkg/server/templates/compare.html`
- Modify: `pkg/server/ui.go`
- Modify: `pkg/server/templates/image.html`
- Create: `pkg/server/compare_test.go`

- [ ] Write failing authenticated/isolation tests for `GET /compare?from=&to=` and a comparison form on the repository image page.
- [ ] Register `GET /compare`; render counts and exact finding/package/license changes with “Improves posture”, “Regresses posture”, or “No material change”.
- [ ] On a repository with three or more generations, compare newer candidates and report the newest tracked digest with a strictly better verdict as “fewer relevant findings”; never use “safe”.
- [ ] Run server/Postgres race tests and commit with `git commit -S -m "feat(posture): add digest comparison workflow"`.

### Task 3: Daily tenant posture snapshots

**Files:**
- Create: `pkg/data/postgres/sql/migrations/022_tenant_posture_snapshot.sql`
- Create: `pkg/data/postgres/posture.go`
- Create: `pkg/data/postgres/posture_test.go`
- Modify: `pkg/scan/scan.go`
- Modify: `pkg/scan/scan_test.go`

**Schema:** one row per `(tenant_id,snapshot_date)` with image, relevant-finding, critical/high/medium/low, fixable, and KEV counts plus `captured_at`; current findings are deduplicated by `(sbom_id,finding_id)`.

- [ ] Write failing idempotency, scanner-dedup, and tenant-isolation tests.
- [ ] Add the forward-only migration and `SnapshotTenantPosture(ctx)` transaction that upserts all active tenants for `CURRENT_DATE`.
- [ ] Invoke it through an optional scan-store interface after alert evaluation; log and continue on failure.
- [ ] Run scan/Postgres race tests and commit with `git commit -S -m "feat(posture): snapshot tenant vulnerability debt"`.

### Task 4: Fleet and repository trend view

**Files:**
- Modify: `pkg/data/postgres/posture.go`
- Modify: `pkg/data/postgres/posture_test.go`
- Create: `pkg/server/ui_trends.go`
- Create: `pkg/server/templates/trends.html`
- Modify: `pkg/server/ui.go`
- Modify: `pkg/server/templates/_chrome.html`
- Create: `pkg/server/trends_test.go`

- [ ] Add failing bounded-window and cross-tenant tests for snapshot reads.
- [ ] Implement `TenantPostureTrend(ctx, tenantID string, days int)` with `days` clamped to `1..365` and chronological output.
- [ ] Register `GET /trends`, show current debt and day-over-day deltas, and state the first snapshot date so coverage is honest.
- [ ] Add a Trends nav entry and responsive server-rendered trend table/chart using existing visual tokens.
- [ ] Run the full repository race/coverage/lint gate and commit with `git commit -S -m "feat(posture): add fleet posture trends"`.

## Unresolved Questions

None. Historical trend coverage begins at first snapshot by design.
