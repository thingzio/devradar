# Release Correctness Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the integrated release-review blockers in event delivery, policy prospectivity, VEX consistency, comparison resilience, repository trends, and migration operations.

**Architecture:** Replace the lossy event high-water scan with a transactional pending-event queue written in the same `ApplyScan` transaction. Treat alert-policy `updated_at` as the persisted policy version, use latest VEX state everywhere, preserve archived immutable evidence for explicit comparisons, and extend the existing daily snapshot model with repository rows.

**Tech Stack:** Go 1.26, PostgreSQL 16, `database/sql`, `html/template`, existing migration runner and server UI.

## Global Constraints

- Scan persistence remains transactional, retry-safe, tenant-scoped, and independent of successful alert evaluation.
- Browser alert generation remains prospective; migrations do not backfill historical alerts.
- Reverse commit order cannot lose eligible events.
- Policy changes apply only to later events; a concurrent policy change prevents stale drafts from inserting.
- VEX suppression is latest-statement-wins in every aggregate and detail path.
- Explicit comparison accepts tenant-owned immutable evidence, including archived SBOMs; upgrade recommendations remain active-only and strict.
- Repository trends contain observed daily snapshots only; no reconstructed history.
- Add only forward, idempotent migrations. No deploy or release.

---

### Task 1: Transactional alert event queue and operational indexes

**Files:**
- Create: `pkg/data/postgres/sql/migrations/024_alert_event_queue.sql`
- Modify: `pkg/data/postgres/applyscan.go`
- Modify: `pkg/data/postgres/alert.go`
- Modify: `pkg/data/postgres/models.go`
- Modify: `pkg/data/postgres/applyscan_test.go`
- Modify: `pkg/data/postgres/alert_test.go`
- Modify: `pkg/alert/evaluator.go`
- Modify: `pkg/alert/evaluator_test.go`

**Interfaces:**
- Produce: pending queue keyed `(consumer,event_occurred_at,event_id)` with `processed_at`.
- Change: `CommitAlertBatch(..., processed []AlertPosition, end AlertPosition)`.

- [ ] Write a reverse-commit integration test: transaction A inserts an eligible event and queue row but remains uncommitted; transaction B commits a later event, is evaluated/marked processed; A commits; the next read must return A.
- [ ] Verify the test fails against cursor-only selection.
- [ ] Add migration 024 with `devradar_alert_event_queue`, a partial pending index, global actionable-event `(occurred_at,id)`, alert `created_at`, and evaluator-failure `occurred_at` indexes. Do not enqueue historical events.
- [ ] Make `insertEvent` return the inserted event ID and enqueue `image`/`db` events for `browser-alerts-v1` in the same scan transaction. Tooling events are never queued.
- [ ] Select candidates from unprocessed queue rows, joining the immutable source event. Atomically insert alerts/failures, mark every examined queue row processed, and advance the cursor only as a monotonic observability high-water.
- [ ] Update evaluator/store interfaces and tests so unmatched and failed candidates are also marked processed.
- [ ] Run race tests for postgres/alert/scan and commit signed.

### Task 2: Evaluator isolation and prospective policy versions

**Files:**
- Modify: `pkg/alert/alert.go`
- Modify: `pkg/alert/alert_test.go`
- Modify: `pkg/alert/evaluator.go`
- Modify: `pkg/alert/evaluator_test.go`
- Modify: `pkg/data/postgres/alert.go`
- Modify: `pkg/data/postgres/alert_test.go`
- Modify: `pkg/data/postgres/models.go`

**Interfaces:**
- Extend `AlertDraft` with the policy `UpdatedAt` version used to match.

- [ ] Replace the comparison-error retry test with a failing isolation test requiring the normal alert, one recorded failure, processed queue position, and continued later-event processing.
- [ ] Add matcher tests proving an event before nonzero `policy.UpdatedAt` is ignored and an event at/after it is eligible.
- [ ] Add a store integration test: obtain a draft, update/disable the policy before commit, and assert the stale draft does not insert while its event is processed.
- [ ] On comparison failure append `AlertFailure`, retain normal drafts, increment failure count, and continue.
- [ ] Set `PolicyUpdatedAt` on drafts. Insert each alert through its current policy row only when it is still enabled, tenant-owned, and `updated_at` equals the draft version. A zero version is allowed only for focused low-level tests.
- [ ] Run race tests and commit signed.

### Task 3: Latest VEX semantics, visible work context, and resilient comparisons

**Files:**
- Modify: `pkg/data/postgres/vex.go`
- Modify: `pkg/data/postgres/posture_test.go`
- Modify: `pkg/server/ui_work.go`
- Modify: `pkg/server/templates/work.html`
- Modify: `pkg/server/static/css/app.css`
- Modify: `pkg/server/work_test.go`
- Modify: `pkg/data/postgres/compare.go`
- Modify: `pkg/data/postgres/compare_test.go`
- Modify: `pkg/server/ui_compare.go`
- Modify: `pkg/server/templates/compare.html`
- Modify: `pkg/server/compare_test.go`
- Create: `pkg/server/compare_internal_test.go`

- [ ] Add failing tests proving a later `affected` VEX restores an exposure to tenant snapshots/admin aggregates and partial/full suppression is visible on Work.
- [ ] Replace aggregate “any suppressing statement” with a correlated latest-statement expression matching the detail path.
- [ ] Carry `Suppressed` and `AllVEXd` into `workRow`; show partial/full text and de-emphasize only fully suppressed items.
- [ ] Add failing store/route tests comparing archived same-tenant/same-repository SBOMs; remove active-only filters from explicit comparison reads, not recommendations.
- [ ] Make recommendation loading a tested best-effort helper; log failures and preserve the exact comparison page.
- [ ] Explain verdict precedence in the comparison template: KEV → critical → high → medium → low → total.
- [ ] Run race tests and commit signed.

### Task 4: Observed repository posture trends

**Files:**
- Create: `pkg/data/postgres/sql/migrations/025_repository_posture_snapshot.sql`
- Modify: `pkg/data/postgres/posture.go`
- Modify: `pkg/data/postgres/posture_test.go`
- Modify: `pkg/server/ui_trends.go`
- Modify: `pkg/server/templates/trends.html`
- Modify: `pkg/server/trends_test.go`

**Interfaces:**
- Produce: `RepositoryPostureTrend(ctx, tenantID, repository, days)` and repository options with snapshot coverage.

- [ ] Add migration 025 with daily `(tenant_id,repository,snapshot_date)` rows mirroring canonical VEX-aware tenant counts.
- [ ] Extend the existing snapshot transaction to replace today’s repository rows and tenant rows atomically.
- [ ] Add tenant-isolated, bounded repository trend reads and tests for missing dates/no synthetic history.
- [ ] Add an optional repository selector to `/trends`; empty selection retains fleet trends. Render the same observed-point semantics and exact selected repository.
- [ ] Run race tests and commit signed.

### Task 5: UTC consistency, migration rehearsal, and operational evidence

**Files:**
- Modify: `pkg/data/postgres/posture.go`
- Modify: `pkg/data/postgres/posture_test.go`
- Modify: `DEPLOYMENT.md`

- [ ] Change snapshot keys to `(now() AT TIME ZONE 'UTC')::date` in tenant and repository writes.
- [ ] Test UTC-date behavior under a non-UTC session timezone.
- [ ] Document isolated pre-migration clone, migrated clone, validation queries, rollback-by-reclone, and explicit no-release gate.
- [ ] Restore the production backup into the retained pre-migration DB, clone, migrate 19–25, verify idempotency, compare row counts, and retain the migrated clone for local UI.
- [ ] Run `EXPLAIN (ANALYZE, BUFFERS)` for queue/admin/overview aggregates and record any required index correction.
- [ ] Run full qualification, broad review, build, diff, and signed-commit checks.

## Unresolved Questions

None.
