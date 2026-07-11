# Alert Action Loop Completion Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Generate one idempotent repository-posture-regression alert for a regressing new digest and link every browser alert to its relevant work and comparison evidence.

**Architecture:** Reuse immutable `CompareSBOMs` evidence. The alert evaluator optionally asks the concrete store for the immediately preceding active generation when an eligible image-caused added event already matches policy; a partial unique index collapses every triggering finding for one SBOM to one regression alert. Alert detail resolves work, previous-generation comparison, and conservative newer-digest recommendation links best-effort.

**Tech Stack:** Go 1.26, PostgreSQL, existing alert evaluator/cursor, stdlib HTTP/templates.

## Global Constraints

- Alert generation remains outside `ApplyScan` and never blocks scan persistence.
- Regression alerts are prospective, tenant-scoped, image-caused, label-policy-aware, and idempotent.
- One new digest produces at most one `posture_regression` alert per tenant policy even when many finding events trigger evaluation or a batch retries.
- Comparison uses the immediate preceding active generation in the same tenant and repository by `(COALESCE(generated_at,submitted_at), id)`.
- A comparison link reports observed evidence only; “newer tracked digest with fewer relevant findings” requires the existing strict recommendation contract.
- Email, webhooks, acknowledgements, delivery history, and per-user state remain out of scope.
- No deployment or release.

---

### Task 1: Idempotent posture-regression alert generation

**Files:**
- Create: `pkg/data/postgres/sql/migrations/023_posture_regression_alert.sql`
- Create: `pkg/data/postgres/posture_alert.go`
- Create: `pkg/data/postgres/posture_alert_test.go`
- Modify: `pkg/data/postgres/alert.go`
- Modify: `pkg/data/postgres/alert_test.go`
- Modify: `pkg/alert/evaluator.go`
- Modify: `pkg/alert/evaluator_test.go`

**Interfaces:**
- Produce: `func (s *Store) ComparePreviousSBOM(ctx context.Context, tenantID, sbomID string) (*SBOMComparison, error)`; return `(nil,nil)` when no older active generation exists.
- Consume: existing `CompareSBOMs`, `AlertDraft`, and atomic `CommitAlertBatch` cursor contract.

- [ ] Write failing store tests proving immediate-previous selection, active/same-repository/tenant isolation, and regresses/improves results.
- [ ] Write failing evaluator tests proving an eligible image-added event can create its normal alert plus one regression draft, repeated same-SBOM events are collapsed within a pass, DB events do not run comparison, and detector failure is isolated without discarding the normal alert.
- [ ] Verify RED with `go test ./pkg/data/postgres ./pkg/alert -run 'PostureRegression|ComparePreviousSBOM' -count=1`.
- [ ] Add migration 023:

```sql
CREATE UNIQUE INDEX IF NOT EXISTS idx_devradar_alert_one_posture_regression
ON devradar_alert (tenant_id, policy_id, sbom_id, alert_kind)
WHERE alert_kind = 'posture_regression';
```

- [ ] Implement `ComparePreviousSBOM` with one tenant-scoped predecessor query ordered by effective timestamp and ID descending, followed by the existing exact comparison.
- [ ] Add an optional evaluator interface:

```go
type postureRegressionStore interface {
	ComparePreviousSBOM(context.Context, string, string) (*postgres.SBOMComparison, error)
}
```

Evaluate regression only after `Match` returned a normal eligible draft for an `added` event with cause `image`. Maintain a per-pass `seenSBOM` set. Append a `KindPostureRegression` draft only when `comparison.Verdict == postgres.PostureRegresses`; isolate comparison errors as `AlertFailure` while retaining normal drafts.
- [ ] Change alert insert conflict handling to targetless `ON CONFLICT DO NOTHING` so both the event natural key and the partial regression index make retries harmless.
- [ ] Run `go test -race ./pkg/data/postgres ./pkg/alert ./pkg/scan -count=1` and commit with `git commit -S -m "feat(alerts): detect repository posture regressions"`.

### Task 2: Alert-to-action browser links

**Files:**
- Modify: `pkg/server/ui_alerts.go`
- Modify: `pkg/server/templates/alert.html`
- Modify: `pkg/server/templates/work.html`
- Modify: `pkg/server/alerts_test.go`

**Interfaces:**
- Consume: `ComparePreviousSBOM`, `RecommendUpgrade`, and canonical CVE detail routes.
- Produce: work fragment IDs `work-<CVE>` and best-effort comparison/recommendation URLs on `alertDetailView`.

- [ ] Write failing authenticated and cross-tenant route tests for a work link, immediate previous-generation comparison link, and strict newer-digest recommendation link.
- [ ] Give each work queue article a stable escaped `id="work-{{.CVE}}"`; build the alert link as `/work#work-<escaped exposure>`.
- [ ] In `handleAlertDetail`, resolve `ComparePreviousSBOM` and `RecommendUpgrade` for the alert SBOM. Treat errors as logged additive degradation rather than a page failure. Encode exact `from`/`to` query parameters with `url.Values`.
- [ ] Render an “Act on this” section with:
  - “Open in work queue” for the triggering CVE;
  - “Compare with preceding tracked digest” when previous evidence exists;
  - “Newer tracked digest with fewer relevant findings” only when `RecommendUpgrade` returns a candidate.
- [ ] Preserve existing CVE, image, digest, read-state, and CSRF behavior; do not use “safe,” “compatible,” or “reachable.”
- [ ] Run `go test -race ./pkg/server ./pkg/data/postgres ./pkg/alert -count=1`, then `make qualify`, `go build ./...`, and `git diff --check`.
- [ ] Commit with `git commit -S -m "feat(alerts): link alerts to remediation evidence"`.

## Unresolved Questions

None.
