# Alert Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Persist tenant alert policies and channel-neutral alerts, then evaluate new actionable finding events idempotently after each scan pass without coupling alert failures to `ApplyScan`.

**Architecture:** A forward-only migration adds policy, alert, cursor, and evaluation-failure tables. `pkg/alert` owns deterministic policy matching; `pkg/data/postgres` owns cursor/event reads and atomic alert-insert/cursor-advance writes. The scan runner invokes the evaluator after enrichment so KEV state is current, but evaluator failure is logged and never changes scan success.

**Tech Stack:** Go 1.26, `database/sql`, PostgreSQL, stdlib `context`/`log/slog`, existing migration runner and integration-test helpers.

## Global Constraints

- Browser-only, tenant-scoped, and opt-in; no email or webhook delivery.
- Policy changes are prospective; enabling alerts never backfills historical events.
- Only `image`- and `db`-caused events are eligible; `tooling` never alerts.
- Alert generation remains outside `ApplyScan` and cannot block scan persistence.
- All tenant-scoped store methods take `tenantID` first and filter by it.
- Insert effects are idempotent under crash, retry, and overlapping job execution.
- Do not deploy, tag, push, or release.

---

### Task 1: Alert schema and storage models

**Files:**
- Create: `pkg/data/postgres/sql/migrations/019_alerts.sql`
- Create: `pkg/data/postgres/alert_test.go`
- Modify: `pkg/data/postgres/models.go`

**Interfaces:**
- Produces: `postgres.AlertPolicy`, `postgres.Alert`, `postgres.AlertEvent`, `postgres.AlertCandidate`, `postgres.AlertDraft`, `postgres.AlertFailure`, and `postgres.AlertPosition`.
- Produces tables: `devradar_alert_policy`, `devradar_alert`, `devradar_alert_cursor`, and `devradar_alert_failure`.

- [x] **Step 1: Add a failing migration integration test**

Add `TestAlertMigration_DefaultsAndConstraints` in `pkg/data/postgres/alert_test.go`. Seed a tenant with `seedTenantAndSBOM`, insert the default policy with only `tenant_id`, and assert `enabled=false`, `min_severity='medium'`, `alert_kev=true`, `alert_fix_available=true`, `include_image=true`, `include_db=true`, and an empty labels array. Attempt a second policy for the tenant and assert a unique-constraint error. Attempt an alert with `cause='tooling'` and assert the cause check rejects it.

```go
func TestAlertMigration_DefaultsAndConstraints(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	tenantID, sb := seedTenantAndSBOM(t, st)

	var policyID, gotTenantID, minSeverity string
	var enabled, alertKEV, alertFixAvailable, includeImage, includeDB bool
	var labels []string
	var createdAt, updatedAt time.Time
	err := st.DB().QueryRowContext(ctx, `
		INSERT INTO devradar_alert_policy (tenant_id) VALUES ($1)
		RETURNING id, tenant_id, enabled, min_severity, alert_kev,
		          alert_fix_available, include_image, include_db, labels,
		          created_at, updated_at`, tenantID).Scan(
		&policyID, &gotTenantID, &enabled, &minSeverity, &alertKEV,
		&alertFixAvailable, &includeImage, &includeDB, pq.Array(&labels),
		&createdAt, &updatedAt)
	if err != nil {
		t.Fatalf("insert policy: %v", err)
	}
	if gotTenantID != tenantID || enabled || minSeverity != data.SeverityMedium || !alertKEV ||
		!alertFixAvailable || !includeImage || !includeDB || len(labels) != 0 ||
		createdAt.IsZero() || updatedAt.IsZero() {
		t.Fatalf("unexpected policy defaults")
	}
	if _, err := st.DB().ExecContext(ctx,
		`INSERT INTO devradar_alert_policy (tenant_id) VALUES ($1)`, tenantID); err == nil {
		t.Fatal("second tenant policy should violate uniqueness")
	}
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_alert
		(tenant_id, policy_id, event_id, event_occurred_at, alert_kind, sbom_id,
		 repository, digest, finding_id, exposure, package, version, severity, score, cause)
		VALUES ($1,$2,1,now(),'new_finding',$3,'registry.test/app','sha256:x',
		        'finding','CVE-1','pkg','1','high',7.5,'tooling')`,
		tenantID, policyID, sb.ID); err == nil {
		t.Fatal("tooling-caused alert should violate cause check")
	}
}
```

- [x] **Step 2: Run the test and verify failure**

Run: `DATABASE_URL=postgres://devradar:devradar@localhost:5432/devradar?sslmode=disable go test ./pkg/data/postgres -run TestAlertMigration_DefaultsAndConstraints -count=1`

Expected: FAIL because migration 019 and alert models do not exist.

- [x] **Step 3: Add the migration**

Create `019_alerts.sql` with these exact invariants:

```sql
CREATE TABLE IF NOT EXISTS devradar_alert_policy (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL UNIQUE REFERENCES devradar_tenant(id) ON DELETE CASCADE,
    enabled             BOOLEAN NOT NULL DEFAULT false,
    min_severity        TEXT NOT NULL DEFAULT 'medium'
                        CHECK (min_severity IN ('critical','high','medium','low','negligible')),
    alert_kev           BOOLEAN NOT NULL DEFAULT true,
    alert_fix_available BOOLEAN NOT NULL DEFAULT true,
    include_image       BOOLEAN NOT NULL DEFAULT true,
    include_db          BOOLEAN NOT NULL DEFAULT true,
    labels              TEXT[] NOT NULL DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS devradar_alert (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID NOT NULL REFERENCES devradar_tenant(id) ON DELETE CASCADE,
    policy_id         UUID NOT NULL REFERENCES devradar_alert_policy(id) ON DELETE CASCADE,
    event_id          BIGINT NOT NULL,
    event_occurred_at TIMESTAMPTZ NOT NULL,
    alert_kind        TEXT NOT NULL CHECK (alert_kind IN ('new_kev','new_finding','fix_available','posture_regression')),
    sbom_id           TEXT NOT NULL REFERENCES devradar_sbom(id) ON DELETE CASCADE,
    repository        TEXT NOT NULL,
    digest            TEXT NOT NULL,
    finding_id        TEXT NOT NULL,
    exposure          TEXT NOT NULL,
    package           TEXT NOT NULL,
    version           TEXT NOT NULL,
    severity          TEXT NOT NULL,
    score             REAL NOT NULL,
    cause             TEXT NOT NULL CHECK (cause IN ('image','db')),
    read_at           TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, policy_id, event_id, event_occurred_at, alert_kind)
);
CREATE INDEX IF NOT EXISTS idx_devradar_alert_tenant_time
    ON devradar_alert (tenant_id, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_devradar_alert_tenant_unread
    ON devradar_alert (tenant_id, created_at DESC) WHERE read_at IS NULL;

CREATE TABLE IF NOT EXISTS devradar_alert_cursor (
    consumer         TEXT PRIMARY KEY,
    last_occurred_at TIMESTAMPTZ NOT NULL,
    last_event_id    BIGINT NOT NULL,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS devradar_alert_failure (
    id                BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    consumer          TEXT NOT NULL,
    event_id          BIGINT NOT NULL,
    event_occurred_at TIMESTAMPTZ NOT NULL,
    error             TEXT NOT NULL,
    occurred_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (consumer, event_id, event_occurred_at)
);
```

- [x] **Step 4: Add storage models**

Append the exact field shapes below to `pkg/data/postgres/models.go`.

```go
type AlertPolicy struct {
	ID, TenantID                         string
	Enabled                              bool
	MinSeverity                          string
	AlertKEV, AlertFixAvailable          bool
	IncludeImage, IncludeDB              bool
	Labels                               []string
	CreatedAt, UpdatedAt                 time.Time
}

type AlertEvent struct {
	ID                                   int64
	OccurredAt                           time.Time
	TenantID, SBOMID, Repository, Digest string
	FindingID, EventType, Exposure       string
	Package, Version, Severity, Cause    string
	Score                                float32
	KEV                                  bool
	Labels                               []string
}

type AlertDraft struct {
	PolicyID string
	Kind     string
	Event    AlertEvent
}

type AlertCandidate struct {
	Policy AlertPolicy
	Event  AlertEvent
}

type AlertFailure struct {
	Position AlertPosition
	Error    string
}

type AlertPosition struct {
	OccurredAt time.Time
	EventID    int64
}

type Alert struct {
	ID, TenantID, PolicyID               string
	EventID                               int64
	EventOccurredAt                       time.Time
	Kind, SBOMID, Repository, Digest     string
	FindingID, Exposure, Package, Version string
	Severity, Cause                       string
	Score                                 float32
	ReadAt                                *time.Time
	CreatedAt                             time.Time
}
```

- [x] **Step 5: Run migration tests**

Run: `DATABASE_URL=postgres://devradar:devradar@localhost:5432/devradar?sslmode=disable go test ./pkg/data/postgres -run 'TestAlertMigration|TestMigrate' -count=1`

Expected: PASS.

- [x] **Step 6: Commit**

```bash
git add pkg/data/postgres/sql/migrations/019_alerts.sql pkg/data/postgres/alert_test.go pkg/data/postgres/models.go
git commit -S -m "feat(alerts): add durable alert schema"
```

### Task 2: Deterministic policy matcher

**Files:**
- Create: `pkg/alert/alert.go`
- Create: `pkg/alert/alert_test.go`

**Interfaces:**
- Consumes: `postgres.AlertPolicy` and `postgres.AlertEvent`.
- Produces: `alert.Match(policy postgres.AlertPolicy, event postgres.AlertEvent) ([]postgres.AlertDraft, error)`.

- [x] **Step 1: Write table-driven failing tests**

Cover disabled policy, tooling cause, excluded image/db causes, nonmatching labels, below-threshold severity, unknown severity, KEV, fixed event, and overlap deduplication. An event that is both KEV and above threshold produces `new_kev` only; `fixed` produces `fix_available` only when enabled.

```go
func TestMatch(t *testing.T) {
	basePolicy := postgres.AlertPolicy{ID: "p1", Enabled: true, MinSeverity: data.SeverityMedium,
		AlertKEV: true, AlertFixAvailable: true, IncludeImage: true, IncludeDB: true}
	baseEvent := postgres.AlertEvent{EventType: data.EventAdded, Severity: data.SeverityHigh,
		Cause: data.CauseDB, Labels: []string{"prod"}}
	tests := []struct {
		name string
		policy postgres.AlertPolicy
		event postgres.AlertEvent
		want []string
	}{
		{"disabled", withEnabled(basePolicy, false), baseEvent, nil},
		{"new finding", basePolicy, baseEvent, []string{KindNewFinding}},
		{"kev wins", basePolicy, withKEV(baseEvent, true), []string{KindNewKEV}},
		{"fix available", basePolicy, withType(baseEvent, data.EventFixed), []string{KindFixAvailable}},
		{"label mismatch", withLabels(basePolicy, []string{"staging"}), baseEvent, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Match(tt.policy, tt.event)
			if err != nil { t.Fatal(err) }
			if !slices.Equal(tt.want, kinds(got)) { t.Fatalf("kinds = %v, want %v", kinds(got), tt.want) }
		})
	}
}
```

- [x] **Step 2: Verify failure**

Run: `go test ./pkg/alert -run TestMatch -count=1`

Expected: FAIL because `pkg/alert` does not exist.

- [x] **Step 3: Implement matching**

Define `KindNewKEV`, `KindNewFinding`, `KindFixAvailable`, and `KindPostureRegression`. `Match` returns an error when required event identity fields are empty or the cause/event type is unknown. Otherwise it returns nil unless the policy is enabled, the cause is enabled and actionable, and policy labels intersect event labels when policy labels are nonempty. Evaluate fixed first, KEV second, then `data.MeetsThreshold`; return at most one draft for a finding event.

- [x] **Step 4: Run matcher tests**

Run: `go test ./pkg/alert -count=1`

Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add pkg/alert
git commit -S -m "feat(alerts): add deterministic policy matcher"
```

### Task 3: Cursor-backed evaluator store

**Files:**
- Create: `pkg/data/postgres/alert.go`
- Modify: `pkg/data/postgres/alert_test.go`

**Interfaces:**
- Produces: `EnsureAlertPolicy(ctx, tenantID string) (*AlertPolicy, error)`.
- Produces: `NextAlertEvents(ctx, consumer string, limit int) ([]AlertCandidate, AlertPosition, bool, error)` where `initialized=true` means the cursor was created at the current event tail and no historical rows are returned.
- Produces: `CommitAlertBatch(ctx, consumer string, drafts []AlertDraft, failures []AlertFailure, end AlertPosition) error`.

- [x] **Step 1: Write failing integration tests**

Add tests proving cursor initialization skips historical events, a later event is returned once, repeated batch commit produces one alert, cursor updates never move backward, and a second tenant cannot observe the alert through tenant-scoped reads.

- [x] **Step 2: Verify failure**

Run: `DATABASE_URL=postgres://devradar:devradar@localhost:5432/devradar?sslmode=disable go test ./pkg/data/postgres -run TestAlertEvaluatorStore -count=1`

Expected: FAIL with missing store methods.

- [x] **Step 3: Implement cursor initialization and reads**

`NextAlertEvents` first executes an `INSERT ... SELECT` that initializes the named consumer to the maximum `(occurred_at,id)` event position, using epoch/zero when no events exist and `ON CONFLICT DO NOTHING`. If it inserted the row, return `initialized=true` and no events. Otherwise select the next bounded batch ordered by `(occurred_at,id) ASC`, join SBOM labels/repository/digest, enrichment KEV, and the tenant policy into `AlertCandidate`. Tenants without a policy receive an in-memory disabled default and remain non-alerting. Clamp limit to 100 when outside `1..1000`.

- [x] **Step 4: Implement atomic effects and monotonic cursor advance**

`CommitAlertBatch` begins one transaction, inserts every draft with `ON CONFLICT DO NOTHING`, records failures with `ON CONFLICT DO NOTHING`, and advances the cursor only when its current tuple is older:

```sql
UPDATE devradar_alert_cursor
SET last_occurred_at=$2, last_event_id=$3, updated_at=now()
WHERE consumer=$1
  AND (last_occurred_at,last_event_id) < ($2,$3)
```

Commit only after all effects succeed. A crash before commit leaves neither effects nor cursor movement; a crash after commit safely re-reads nothing.

- [x] **Step 5: Run integration tests**

Run: `DATABASE_URL=postgres://devradar:devradar@localhost:5432/devradar?sslmode=disable go test ./pkg/data/postgres -run TestAlert -count=1`

Expected: PASS.

- [x] **Step 6: Commit**

```bash
git add pkg/data/postgres/alert.go pkg/data/postgres/alert_test.go
git commit -S -m "feat(alerts): add cursor-backed alert storage"
```

### Task 4: Best-effort evaluator orchestration

**Files:**
- Create: `pkg/alert/evaluator.go`
- Create: `pkg/alert/evaluator_test.go`
- Modify: `pkg/scan/scan.go`
- Modify: `pkg/scan/scan_test.go`

**Interfaces:**
- Produces: `alert.Store` with `NextAlertEvents` and `CommitAlertBatch`.
- Produces: `alert.Evaluator{Store Store, Consumer string, BatchSize int}` and `Evaluate(ctx) (alert.Result, error)`.
- Scan integration uses optional interface assertion so existing scan fakes remain focused.

- [x] **Step 1: Write evaluator failure/retry tests**

Use an in-memory fake store to prove initialization returns zero, matching events create drafts, malformed-event matcher errors become isolated failures, multiple batches drain, cancellation stops, and store errors return with context.

- [x] **Step 2: Verify failure**

Run: `go test ./pkg/alert -run TestEvaluator -count=1`

Expected: FAIL because `Evaluator` does not exist.

- [x] **Step 3: Implement bounded draining**

Use consumer `browser-alerts-v1` and default batch size 100. Loop until the store returns fewer than the requested batch size. Check `ctx.Err()` before each batch. Match every event independently, collect drafts/failures, then call `CommitAlertBatch` with the final event position. Return counts for examined, created drafts, and failures.

- [x] **Step 4: Add best-effort scan invocation**

After `refreshEnrichment(ctx)`, assert whether `r.store` implements `alert.Store`. If so, invoke the evaluator and log either `alert evaluation failed` or completion counts. Never return its error from `Runner.Execute`.

- [x] **Step 5: Run package and integration tests**

Run: `go test ./pkg/alert ./pkg/scan ./pkg/data/postgres -count=1`

Expected: PASS (Postgres tests may skip when `DATABASE_URL` is unavailable).

- [x] **Step 6: Run the foundation quality gate**

Run: `go test -race ./pkg/alert ./pkg/scan ./pkg/data/postgres -count=1 && go vet ./pkg/alert ./pkg/scan ./pkg/data/postgres`

Expected: PASS.

- [x] **Step 7: Commit**

```bash
git add pkg/alert pkg/scan
git commit -S -m "feat(alerts): evaluate actionable scan events"
```

## Completion Boundary

This plan completes durable browser-channel alert generation only. Browser settings/list/detail, work queue, and comparison/trends remain separate plans and commits. No route exposes alerts yet, so shadow evaluation is the only possible behavior after this plan.

## Unresolved Questions

None. Tenant scope, prospective opt-in, browser-only delivery, and owner-controlled release gates are approved.
