# Overview Signal Launchpad Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn `/overview` into a compact launchpad for current posture, remediation work, trend direction, license policy, and digest comparison.

**Architecture:** Preserve FleetStats, unread alerts, charts, and top images as the core page contract. Add one tenant-scoped comparison-readiness query and four independent best-effort signal loaders; reuse the existing work, trend, and license domain reads so Overview links to canonical workflows instead of duplicating them.

**Tech Stack:** Go 1.26, PostgreSQL 16, `database/sql`, `html/template`, existing server-rendered CSS.

## Global Constraints

- `/overview` remains a compact signed-in maintainer launchpad, not an executive report.
- New work, trend, license, and comparison signals are additive and fail independently.
- Reuse canonical work ordering, exact observed snapshots, read-time license policy evaluation, and active distinct digests.
- No synthetic history, opaque score, fleet-wide upgrade recommendation, or safe/compatible/reachable/compliant claim.
- Every store read takes `tenantID` first and proves cross-tenant isolation.
- No migration, dependency, client-side fetch, font, gradient, or animation.
- No deployment or release.

---

### Task 1: Tenant-scoped comparison readiness

**Files:**
- Modify: `pkg/data/postgres/compare.go`
- Modify: `pkg/data/postgres/compare_test.go`

**Interfaces:**
- Produces: `func (s *Store) ComparisonReadyRepositoryCount(ctx context.Context, tenantID string) (int, error)`.
- Consumes: active `devradar_sbom` rows grouped by tenant and repository.

- [ ] **Step 1: Write the failing isolation/count test**

Add `TestComparisonReadyRepositoryCount_DistinctActiveDigestsAndTenantIsolation`. Seed one tenant with two active rows for the same digest, then a second active digest in the same repository; seed another single-digest repository, an archived distinct digest, and a foreign tenant with two digests. Assert the first tenant returns `1`, the foreign tenant returns `1`, and an empty tenant returns `0`.

- [ ] **Step 2: Verify RED**

Run:

```bash
go test ./pkg/data/postgres -run TestComparisonReadyRepositoryCount -count=1
```

Expected: compile failure because `ComparisonReadyRepositoryCount` does not exist.

- [ ] **Step 3: Implement the focused aggregate**

Add:

```go
func (s *Store) ComparisonReadyRepositoryCount(ctx context.Context, tenantID string) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `
		SELECT count(*)
		FROM (
			SELECT repository
			FROM devradar_sbom
			WHERE tenant_id=$1 AND status='active'
			GROUP BY repository
			HAVING count(DISTINCT digest) >= 2
		) ready`, tenantID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count comparison-ready repositories: %w", err)
	}
	return count, nil
}
```

- [ ] **Step 4: Verify GREEN**

Run the focused test again. Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/data/postgres/compare.go pkg/data/postgres/compare_test.go
git commit -S -m "feat(posture): count comparison-ready repositories"
```

### Task 2: Reusable work rows and independent Overview signals

**Files:**
- Create: `pkg/server/overview_test.go`
- Modify: `pkg/server/ui_work.go`
- Modify: `pkg/server/ui_overview.go`
- Modify: `pkg/server/templates/overview.html`
- Modify: `pkg/server/static/css/app.css`

**Interfaces:**
- Consumes: `FleetCVEs(ctx, tenantID, minSeverity, ..., "risk", "desc", "", 3)`, `TenantPostureTrend(ctx, tenantID, 30)`, `GetLicensePolicy`, `FleetLicenseStats`, and `ComparisonReadyRepositoryCount`.
- Produces: `workRows([]postgres.FleetCVE) []workRow`; compact Overview signal models with per-signal unavailable flags.

- [ ] **Step 1: Write failing route tests for content, empty states, and isolation**

Add integration tests that seed four risk-ranked CVEs, two recorded posture points, a non-empty license policy with a violating package, two active digests in one repository, and foreign-tenant sentinel values. Authenticate as the owning tenant and assert:

```go
for _, want := range []string{
	"Current posture", "What needs attention", "Full work queue",
	"Direction of travel", "Day-over-day change", "View trends",
	"License policy", "policy violation", "View licenses",
	"Compare releases", "1 repository ready", "Choose digests",
} {
	if !strings.Contains(body, want) { t.Errorf("missing %q", want) }
}
if strings.Count(body, `class="overview-work-item`) != 3 { t.Fatal("work preview must be capped at three") }
for _, forbidden := range []string{"foreign-sentinel", "safe", "compatible", "reachable", "compliant"} {
	if strings.Contains(strings.ToLower(body), forbidden) { t.Fatalf("forbidden/leaked %q", forbidden) }
}
```

Add table-driven cases for no snapshots (`Coverage begins with the first snapshot`), one point (`No prior snapshot`), a date gap (`Change since YYYY-MM-DD`), empty policy (`No policy configured`), configured zero violations, and zero comparison-ready repositories. Preserve the existing unread-alert degradation and no-images onboarding assertions. An active image with zero findings must render current posture rather than first-SBOM onboarding.

- [ ] **Step 2: Verify RED**

Run:

```bash
go test ./pkg/server -run 'TestOverviewSignals|TestOverviewSignalEmptyStates|TestOverviewTrackedImageWithNoFindings' -count=1
```

Expected: failures because the action band and signal copy are absent.

- [ ] **Step 3: Extract the existing work-row mapper**

Move the loop in `handleWorkQueue` into:

```go
func workRows(items []postgres.FleetCVE) []workRow {
	rows := make([]workRow, 0, len(items))
	for _, item := range items {
		agreement := "Single-scanner signal"
		if item.ScannerCount > 1 { agreement = fmt.Sprintf("%d scanners agree", item.ScannerCount) }
		age := "first seen just now"
		if !item.FirstSeen.IsZero() { age = "first seen " + humanizeSince(time.Since(item.FirstSeen)) }
		rows = append(rows, workRow{
			CVE: item.CVE, Severity: item.WorstSev, KEV: item.KEV, Fixable: item.Fixable,
			EPSS: formatEPSS(item.EPSS), ImageCount: item.ImageCount, FindingCount: item.FindingCount,
			Age: age, Agreement: agreement, Repositories: item.Repositories, AllVEXd: item.AllVEXd,
		})
	}
	return rows
}
```

Use it from both Work and Overview so ranking explanations and scanner/VEX metadata cannot drift.

- [ ] **Step 4: Add explicit signal view models and helper logic**

Extend `overviewView` with `WorkItems`, `WorkUnavailable`, `Trend`, `TrendUnavailable`, `License`, `LicenseUnavailable`, `ComparisonReady`, and `ComparisonUnavailable`. Define small focused structs. Build trend copy from the final two observed points only:

```go
func overviewTrend(points []postgres.TenantPosturePoint) overviewTrendSignal {
	if len(points) == 0 { return overviewTrendSignal{Empty: true} }
	cur := points[len(points)-1]
	out := overviewTrendSignal{HasData: true, Date: cur.Date.Format(time.DateOnly), Total: cur.Total}
	if len(points) == 1 { out.Comparison = "No prior snapshot"; return out }
	prev := points[len(points)-2]
	out.Delta = cur.Total - prev.Total
	if prev.Date.AddDate(0, 0, 1).Equal(cur.Date) { out.Comparison = "Day-over-day change" } else { out.Comparison = "Change since " + prev.Date.Format(time.DateOnly) }
	return out
}
```

License state must distinguish `policy.IsEmpty()` from configured zero violations. Change `HasData` from `fs.Total > 0` to `fs.Images > 0` so onboarding means no tracked images.

- [ ] **Step 5: Load every new signal best-effort**

After core FleetStats/ListRepoImages succeeds, invoke each domain read independently. Log failures with `tenant_id` and set only that signal's unavailable flag. Use limit `3`, sort `risk desc`, default filter, and a bounded 30-day trend window. Call `FleetLicenseStats` only after `GetLicensePolicy` succeeds. Do not return HTTP 500 for any new signal failure.

- [ ] **Step 6: Render the compact action band**

After “Current posture,” add a semantic `.overview-action-grid`: a two-column work preview and a narrow signal stack. Work items link to `/cves/<CVE>` and show KEV, fix availability, severity, EPSS, blast radius, age, and agreement. Trend links to `/trends`; license links to `/licenses` and, for no policy, `/tokens`; compare links to `/dashboard`. Render every unavailable/empty state exactly as the approved spec requires.

Add only scoped CSS for `.overview-action-grid`, `.overview-work-preview`, and `.overview-signal-stack`, reusing existing tokens and stacking to one column under the existing mobile breakpoint.

- [ ] **Step 7: Verify focused and adjacent behavior**

Run:

```bash
go test -race ./pkg/server ./pkg/data/postgres -run 'Overview|ComparisonReadyRepositoryCount|WorkQueue|Trends' -count=1
```

Expected: PASS.

- [ ] **Step 8: Run qualification and commit**

Run `make qualify`, `go build ./...`, and `git diff --check`. Expected: all exit zero and coverage remains at least 45%.

```bash
git add pkg/server/overview_test.go pkg/server/ui_work.go pkg/server/ui_overview.go pkg/server/templates/overview.html pkg/server/static/css/app.css
git commit -S -m "feat(ui): make overview an actionable launchpad"
```

## Unresolved Questions

None.
