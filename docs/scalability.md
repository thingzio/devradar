# DevRadar Scalability

Where DevRadar stops scaling, what signals say it is about to, and what to change
when it does.

_Measured 2026-08-15 against an isolated local restore of the production backup
`thingz-20260815-050144.sql.gz` (3 accounts, 378 SBOMs). Timings are local Docker
PostgreSQL 16, so absolute milliseconds differ from Cloud SQL — the complexity
classes and ratios are what transfer. See "Refreshing this analysis" to rerun it._

Cost-side actions overlap with several items here; `docs/cost-optimization.md`
tracks those with effort and risk. This document is about breaking points.

## Unit economics

One account holds 92% of production data (348 of 378 SBOMs, 93k of 99k
findings), so per-account averages mislead. Size everything **per SBOM**.

| Table | Per SBOM | Grows with |
|-------|---------:|------------|
| `devradar_finding` (261 rows) | 108 KB | SBOM count — **bounded**, rewritten per scan |
| `devradar_sbom_package` (174 rows) | 65 KB | SBOM count — **bounded** |
| `devradar_sbom` + `devradar_sbom_rollup` | 2 KB | SBOM count — **bounded** |
| `devradar_scan_run` (~1.3 rows/day) | 0.6 KB/**day** | SBOM count × **time** |
| `devradar_finding_event` (~1 row/day) | 0.8 KB/**day** | SBOM count × **time** |
| `devradar_alert_event_queue`, snapshots, alerts | ~0.2 KB/**day** | SBOM count × **time** |

**DB size ≈ (SBOMs × 175 KB) + (SBOMs × 0.55 MB × years).**

The second term has no ceiling and dominates after roughly four months at any
fleet size. Total devradar footprint at measurement: 173 MB.

## Bounded vs unbounded tables

`PurgeExpiredAuth` reclaims sessions, login tokens, and both token-flash tables.
`pkg/ratelimit` windows `devradar_rate_event`. Posture snapshots replace the
current day in place.

Nothing else is ever deleted. `devradar_finding_event`, `devradar_scan_run`,
`devradar_alert`, `devradar_alert_event_queue`, `devradar_scan_failure`, and
`devradar_audit_event` accumulate for the life of the account.

`devradar_alert_event_queue` shows the benign shape of this: 17,538 rows, **zero
pending** — fully drained, every processed row retained. The partial
`WHERE processed_at IS NULL` index keeps the drain query proportional to the
pending set, so this costs storage, not latency.

`devradar_finding_event` is already range-partitioned by month, so the retention
mechanism (`DROP PARTITION`) exists and is cheap. It is simply never invoked.
Retiring a partition is the single highest-leverage storage change available.

## Scan cadence

Production overrides the 12h code default: `var.scan_max_age = "24h"` with
`var.scan_schedule = "*/15"`, so each SBOM is scanned about once a day across
96 ticks. The measured rate corroborates it — ~500 `scan_run` rows/day across
two scanners is ~250 SBOMs/day out of 378.

Steady state therefore spreads work thinly, and the sequential loop in `scanDue`
is not the constraint most of the time:

| Fleet | SBOMs/tick | Tick wall-clock | Full-corpus pass |
|-------|-----------:|----------------:|-----------------:|
| 378 (today) | ~4 | ~45 s | **~72 min** |
| 756 (2x) | ~8 | ~1.5 min | ~2.4 h |
| 3,780 (10x) | ~39 | ~7 min | ~11.5 h |

The job timeout is 5400 s (90 min), sized in `infra/saas/cloudrun.tf` against
"the ~72 min corpus budget" — already 80% consumed at today's fleet.

A full-corpus pass only happens on a **herd**: cold start, an outage longer than
the staleness window, a scanner DB version bump, or a bulk forced rescan. At 2x
a herd exceeds the timeout; at 10x it exceeds it by 8x.

Degradation is graceful rather than catastrophic. `ListScannableSBOMs` orders by
`sb.submitted_at` ascending, which is stable, and each completed scan writes a
`devradar_scan_run` that drops the SBOM out of the due set. A killed execution
keeps its progress and the next tick resumes. Two consequences remain:
oldest-submitted wins, so a newly submitted SBOM waits behind the entire backlog
and submission-to-first-result latency is what users actually feel; and
`max_retries = 1` means every over-budget execution reports failure to ops.

## Scenarios

**2x (~750 SBOMs).** DB ~570 MB in year one, ~1 GB in year two; disk autoresize
absorbs it. Dashboard ~100 ms. Scan steady state ~1.5 min/tick. The only break is
the herd path. No design change required.

**10x (~3,800 SBOMs, ~30 accounts).** DB ~660 MB bounded plus **2.2 GB/year**
accumulating — ~2.9 GB at year one, ~7 GB at year three. Scan steady state
~7 min/tick, still inside the timeout; the ScanMaxAge design genuinely scales.
Dashboard ~500 ms on the rollup path and ~4.8 s for any account with a
suppressing VEX statement. The shared database, not the application, is what
gives out first.

## Ranked constraints

**1. The shared Cloud SQL instance.** `db-custom-1-3840` — 1 vCPU, 3.75 GB,
ZONAL, shared with devpulse and devtrace. `FleetStats` is ~50 ms of nearly pure
CPU today and ~500 ms at 10x, on a single core, which saturates at roughly two
dashboard loads per second **across all three products**. This is infrastructure,
not code, and it is the first hard wall.

**2. Two sequential scans in the hottest query.** `fleetStatsRollup` states that
"the partial KEV index keeps it cheap" (`pkg/data/postgres/read_images.go`), but
the measured plan is a full `Seq Scan` over `devradar_finding` — 98,616 rows,
24 ms. The sibling `MAX(sr.scanned_at)` sub-select seq-scans all 33,768
`devradar_scan_run` rows for 11 ms. Together they are ~70% of a 50 ms query. Both
grow linearly, and `scan_run` grows on the time axis even at a flat fleet size.

**3. The VEX cliff.** One `not_affected` statement moves an account off the
rollup fast path onto `fleetStatsLive`, which runs eleven
`COUNT(DISTINCT (f.sbom_id, f.finding_id))` aggregates plus a correlated
suppression subquery per finding row. Measured on the same account shape:
**50 ms → 480 ms**, roughly 5 s at 10x. This is a step function triggered by a
customer action, not by growth, so it can arrive at any fleet size.

**4. Scan wall-clock under herd conditions.** `task_count = 1`,
`parallelism = 1`, and a sequential `scanOne` loop.

**5. Unbounded retention.** A storage, backup-window, and PITR cost problem
before it is a latency problem.

**6. `ListImages` has no `LIMIT`.** It returns every image for an account —
~3,480 rows at 10x, on a 512 Mi service capped at 3 instances.

The due-set query is explicitly *not* on this list: 8.4 ms today and index-driven,
projecting to ~85 ms at 10x for 96 executions a day.

## Triggers

| Signal | Threshold | Action |
|--------|-----------|--------|
| Cloud SQL CPU (shared instance) | >50% sustained | Raise tier, or split devradar onto its own instance. **Watch first.** |
| Scan execution wall-clock | >45 min | Herd risk is real; parallelize `scanOne` or shard by account |
| Scan job failure rate | any sustained non-zero | Already hitting the 90-min ceiling |
| Due-set size at tick start | >150 SBOMs | Steady state is drifting toward full-pass behavior |
| Submission → first result, p95 | >30 min | Oldest-first ordering is starving new submissions |
| Accounts with suppressing VEX | ≥1 with >20k findings | The 480 ms path is now someone's normal |
| `devradar_finding` rows | >500k | KEV seq scan crosses ~120 ms |
| `devradar_scan_run` rows | >250k | `MAX(scanned_at)` seq scan crosses ~80 ms |
| devradar DB size | >5 GB | Backup window and PITR cost become operational concerns |

## Remediation by horizon

**Now, cheap.** Serve the KEV count and `MAX(scanned_at)` from indexes or the
rollup — that is ~70% of the dashboard query for no design change. Add a
retention sweep that drops aged `devradar_finding_event` partitions and prunes
processed `devradar_alert_event_queue` rows and old `devradar_scan_run` history.
`docs/cost-optimization.md` item 9 (GCS lifecycle on the `sboms` bucket) is the
blob-side equivalent.

**Before 2x.** Raise the job timeout, or parallelize `scanOne` with bounded
goroutines — tracked as `docs/cost-optimization.md` item 5, which already notes
that per-SBOM temp names are unique (`safe(id)`) and that `ScanPoolConfig` needs
a connection bump. Consider interleaved or newest-first work ordering so new
submissions are not starved during a backlog.

**Before 10x.** Move devradar to its own Cloud SQL instance or a tier with real
CPU headroom. Give the VEX-aware path a rollup so `fleetStatsLive` stops
re-aggregating findings per request.

## Refreshing this analysis

The numbers above come from an isolated restore, using the same local-only
procedure as the pre-release rehearsal in `DEPLOYMENT.md`. To rerun after fleet
growth: restore the latest backup into a scratch database, then measure

- per-table sizes and row counts (`pg_total_relation_size` over `devradar_%`),
- per-account distribution of SBOMs, findings, packages, events, and scan runs,
- accumulation windows (`min`/`max` timestamps) for the unbounded tables,
- `EXPLAIN (ANALYZE, BUFFERS)` on `FleetStats` (both paths), `ListScannableSBOMs`,
  and `NextAlertEvents`.

Verify every URL resolves to localhost before running anything destructive, and
never point these at Cloud SQL.

## Caveats

The 2x and 10x figures are linear extrapolations from a three-account sample
dominated by one account, so variance in per-account *shape* — SBOM size, finding
density, VEX adoption — is unmodeled. Treat them as order-of-magnitude planning
inputs, not forecasts.
