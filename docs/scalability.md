# DevRadar Scalability

Where DevRadar stops scaling, what signals say it is about to, and what to change
when it does.

_Query and storage figures measured 2026-08-15 against an isolated local restore
of the production backup `thingz-20260815-050144.sql.gz` (3 accounts, 378 SBOMs).
Those timings are local Docker PostgreSQL 16, so absolute milliseconds differ
from Cloud SQL — the complexity classes and ratios are what transfer. Scan-job
figures are from production execution `devradar-saas-scan-pm6fp` (2026-08-15).
See "Refreshing this analysis" to rerun both._

**Every number here is measured.** An earlier revision of this document carried
a "~72 min corpus budget" inherited from a comment in `run/devradar/cloudrun.tf` in the private `thingzio/infra` repository
and built the 2x scenario on it; the first real measurement came in at 16 min
and moved the conclusion by 3x. Do not reintroduce an estimate here without
labelling it as one.

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
is not the constraint. The per-SBOM cost is **2.6 s across both scanners** —
measured on execution `devradar-saas-scan-pm6fp`, which scanned a full 371-SBOM
backlog in 16 min 02 s (742 scanner invocations in 962 s). SBOM scanning is cheap
once the vulnerability DBs are resident: there is no image pull and no layer
extraction.

| Fleet | SBOMs/tick | Tick wall-clock | Full-corpus pass |
|-------|-----------:|----------------:|-----------------:|
| 378 (today) | ~4 | ~10 s | **16 min** (measured) |
| 756 (2x) | ~8 | ~20 s | ~33 min |
| 3,780 (10x) | ~39 | ~1.7 min | ~2.7 h |

The job timeout is 5400 s (90 min). A full-corpus pass consumes **18%** of it
today, and the timeout is not crossed until roughly **2,080 SBOMs (~5.5x)**.

A full-corpus pass only happens on a **herd**: cold start, an outage longer than
the staleness window, a scanner DB version bump, or a bulk forced rescan. A herd
fits inside the timeout through 2x and well beyond; it stops fitting near 5.5x,
and at 10x it needs about twice the budget.

Treat 2.6 s/SBOM as a central estimate with a fat tail. `ScanTimeout` bounds a
single SBOM×scanner invocation at 10 min, so one pathological input can add most
of that on its own. The measured run had fresh DBs and hit no such input.

Degradation is graceful rather than catastrophic. `ListScannableSBOMs` orders by
`sb.submitted_at` ascending, which is stable, and each completed scan writes a
`devradar_scan_run` that drops the SBOM out of the due set. A killed execution
keeps its progress and the next tick resumes. Two consequences remain:
oldest-submitted wins, so a newly submitted SBOM waits behind the entire backlog
and submission-to-first-result latency is what users actually feel; and
`max_retries = 1` means every over-budget execution reports failure to ops.

## Scenarios

**2x (~750 SBOMs).** DB ~570 MB in year one, ~1 GB in year two; disk autoresize
absorbs it. Dashboard ~100 ms. Scan steady state ~20 s/tick, and even a full herd
finishes in ~33 min against a 90 min budget. **Nothing breaks.** No design change
required — this scenario is uneventful on every axis measured.

**10x (~3,800 SBOMs, ~30 accounts).** DB ~660 MB bounded plus **2.2 GB/year**
accumulating — ~2.9 GB at year one, ~7 GB at year three. Scan steady state
~1.7 min/tick; the ScanMaxAge design genuinely scales, and only the herd path
(~2.7 h) exceeds the job timeout. Dashboard ~500 ms on the rollup path and
~4.8 s for any account with a suppressing VEX statement. The shared database,
not the application, is what gives out first.

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

**4. Scanner vulnerability-DB growth — a scaling axis with no fleet term.** This
is the one that has actually caused an outage. Cloud Run's filesystem is
memory-backed tmpfs, and `Dockerfile.scan` fetches both scanner DBs into `$HOME`
at job start, so the DBs are charged against the job's memory limit. They grow
monotonically upstream, so the ceiling is consumed *by doing nothing* — a fleet
of zero SBOMs would eventually hit it. On 2026-08-15 the job began failing on
SIGBUS (signal 7, not the usual SIGKILL: Trivy `mmap`s its BoltDB, and an mmap
page tmpfs cannot back raises SIGBUS) partway through Trivy's DB download.
Raised 2Gi → 4Gi previously, 4Gi → 8Gi in that incident. **Doubling again is not
the fix** — the next occurrence should move the caches off tmpfs, via an NFS
volume rather than GCS FUSE, because BoltDB `mmap` over FUSE is unreliable.

**5. Scan wall-clock under herd conditions.** `task_count = 1`,
`parallelism = 1`, and a sequential `scanOne` loop. Demoted after measurement:
the herd fits the timeout until ~5.5x, so this is no longer a near-term
constraint.

**6. Unbounded retention.** A storage, backup-window, and PITR cost problem
before it is a latency problem.

**7. `ListImages` has no `LIMIT`.** It returns every image for an account —
~3,480 rows at 10x, on a 512 Mi service capped at 3 instances.

The due-set query is explicitly *not* on this list: 8.4 ms today and index-driven,
projecting to ~85 ms at 10x for 96 executions a day.

## Triggers

| Signal | Threshold | Action |
|--------|-----------|--------|
| Cloud SQL CPU (shared instance) | >50% sustained | Raise tier, or split devradar onto its own instance. **Watch first.** |
| Scan job memory utilization at startup | >80% peak | Scanner DBs are outgrowing the limit again; move caches off tmpfs |
| Scan job execution failures | any | Check for SIGBUS during DB download before assuming a scan bug |
| Scan execution wall-clock | >60 min | Herd approaching the 90-min ceiling; parallelize `scanOne` or shard by account |
| Due-set size at tick start | >1,500 SBOMs | Approaching the ~2,080 full-pass ceiling |
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

**Before 2x.** Nothing is required. The measurement removed the only item that
was here — parallelizing `scanOne` was justified by the inherited ~72 min
estimate, and at a measured 16 min it is a **cost** lever, not a scaling one. It
stays tracked as `docs/cost-optimization.md` item 5 (which already notes that
per-SBOM temp names are unique via `safe(id)` and that `ScanPoolConfig` needs a
connection bump), to be picked up on cost grounds if at all.

**Before 10x.** Move devradar to its own Cloud SQL instance or a tier with real
CPU headroom. Give the VEX-aware path a rollup so `fleetStatsLive` stops
re-aggregating findings per request. Move the scanner DB caches off tmpfs before
the memory ceiling is hit a third time. Consider interleaved or newest-first work
ordering so new submissions are not starved behind a backlog — at 10x a herd runs
~2.7 h, long enough for oldest-first to be felt.

## Refreshing this analysis

**Storage and query figures** come from an isolated restore, using the same
local-only procedure as the pre-release rehearsal in `DEPLOYMENT.md`. To rerun
after fleet growth: restore the latest backup into a scratch database, then
measure

- per-table sizes and row counts (`pg_total_relation_size` over `devradar_%`),
- per-account distribution of SBOMs, findings, packages, events, and scan runs,
- accumulation windows (`min`/`max` timestamps) for the unbounded tables,
- `EXPLAIN (ANALYZE, BUFFERS)` on `FleetStats` (both paths), `ListScannableSBOMs`,
  and `NextAlertEvents`.

Verify every URL resolves to localhost before running anything destructive, and
never point these at Cloud SQL.

**Scan-job figures** cannot be measured from a restore — they need a real
execution. The cheap way to get a full-corpus number is to catch a herd: after
any scan outage the whole fleet is past due, so the next execution is a full
pass. Otherwise force one. Then:

```
gcloud logging read \
  'resource.labels.job_name="devradar-saas-scan" AND labels."run.googleapis.com/execution_name"="<execution>"' \
  --project=thingzio --order=asc --limit=50 \
  --format='table(timestamp, jsonPayload.msg, jsonPayload.sbom_count, jsonPayload.scanned)'
```

`scan run starting` → `scan run complete` is the wall clock; divide by
`sbom_count` for per-SBOM cost, and by `sbom_count × scanners` for per-invocation
cost. Divide the 5400 s timeout by per-SBOM cost to get the fleet size at which a
herd stops fitting. Note that `scanOne` logs nothing per SBOM, so a long run
produces no progress output at all; live progress comes from the database:

```sql
SELECT count(DISTINCT sbom_id) FROM devradar_scan_run WHERE scanned_at > '<run start>';
```

## Caveats

The 2x and 10x figures are linear extrapolations from a three-account sample
dominated by one account, so variance in per-account *shape* — SBOM size, finding
density, VEX adoption — is unmodeled. Treat them as order-of-magnitude planning
inputs, not forecasts.
