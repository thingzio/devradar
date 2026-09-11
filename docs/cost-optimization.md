# DevRadar Cost Optimization

Findings and actions from the 2026-07-25 thingz.io billing review. DevRadar had
not had a cost pass since going live (`serve`/`scan` 2026-07-05, `deliver`/
sharing 2026-07-15) and was already ~40% of GCP spend (~$77-78/mo of ~$187/mo
projected).

Full billing context and cross-service (DevPulse/DevTrace/Cloud SQL) numbers
live in the shared `tco.md` (source of truth for account/billing detail, not
committed to this repo). This doc tracks only DevRadar-specific options and
their status.

## Applied

| # | Action | Change | Est. impact/mo | Status |
|---|--------|--------|----------------:|--------|
| 1 | Stretch `devradar-deliver` cron `* * * * *` → `*/5 * * * *` | `infra/run/scheduler.tf` | ~-$41 | Applied 2026-07-25 (`terraform apply`) |
| 2 | Raise scan staleness window 12h → 24h | New `var.scan_max_age` (default `24h`) sets `DEVRADAR_SCAN_MAX_AGE` on the `devradar-scan` Cloud Run Job; code default (12h) untouched — infra-only, no image rebuild | ~-$10 to ~-$15 (more as fleet grows) | Applied 2026-07-25 (`terraform apply`) |

Both are pure Terraform changes — no application code changed, no new release
needed. `DEVRADAR_SCAN_MAX_AGE` was already an env-var-driven tunable
(`pkg/config/env.go`); it just wasn't wired to Terraform before now, so the
scan job silently ran on the 12h code default. `deliver`'s lease durations
(5 min row lease, 6 min slot lease) already tolerate the slower cadence with no
code change.

**Verify against actuals before declaring done:** re-run the billing review
(`reviewing-thingz-billing` skill) after a few days of `*/5` deliver + 24h scan
data and confirm the daily net drops roughly as projected. If it doesn't land
close to projection, re-open this doc rather than assuming the fix worked.

## Deferred — pending review

These came out of the same review but were not applied yet; revisit after
option 1/2 are confirmed against actuals.

| # | Option | Est. impact/mo | Effort | Risk |
|---|--------|----------------|--------|------|
| 3 | Fold `deliver` into `scan`'s per-tick maintenance; drop the `devradar-deliver` job + scheduler entirely | ~-$50 (full deliver job cost) | Medium | Medium — couples email-send failure domain to scan job; needs `SEND_API_KEY`/`DEVRADAR_DELIVERY_KEY` secrets + IAM added to scan's service account; invite latency moves to scan cadence (15-30 min) |
| 4 | Event-driven delivery: attempt send inline (bounded timeout) right after the outbox write in `handleCreateInvitation`/`handleResendInvitation`/`handleChangeInvitationRole`; keep outbox+lease as retry-only fallback swept infrequently | ~-$50, plus better UX (near-instant vs polling) | Medium-High | Medium — must not block the HTTP response; durable fallback path still needs testing |
| 5 | Parallelize SBOM scanning within one scan execution (bounded goroutines + semaphore, same pattern as `pkg/delivery`) instead of the current sequential loop in `scanDue`/`scanOne` | -15-30% of scan's compute cost (cuts billed wall-clock, not just idle-tick overhead) | Medium | Low-Medium — temp file names are already unique per SBOM (`safe(id)`), so parallel-safe; needs a concurrency-safety pass and a `ScanPoolConfig` conn bump |
| 6 | Scan cron `*/15` → `*/30` | ~-$2-4 now, shrinking benefit as fleet grows (only cuts idle-tick cold starts, not the dominant per-SBOM cost) | Low | Low — new-SBOM pickup latency 15→30 min |
| 8 | Instrument scan cost-per-SBOM before leaning on 5/6 | $0 now, informs sizing | Medium | None |
| 9 | GCS lifecycle policy on the `sboms` bucket (no expiry today) | Negligible now, preventive | Low | Low |

Note: numbering matches the original review (option 7, raising the GCP budget
alert, was explicitly skipped — it's account-level, not DevRadar-specific, and
carries no cost impact).

**Decision needed before 3 or 4:** pick one, not both. Option 3 is the
pragmatic "one fewer Cloud Run Job" consolidation; option 4 is the
architecturally cleaner fix but touches request-handling code and needs UX
sign-off on latency expectations.

Out of scope for this repo: Cloud SQL 1yr CUD (`thingzio-pg` is shared infra,
not DevRadar-owned) and `devtrace-saas-serve` min-instance change (separate
service/repo) — tracked in `tco.md` instead.
