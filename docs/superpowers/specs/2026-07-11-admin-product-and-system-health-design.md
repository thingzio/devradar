# Admin Product and System Health

Date: 2026-07-11

## Objective

Extend the operator console so it reflects DevRadar's new alert, posture, comparison, and license capabilities across the platform while preserving a clear boundary between product health and infrastructure health.

`/admin` remains the database-backed, aggregate product and pipeline view. `/admin/metrics` remains the infrastructure-only Cloud Monitoring view. The new surfaces are aggregate-only: they do not identify tenants or add tenant drill-down.

## Audience and Page Roles

The audience is the DevRadar operator. The operator needs to answer two different questions:

1. Is the product being adopted, and are its data pipelines producing useful, current results?
2. Is the underlying Cloud Run and Cloud SQL infrastructure healthy?

The pages keep those questions separate:

- `/admin` reports current application state derived from DevRadar's PostgreSQL tables.
- `/admin/metrics` reports service and database resource behavior from Google Cloud Monitoring.

No custom Prometheus, OpenTelemetry, or application metric exporter is introduced.

## Admin Dashboard Product Signals

The existing platform counts, severity distribution, finding-event activity, scan failures, VEX count, and day/week/month deltas remain intact.

A compact “Product health” section adds four aggregate groups.

### Alert adoption and evaluator health

Show:

- enabled alert policies;
- alerts created in the last 24 hours;
- currently unread alerts;
- eligible finding events waiting after the `browser-alerts-v1` cursor;
- age of the oldest waiting event when a backlog exists;
- evaluator failures recorded in the last 24 hours.

Backlog is the count of `image`- or `db`-caused finding events strictly after the durable cursor tuple. Zero backlog is displayed as “caught up.” Cursor age alone must not be presented as an incident because an idle event stream legitimately leaves the cursor unchanged. When backlog exists, the oldest pending event's age is the actionable lag signal.

### Posture coverage and actionable exposure

Show:

- tenant posture snapshot coverage for the current UTC date, expressed as tenants with a current snapshot over tenants with at least one active SBOM;
- canonical active vulnerability exposures;
- canonical active exposures with a scanner-reported fix;
- canonical active exposures present in CISA KEV.

An exposure is canonicalized per tenant, active SBOM, and finding identity so Grype and Trivy agreement is not double-counted. Fixable and KEV are unions of the scanners' evidence for that canonical exposure. These are observed exposure counts, not claims of runtime reachability. Snapshot coverage explicitly says “No active tenants” when the denominator is zero and never turns missing history into synthetic data.

### Comparison readiness

Show the number of tenant/repository groups that have at least two active, distinct digests. This indicates that exact digest comparison is available; it does not infer whether any candidate is newer, compatible, deployed, or safe.

### License-policy adoption

Show the number of tenants with a persisted license policy and the number with a non-empty enforcement policy. A policy is enforcing when it denies at least one category or includes at least one explicit deny exception. Allow-only or empty saved policies remain “configured” but are not described as enforcing.

## Data and Code Boundaries

All new cross-tenant SQL stays in `pkg/data/postgres/admin.go`, uses `Admin`-prefixed methods, and is callable only from the existing admin-gated handler. Tenant-facing store methods remain tenant-scoped and unchanged.

A focused `AdminProductHealth` read returns one render-ready aggregate model. It uses indexed, bounded aggregate queries and no per-tenant loop. It does not persist data and requires no migration.

The handler loads this model independently of the existing core platform counts. A product-health query failure is best-effort: the dashboard still renders its existing sections and shows “Product health temporarily unavailable.” The failure is logged with structured context and no tenant data.

## Infrastructure Metrics

`/admin/metrics` keeps its existing request rate, p99 latency, instance count, scan-job completion, and running-execution series. Add:

- Cloud Run serve CPU utilization;
- Cloud Run serve memory utilization;
- Cloud SQL CPU utilization;
- Cloud SQL active connections;
- Cloud SQL disk utilization.

The Cloud SQL instance is selected by `DEVRADAR_CLOUD_SQL_INSTANCE`, defaulting to the existing shared instance name `thingzio-pg`. The monitored resource filter includes both project and instance identity so unrelated databases are excluded.

These remain raw Cloud Monitoring series collected with the page's existing bounded timeout and concurrent query fan-out. One unavailable series renders an inline query error while the other series remain visible. The optional AI summary receives the expanded raw data but stays non-critical.

No application-derived counts are copied into `/admin/metrics`, and no Cloud Monitoring data is copied into `/admin`.

## Presentation and Accessibility

The new product-health area uses the existing admin cards, stat rows, typography, colors, and responsive behavior. It is compact enough to scan without turning the dashboard into a tenant report.

Labels state the measured population and time window. Severity or warning color supplements text rather than carrying meaning alone. Empty and unavailable states use explicit prose. The page must not use or imply “safe,” “compatible,” “reachable,” or “compliant.”

## Failure and Empty-State Semantics

- No alert policies: show zero enabled, not “alerts disabled platform-wide.”
- No alerts in 24 hours: show zero without treating it as evaluator failure.
- No pending events: show “caught up.”
- Pending events: show both count and oldest age.
- No evaluator failures in 24 hours: show zero.
- No active-SBOM tenants: show “No active tenants” for snapshot coverage.
- No current snapshots with active tenants: show `0 / N` and identify the current UTC date.
- No comparison-ready repositories: show zero without implying comparison is broken.
- No license policies: show zero configured and zero enforcing.
- Any new product-health read error: preserve the rest of `/admin` and show the section unavailable.
- Any individual Cloud Monitoring query error: preserve all successfully returned metric series.

## Testing

PostgreSQL integration coverage verifies:

- alert policy, 24-hour alert, unread, evaluator backlog, oldest-pending, and failure aggregates;
- the cursor tuple boundary excludes already-consumed events;
- canonical exposure counts deduplicate scanner agreement while unioning fix and KEV evidence;
- posture coverage uses only the current UTC date and active-SBOM tenants;
- comparison readiness requires two distinct active digests in the same tenant/repository group;
- license-policy configured and enforcing semantics;
- all results are global aggregates and contain no tenant identity.

Server coverage verifies:

- the new section renders on `/admin` for an allowlisted operator;
- aggregate labels and empty states are honest;
- product-health failure degrades only the new section;
- no forbidden safety, compatibility, reachability, or compliance claims appear;
- existing 404-on-deny admin authorization remains unchanged.

Metrics unit coverage verifies the exact monitored resource and metric filters for serve CPU/memory and Cloud SQL CPU/connections/disk, including the configured Cloud SQL instance.

The standard test, race, vet, lint, build, and migration gates remain required.

## Out of Scope

- Tenant names, emails, rankings, or per-tenant drill-down for the new signals.
- Per-user or delivery-channel alert metrics.
- Historical product-health charts or new platform snapshot columns.
- Custom application metrics, Prometheus, or OpenTelemetry.
- Automated incident thresholds, paging, or SLO policy.
- Infrastructure mutation, deployment, or release.
