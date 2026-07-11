# Actionable Alerts and Posture Intelligence

Date: 2026-07-11

## Objective

Release tenant-scoped, browser-only alerts together with an actionable work queue, digest comparison, and fleet trends. The release should tell a tenant what changed, what to fix, and whether a tracked upgrade improves its security posture.

Email, webhooks, escalation, acknowledgements, and multi-user ownership are deferred. The design keeps a channel-neutral alert boundary so those capabilities can be added without changing alert evaluation or browser destinations.

## Scope

The release includes:

- Tenant opt-in and one tenant-scoped alert policy.
- Durable alerts for qualifying vulnerability events.
- Dashboard alert summary, alert list, and canonical alert detail page.
- Deterministic remediation work queue.
- Comparison of any two SBOM digests in one repository.
- Fleet and repository posture trends.
- Conservative identification of a newer tracked digest with fewer relevant findings.

The release excludes:

- Email and webhook delivery or configuration.
- Slack, Jira, GitHub, and other adapters.
- Escalation, quiet periods, acknowledgement workflows, and delivery history.
- Opaque or trained risk scores.
- Multiple users per tenant and per-user read state.
- Repository subscriptions and attestation verification.

## Alert Model

### Policy

`devradar_alert_policy` stores one policy per tenant. It contains:

- Whether alert creation is enabled.
- Minimum severity.
- KEV selection or prioritization.
- Whether newly fixable findings create alerts.
- Included causes: `image`, `db`, or both.
- Optional labels or environment filters.

Policy changes apply prospectively. Enabling alerts does not backfill historical events. Disabling alerts stops new alert creation but does not delete existing alerts.

### Alert

`devradar_alert` stores immutable alert facts and a mutable tenant-level `read_at` value. Each alert references its originating finding event, policy, SBOM, digest, finding, cause, and alert kind. Its natural idempotency key is:

`(tenant_id, policy_id, event_id, alert_kind)`

An alert is independent of its presentation or future delivery channel. The alert detail page is its canonical browser destination and will later be the target of email links and webhook payload URLs.

Read/unread is presentation state only. It does not alter the alert lifecycle or originating event.

## Alert Evaluation

Alert evaluation remains outside `ApplyScan`. Scan persistence must not depend on alert policy evaluation or browser functionality.

A separate evaluator reads eligible `image`- and `db`-caused finding events in bounded batches using a durable cursor. For each event it:

1. Loads the tenant policy.
2. Evaluates deterministic predicates.
3. Creates zero or more alerts idempotently.
4. Advances the cursor after the batch is durably processed.

A malformed or unevaluable event is recorded and isolated so it cannot block subsequent events. Evaluation can safely retry after interruption without producing duplicate alerts.

Initial alert kinds are:

- New KEV exposure.
- New finding at or above the configured severity.
- Fix now available.
- Repository posture regression identified by digest comparison.

The phrase "fix now available" means the scanner now reports a fix as available; it does not assert when an upstream fix was published.

## Browser Experience

The tenant dashboard shows a bounded list of recent unread alerts and links to `/alerts`.

`/alerts` provides the tenant's paginated alert history and read/unread controls. `/alerts/{id}` provides the canonical detail view, including:

- What changed and why it matched the policy.
- Image repository, digest, package, vulnerability, severity, KEV, EPSS, and fix state where applicable.
- Image- or database-driven cause.
- Links to the finding, relevant work-queue item, and digest comparison.
- Any newer tracked digest that has fewer relevant findings.

If alert queries fail, the dashboard reports that alerts are unavailable while existing image and finding pages remain usable.

## Actionable Work Queue

`/work` presents remediation units rather than raw scanner rows. Findings are merged by canonical finding identity for prioritization while scanner agreement remains visible metadata.

Ordering is deterministic:

1. KEV status.
2. Fix availability.
3. Severity.
4. EPSS.
5. Affected-image blast radius.
6. Finding age.

The UI exposes these reasons directly and does not reduce them to an opaque score. VEX suppression remains consistent with existing read behavior.

Scanner agreement is a confidence signal, not proof of correctness. Agreement must not double-count a vulnerability or inflate blast radius.

## Digest Comparison

The comparison view accepts any two tenant-owned SBOM digests belonging to the same repository. It reports:

- Findings added and resolved.
- Findings that became fixable or were re-rated.
- Packages and licenses added or removed.
- License-policy regressions.
- Net change in relevant finding counts.
- Whether the newer digest improves or regresses posture under transparent criteria.

The comparison describes observed differences in tracked evidence. It must not claim that a digest is universally safe.

## Trends and Upgrade Guidance

Fleet and repository trends show vulnerability debt and posture improvement or regression over time. Queries are paginated or time-bounded and should reuse existing rollups where their semantics match.

Upgrade guidance may report that a newer tracked digest removes a set of relevant findings or has fewer relevant findings overall. It must identify the comparison basis and retain links to the underlying evidence. It does not infer runtime deployment, compatibility, reachability, or universal safety.

## Tenant Isolation and Failure Handling

Every policy, alert, queue, comparison, and trend query takes `tenant_id` first and scopes all database access to it. Cross-tenant identifiers return no data.

The evaluator uses bounded batches, context deadlines, and idempotent inserts. A retry cannot duplicate alerts. Evaluation failures are observable and retain enough context to diagnose the event and policy involved without exposing tenant data.

No alert-generation failure may roll back or block scan persistence.

## Testing

Required coverage includes:

- Policy predicate matching and prospective policy changes.
- Opt-in without historical backfill.
- Duplicate evaluation and cursor recovery after interruption.
- Malformed-event isolation.
- Tenant isolation for every new store and HTTP operation.
- Deterministic work-queue ordering and tie-breaking.
- Scanner deduplication with agreement metadata preserved.
- Any-two-digest comparison, including package and license changes.
- Conservative upgrade guidance.
- Dashboard degradation when alert reads fail.
- Pagination and production-shaped query performance.

The standard test, race, lint, and migration validation gates remain mandatory.

## Rollout and Release Gates

Rollout proceeds through these stages:

1. Run the evaluator in shadow mode without exposing alerts.
2. Inspect generated alerts for correctness, noise, and duplicates.
3. Enable browser alerts for explicitly opted-in local or test tenants.
4. Validate the complete workflow locally.
5. Restore a production database backup into an isolated environment and test migration apply, application behavior, and rollback.
6. Enable an opt-in beta only after explicit owner approval.
7. Release only after another explicit owner approval.

Release requires:

- Deterministic output.
- Zero duplicate alerts under retries.
- Verified tenant isolation.
- Acceptable latency on production-shaped data.
- Successful migration and rollback validation against the restored backup.
- Successful local product validation by the owner.

No implementation workflow may deploy or release this feature automatically.

## Deferred Evolution

Future email and webhook delivery consumes `devradar_alert` and links to the same detail page. Delivery preferences and configuration belong in tenant settings, but are not exposed in this release.

Multiple-user support will later separate tenant policy ownership from per-user presentation and read state. This release deliberately keeps both policy and read state tenant-scoped.
