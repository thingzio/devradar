# DevRadar — Enhancement Ideas

_Stack-ranked roadmap synthesized from competitive review and DevRadar-specific opportunities._

_Last updated: 2026-07-12._

## Framing

DevRadar's position is **continuous, trustworthy security intelligence for container artifacts based on attestations, not image access**.

Roadmap items either monetize the event stream DevRadar already produces or widen coverage without pulling image bytes or touching a cluster. Runtime enforcement, Kubernetes agents, sandbox execution, and image-layer malware inspection remain out of scope because they break the operating model that makes DevRadar defensible.

### Defensible core already shipped

- Immutable, digest-pinned SBOMs
- Recurring Grype and Trivy rescans
- Explicit image-, database-, and tooling-driven causality
- Append-only vulnerability history
- EPSS and CISA KEV enrichment
- OpenVEX suppression
- License inventory and policies
- Cross-digest timelines
- API-first ingestion
- Low infrastructure and credential risk because images are never pulled
- Browser-first actionable alerts, deterministic remediation work queue, and cross-digest posture intelligence (shipped in v0.11.0)

### Competitive lesson

Anchore Enterprise and Aqua emphasize integrations, prioritization, policy gates, notifications, remediation workflows, and compliance reporting. DevRadar should borrow those workflow concepts while preserving its narrower evidence-first boundary. It should not become a smaller CNAPP.

EPSS, KEV, and OpenVEX are no longer roadmap features; they are inputs to prioritization and alerting. Scanner divergence is a useful confidence and evidence-quality signal, but scanner agreement is not proof of correctness.

## Release 1 — Actionable alerts and posture intelligence ✅ SHIPPED (v0.11.0, 2026-07-12)

Shipped, deployed, and validated in production. Detailed design: `docs/superpowers/specs/2026-07-11-actionable-alerts-and-posture-design.md`.

Browser-only, tenant-scoped, and opt-in, as scoped. Email and webhook delivery reuse the same durable alert model later (Release 3, item 9). All three items below landed, plus an admin product/system-health dashboard and a public continuous-posture landing page that were built alongside them.

### 1. Browser-first actionable alerts ✅

Delivered. Actionable `image`- and `db`-caused finding events are evaluated into durable, idempotent tenant alerts via a transactional outbox (`devradar_alert_event_queue`): `ApplyScan` enqueues each event in the same transaction that writes it, so commit visibility — not event-tuple order — gates readiness. The dashboard shows recent unread alerts; `/alerts` is the history; `/alerts/{id}` is the canonical detail page and future email landing page.

Alert kinds shipped: new KEV exposure, new finding at/above threshold, fix now available, repository posture regression. One tenant-scoped policy controls opt-in, severity, KEV behavior, newly fixable findings, causes, and labels. Policy changes are prospective (events before `updated_at` are skipped); enabling alerts does not backfill history.

Still deferred: email, webhooks, digests, quiet periods, escalations, acknowledgements, delivery history, and per-user state.

### 2. Deterministic “What should I fix?” work queue ✅

Delivered at `/work`. Duplicate scanner rows are merged by canonical finding identity with scanner agreement preserved as metadata. Ordering is a transparent, non-overlapping numeric key: KEV → fix availability → severity → EPSS → affected-image blast radius → finding age. `first_seen` uses a fixed epoch inverse so pagination cursors do not drift between requests. No opaque synthetic score; no runtime-context claims.

### 3. Cross-digest comparison, trends, and conservative upgrade guidance ✅

Delivered at `/compare` and `/trends`. Compares any two tenant-owned digests in one repository (vulnerabilities added/resolved/newly-fixable/re-rated; packages and licenses added/removed; license-policy regressions; net change in relevant findings; transparent improvement/regression verdict). Comparisons include archived SBOMs so a new active digest compares against its retired predecessor. Time-bounded fleet and repository trends are backed by daily `SnapshotTenantPosture` snapshots (findings are mutable, so posture cannot be reconstructed after the fact). Conservative upgrade guidance identifies a newer tracked digest that strictly reduces relevant findings. Alerts link into the comparison or work item that explains the action, closing the loop: **what changed → what matters → whether a tracked upgrade helps**.

### Follow-ups carried out of Release 1 (roadmap, non-blocking)

- **`SnapshotTenantPosture` runs on every scan tick (~96×/day) but only the last write of the day survives.** Correct and serialized under a global advisory lock, but wasteful; gate on a freshness check when tenant count grows.
- **`SnapshotTenantPosture` does a global `DELETE`+`INSERT` with no `ON CONFLICT`.** Safe in production (single serial scan-job instance under the advisory lock); add `ON CONFLICT DO UPDATE` as defense-in-depth against any future second writer.
- **Admin dashboard scans `devradar_finding` (~90k rows) multiple times per GET, uncached, including a snapshot write on the read path.** Fine at current scale and admin-only QPS; add a short TTL cache or serve product-health from the daily snapshot before the fleet grows.
- **Fleet CVE risk key is approximately, not strictly, lexicographic at the EPSS→image-reach boundary** (EPSS deltas below ~0.1 can be broken by image count). Intentional heuristic; documented in `read_cve.go`. Re-tier only if strict EPSS dominance is required.

## Release 2 — Trustworthy automated coverage ← NEXT

This is the approved next release now that Release 1 has shipped. Build the trust primitives before adding a registry-facing discovery control plane. These should land incrementally, not as one indivisible release. Item 4 (attestation verification) is the recommended starting point: it is a prerequisite for the repository subscriptions in item 6 and needs no new network control plane.

### 4. Cryptographic attestation verification

- Subject-digest binding
- Cosign key and keyless verification
- Configurable trusted identities and issuers
- Predicate-type validation
- Signature and transparency-log evidence
- Verifier and policy versions, verification time, identity, and issuer

An expanded status string alone is insufficient; retain evidence required to explain and audit every decision.

> **Effort: medium–large.**

### 5. SBOM quality and coverage assessment

Assess whether evidence is fit for reliable monitoring:

- Signature and subject binding
- Recognized generator and version
- Package identifiers and PURLs
- License coverage
- Duplicate, malformed, or suspiciously small inventories
- Unsupported ecosystems and generator age
- Scanner divergence and zero-finding failures

Return actionable guidance such as: _“Regenerate with current Syft using all-layers cataloging.”_

> **Effort: medium.**

### 6. Repository-scoped attestation subscriptions

After verification and quality assessment are usable, poll explicitly configured repositories for signed SBOM attestations. Discovery may place evidence in quarantine; only trusted attestations enter continuous monitoring automatically.

Requirements include strict SSRF defenses, registry controls, bounded I/O and decompression, pagination limits, rate-limit backoff, tenant quotas, OCI Referrers, immutable-digest deduplication, and explicit discovery states.

Start with public repositories and one well-tested registry implementation. Private credentials and broader compatibility follow demonstrated demand.

> New untrusted-network control plane. **Effort: large.**

## Release 3 — Assurance and workflow

### 7. Policy-as-code and CI assurance gates

Expose deterministic synchronous evaluation through an API and a small CLI/GitHub Action:

- Block new KEVs
- Block critical fixable findings
- Block posture regressions
- Require trusted attestations and acceptable SBOM quality
- Enforce license policy
- Permit auditable, time-limited exceptions

DevRadar evaluates evidence; it does not become the deployment controller.

> **Effort: medium.**

### 8. Governed VEX and exception lifecycle

Add ownership, approval, expiration, evidence URLs, scope preview, reminders, audit history, policy limits, and automatic reopening when affected packages change.

> **Effort: medium.**

### 9. Integrations and remediation handoff

After the browser alert model proves useful, add email and generic webhooks, followed by integrations justified by customer workflows:

- GitHub Issues and Checks
- Jira
- Slack or Teams
- SARIF
- CycloneDX VEX and OpenVEX export

Create one work item per remediation unit, not one per scanner finding.

> **Effort: medium.**

### 10. Deeper remediation intelligence

- Minimum fixed package version when scanner metadata supports it
- All images affected by one vulnerable package
- Newer tracked generations that resolve multiple findings
- Grouping by package or defensible base-image lineage
- Compact remediation-plan export

Keep recommendations evidence-backed and avoid inferred lineage or compatibility claims.

> **Effort: medium–large.**

## Release 4 — Enterprise evidence and strategic expansion

### 11. Audit and compliance evidence packs

Generate time-bounded evidence for artifact inventory, provenance, scan freshness, database versions, finding and exception history, policy results, KEV response, licenses, and scanner gaps. Map evidence conservatively to relevant controls without claiming certification.

> **Effort: medium.**

### 12. Pluggable security-attestation inbox

Accept signed attestations produced by purpose-built CI tools for misconfiguration, secrets, malware, SLSA provenance, build metadata, tests, and policy results. Add one typed evidence family at a time; do not create an untyped generic result store.

> Strategically broad and schema-heavy. **Effort: large.**

## Recommended sequence

1. ✅ Browser alerts + deterministic work queue + cross-digest posture intelligence (v0.11.0)
2. ← **next:** Verification → quality assessment → repository subscriptions
3. CI gates → governed VEX → integrations → deeper remediation
4. Evidence packs → typed attestation inbox

Near-term product loop:

> Submit an SBOM → continuously rescan → see only actionable browser alerts → understand what to fix → compare tracked upgrades.

Long-term onboarding loop:

> Subscribe to a repository → discover and verify signed SBOMs → continuously monitor → deliver actionable alerts through chosen channels → recommend an evidence-backed tracked upgrade.

## Explicitly out of scope

- Image-layer malware or secret scanning
- Dynamic sandbox or threat analysis
- Runtime drift prevention or attack blocking
- Kubernetes agents
- True call-graph reachability from SBOM data alone

Direct-versus-transitive dependency data may be reported where the SBOM contains it, but must not be presented as runtime reachability.
