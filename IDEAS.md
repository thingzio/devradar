# DevRadar — Enhancement Ideas

_Stack-ranked roadmap synthesized from competitive review and DevRadar-specific opportunities._

_Last updated: 2026-07-11._

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

### Competitive lesson

Anchore Enterprise and Aqua emphasize integrations, prioritization, policy gates, notifications, remediation workflows, and compliance reporting. DevRadar should borrow those workflow concepts while preserving its narrower evidence-first boundary. It should not become a smaller CNAPP.

EPSS, KEV, and OpenVEX are no longer roadmap features; they are inputs to prioritization and alerting. Scanner divergence is a useful confidence and evidence-quality signal, but scanner agreement is not proof of correctness.

## Release 1 — Actionable alerts and posture intelligence

This is the approved next release. Detailed design: `docs/superpowers/specs/2026-07-11-actionable-alerts-and-posture-design.md`.

The release is browser-only, tenant-scoped, and opt-in. Email and webhook delivery reuse the same durable alert model later. Nothing is released until local validation and migration rehearsal against an isolated production database backup succeed and the owner explicitly approves deployment.

### 1. Browser-first actionable alerts

Evaluate eligible `image`- and `db`-caused finding events into durable, idempotent tenant alerts. The dashboard shows recent unread alerts; `/alerts` is the history; `/alerts/{id}` is the canonical detail page and future email landing page.

Initial alert kinds:

- New KEV exposure
- New finding at or above the tenant threshold
- Fix now available
- Repository posture regression

One tenant-scoped policy controls opt-in, severity, KEV behavior, newly fixable findings, causes, and labels. Policy changes are prospective; enabling alerts does not backfill history.

The phrase **fix now available** means a scanner now reports a fix as available. It does not assert when an upstream project published the fix.

Deferred: email, webhooks, digests, quiet periods, escalations, acknowledgements, delivery history, and per-user state.

> Highest immediate operational value. **Effort: medium.**

### 2. Deterministic “What should I fix?” work queue

Present remediation units rather than a severity dump. Merge duplicate scanner rows by canonical finding identity while preserving scanner agreement as metadata.

Order transparently by:

1. KEV
2. Fix availability
3. Severity
4. EPSS
5. Affected-image blast radius
6. Finding age

Explain the ordering directly, for example: _“Known exploited, fix available, affects 14 labeled production images.”_ Do not introduce an opaque synthetic score and do not claim runtime context.

> **Effort: medium.**

### 3. Cross-digest comparison, trends, and conservative upgrade guidance

Compare any two tenant-owned SBOM digests in one repository:

- Vulnerabilities added, resolved, newly fixable, or re-rated
- Packages and licenses added or removed
- License-policy regressions
- Net change in relevant findings
- Transparent posture improvement or regression

Add time-bounded fleet/repository trends and identify a newer tracked digest that removes relevant findings or has fewer relevant findings. Describe observed evidence only; never claim that an image is universally safe or compatible.

Alerts link into the comparison or work item that explains the action. This closes the release loop: **what changed → what matters → whether a tracked upgrade helps**.

> Strongest near-term differentiator. **Effort: medium.**

## Release 2 — Trustworthy automated coverage

Build the trust primitives before adding a registry-facing discovery control plane. These should land incrementally, not as one indivisible release.

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

1. Browser alerts + deterministic work queue + cross-digest posture intelligence
2. Verification → quality assessment → repository subscriptions
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
