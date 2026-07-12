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
- Optional cryptographic attestation verification (sigstore/cosign, keyless + key) binding an SBOM to its subject digest with retained, auditable evidence

### Competitive lesson

Anchore Enterprise and Aqua emphasize integrations, prioritization, policy gates, notifications, remediation workflows, and compliance reporting. DevRadar should borrow those workflow concepts while preserving its narrower evidence-first boundary. It should not become a smaller CNAPP.

EPSS, KEV, and OpenVEX are no longer roadmap features; they are inputs to prioritization and alerting. Scanner divergence is a useful confidence and evidence-quality signal, but scanner agreement is not proof of correctness.

## Shipped

Condensed changelog of delivered roadmap items. Details live in the design specs
under `docs/superpowers/specs/` and the security review at
`docs/2026-07-12-security-review.md`.

- **Release 1 — actionable alerts + posture intelligence (v0.11.0).** Browser-first
  durable alerts via a transactional outbox (`devradar_alert_event_queue`); the
  deterministic `/work` remediation queue; `/compare` + `/trends` cross-digest
  comparison, fleet/repo trends, and conservative upgrade guidance. Plus an admin
  product/system-health dashboard and the public continuous-posture landing page.
- **Release 2 item 4 — cryptographic attestation verification (v0.12.0–v0.13.0).**
  Inline `attestation` on `POST /v1/sboms`; `pkg/attest` (nil-safe, `sigstore-go`);
  keyless (Fulcio SAN×issuer + Rekor) and public-key modes; subject binding
  (sbom-bytes strongest, image-digest fallback, optional `REQUIRE_SBOM_BYTES`);
  predicate allow-list (fail-closed); full evidence row in
  `devradar_sbom_attestation`; surfaced on `GET /v1/sboms/{id}` + SBOM detail UI;
  `devradarctl submit --attestation`.
- **Security + performance hardening (v0.12.1–v0.13.0)** from the full-codebase
  review: keyless issuer pinning, empty-predicate fail-closed, fail-closed attest
  config; posture-snapshot throttling + hot-path indexes (migration 028);
  race-safe partition creation; bounded untrusted-input reads (feed / syft-convert
  / scanner output); XFF client-IP fix; AES-GCM-encrypted token flash; optional
  API-token TTL; logout CSRF; DevMode decoupled from the storage selector.

### Open follow-ups carried from shipped work (non-blocking)

- **Attestation re-verification** on trust-policy change — user-triggered only,
  never automatic; schema's `policy_version` already supports the diff.
- **Multiple attestations per SBOM** (today: one inline bundle).
- **Fixture-based e2e crypto test** for real bundle verification in CI (today:
  pure-unit + injected fake + a documented manual check).
- **Admin dashboard** scans `devradar_finding` a few times per GET, uncached
  (admin-only QPS; add a short TTL cache or serve from the daily snapshot before
  the fleet grows).
- **Fleet CVE risk key** is approximately (not strictly) lexicographic at the
  EPSS→image-reach boundary — intentional heuristic, documented in `read_cve.go`.

## Next up — Release 2 (cont.): trustworthy automated coverage

Item 4 (attestation verification) shipped. The rest of Release 2 builds the
remaining trust primitives before any registry-facing discovery.

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

The durable, channel-neutral alert model is already live (Release 1), so this
splits into two slices:

**9a — out-of-browser delivery (promoted, do early).** Email + generic webhooks
riding the existing alert records. Reuses the Resend sender (`pkg/net`) already
wired for magic links. Closes the "alerts you never see unless you log in" gap.

**9b — workflow adapters (later, demand-driven):**

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

1. ✅ Browser alerts + work queue + cross-digest posture intelligence (v0.11.0)
2. ✅ Attestation verification + security/perf hardening (v0.12.0–v0.13.0)
3. ← **next:** SBOM quality assessment (#5) → integrations: email/webhooks first (#9) → CI assurance gates (#7)
4. Repository subscriptions (#6) → governed VEX (#8) → deeper remediation (#10)
5. Evidence packs (#11) → typed attestation inbox (#12)

**Re-prioritization note (2026-07-12):** #5 (SBOM quality) is promoted — it reuses
data already captured at ingest (generator/tool, PURLs, licenses, scanner
divergence, zero-finding failures), needs no new infrastructure, and directly
raises trust in every other signal. Email/webhook delivery (#9, first slice) is
pulled earlier than the rest of #9 because the durable alert model is already
live and "alerts you can't see unless you visit" is the biggest current gap.
Repository subscriptions (#6) is deferred behind #5 and the delivery slice: it is
the only large new untrusted-network control plane and should not precede a
usable quality gate and out-of-browser delivery.

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
