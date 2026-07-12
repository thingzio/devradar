# DevRadar Roadmap

DevRadar already supports digest-pinned SBOM ingest, recurring Grype/Trivy
matching, causal history, EPSS/KEV, OpenVEX, license policy, browser alerts, a
deterministic work queue, digest comparison, posture trends, admin health, and
optional sigstore/cosign verification.

The roadmap contains only unshipped outcomes. Rank work by:

1. User benefit and trust gained.
2. Evidence that the problem exists now.
3. Effort and operational surface added.
4. Whether it unlocks later work.

Do not widen the product into a CNAPP. DevRadar evaluates submitted artifact
evidence; it does not pull images, run agents, inspect clusters, or enforce
deployments.

## 0. Production Gate

Complete before the first production `terraform apply`. These reduce the blast
radius of the hostile scanner boundary and make failures observable.

| Outcome | Why now | Effort | Exit measure |
|---|---|---:|---|
| Split serve, scan, and migrator service accounts and DB roles | Scanner subprocesses currently share credentials and permissions they do not need | M | Scan cannot read auth/email/OAuth secrets or write/delete SBOM objects; runtime roles lack DDL |
| Harden build provenance | Mutable installer scripts, tag-pinned bases/deploys, and CI scanner drift weaken reproducibility | M | CI and runtime use `.settings.yaml` versions; bases/installers/deploys are digest or checksum pinned; release images have SBOM, signature, and provenance |
| Wire production guards | Token-flash encryption and complete-toolchain enforcement exist in code but need Terraform | S | Flash key is Secret Manager-backed; scan job refuses a partial Grype/Trivy/Syft image |
| Add service alarms and SLOs | Admin views are not paging; scheduler/job/feed failures can otherwise age silently | M | Alerts cover HTTP errors/latency, absent or failed scan jobs, scheduler failures, scan/evaluator backlog age, enrichment freshness, and Cloud SQL saturation |
| Define GCS lifecycle and deletion | Tenant deletion can leave objects; retention is undefined | M | Deletion uses a retryable outbox; bucket versioning/retention and archive policy are explicit and tested |

## 1. Improve Evidence Quality

Build an SBOM quality assessment from data already captured: generator/version,
package/PURL/license coverage, inventory size, attestation status, scanner
divergence, zero-finding anomalies, and unsupported ecosystems.

Return specific remediation, for example: “Regenerate this digest with current
Syft using all-layers CycloneDX.” Do not collapse the result into an opaque
score.

- **User benefit:** prevents confident decisions from weak evidence.
- **Effort:** medium; no new control plane.
- **Dependency unlocked:** trustworthy CI gates and safe automatic discovery.
- **Success:** every active SBOM has explainable checks; users can resolve the
  dominant quality failures without reading scanner logs.

## 2. Deliver Alerts Outside the Browser

Add email first, then generic signed webhooks. Consume existing durable alert
records; do not create a second evaluator. Delivery state, retries, and dead
letters must be channel-neutral and idempotent.

- **User benefit:** actionable changes reach users without requiring a login.
- **Effort:** small-medium for email, medium for webhooks.
- **Success:** retrying a delivery never duplicates an alert; channel failures
  never block scans; users can test and disable a destination.

Demand-driven adapters—GitHub Issues/Checks, Jira, Slack, and Teams—come later.
Create one work item per remediation unit, not per scanner row.

## 3. Finish the Automation Contract

Add the smallest API surface needed for deterministic CI and CLI workflows:

1. `GET /v1/sboms/{id}/scan-status` for `pending | scanning | complete | failed`
   and per-scanner freshness.
2. Token introspection (`/v1/me`) and effective tenant policy/settings.
3. `GET /v1/sboms` for a paginated tenant inventory.
4. API access to existing server-side digest comparison.

Batch submission is deferred until measured CI workflows regularly submit many
images together; independent requests already provide clearer retry semantics.
Exact totals on keyset-paginated lists are also deferred until a UI or billing
requirement justifies the query cost.

- **User benefit:** removes polling heuristics and N+1 discovery from
  `devradarctl` and CI.
- **Effort:** medium.
- **Success:** submit-and-wait has a deterministic terminal state and fleet
  automation requires no browser-only data.

## 4. Add Deterministic CI Assurance Gates

Expose synchronous, versioned policy evaluation through the API, CLI, and a
small GitHub Action. Initial predicates:

- no new KEV exposure;
- no critical fixable finding;
- no posture regression versus an explicit baseline digest;
- acceptable attestation and SBOM quality;
- license policy satisfied;
- auditable, time-limited exceptions.

Add SARIF export here because it serves the same CI workflow. DevRadar reports a
policy decision and evidence; it does not become the deployment controller.

- **Effort:** medium after quality assessment and scan status.
- **Success:** identical evidence and policy version always produce the same
  result locally and in CI, with an explanation for every failed predicate.

## 5. Govern VEX and Exceptions

Extend the current read-time OpenVEX overlay with ownership, approval, expiry,
evidence URLs, scope preview, audit history, policy limits, and automatic
reopening when affected package evidence changes.

- **User benefit:** suppressions become reviewable exceptions rather than
  permanent assertions.
- **Effort:** medium.
- **Success:** every active suppression has an owner, basis, scope, and expiry;
  expired or invalidated claims re-enter the work queue predictably.

## 6. Repository Attestation Subscriptions

Only after quality checks, delivery, and policy evaluation are reliable, allow a
tenant to configure a repository whose signed SBOM attestations DevRadar may
discover through OCI Referrers. Start with public repositories and one registry
implementation. Discovered evidence stays quarantined until trust and quality
checks pass.

This is the first new untrusted-network control plane. It requires strict SSRF
defenses, registry allow-lists, bounded pagination and decompression, quotas,
rate-limit backoff with jitter, and immutable-digest deduplication.

- **User benefit:** reduces manual submission while preserving the no-image-pull
  boundary.
- **Effort:** large.
- **Success:** only verified, acceptable evidence activates monitoring; a bad or
  hostile registry cannot starve existing scans.

## 7. Deepen Remediation and Evidence

Pursue these only after the preceding loops show adoption:

| Capability | User outcome | Effort |
|---|---|---:|
| Fixed-version and package-centric remediation | One evidence-backed upgrade action across affected images | M-L |
| Time-bounded evidence packs | Export inventory, provenance, freshness, DB/tool versions, findings, exceptions, licenses, and response history without claiming certification | M |
| Typed attestation inbox | Add signed misconfiguration, secret, malware, SLSA, test, or policy evidence one schema family at a time | L |

## Explicit Deferrals

- Pulling images or holding registry credentials.
- Kubernetes agents, runtime enforcement, call-graph reachability, sandboxing,
  malware scanning, or secret scanning performed by DevRadar.
- Anonymous public aggregation until demand justifies a separate privacy and
  isolation design.
- More vulnerability scanners without evidence that Grype/Trivy gaps materially
  change user decisions.
- AI-generated `not_affected` claims. An SBOM cannot establish exploitability.
- Multi-user ownership, escalation, or acknowledgement workflows until a real
  team-account requirement appears.
- Shared GCS scanner-DB caching until provider limits or measured startup cost
  exceed the operational cost of cache integrity and invalidation.
