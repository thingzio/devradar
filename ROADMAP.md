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

## Proposed: Multi-User Tenancy and Scoped Image Sharing

This implementation brief records the new requirement and the repository review
findings. It does not change the existing roadmap ranking or deferrals; those
remain owner decisions when this work is scheduled.

### Requested Outcome

Support two distinct sharing models without copying SBOM evidence or weakening
tenant isolation:

1. **Image sharing.** An account selects one or more tracked images and enters
   one or more email addresses. After accepting the invitation and signing in,
   each recipient gets read-only access to all evidence for those images.
2. **Account sharing.** An account enters one or more email addresses. After
   acceptance, each recipient gets the requested exact same level of access to
   all current and future account data. The recommended implementation narrows
   ownership-only operations as described below; literal co-ownership remains
   an explicit product decision.

Invitations must work whether the email already resolves to a DevRadar tenant or
will register later. Access must be revocable, auditable, and effective only
after the recipient proves control of the invited email.

### Feasibility and Recommendation

Both models are feasible. Build account membership first even though it grants
broader access: the existing `tenant_id` is already the authorization and data
ownership boundary, so an account member can reuse existing queries after the
request resolves an active account. Image sharing cuts inside that boundary and
requires a second, repository-scoped authorization path.

| Model | Feasibility | Relative effort | Recommendation |
|---|---|---:|---|
| Account membership | High | M-L | Implement first |
| Read-only image dossier | High | L | Implement after membership |
| Image-scoped fleet views, alerts, and API tokens | High | XL | Defer until demanded |

Do not implement sharing by copying SBOMs/findings into the recipient's tenant.
Copying would duplicate scans and alerts, break tenant-scoped content identity,
complicate revocation, and allow the copies to diverge from the owner's policy,
VEX, and archive state. Do not introduce RLS only for this feature; preserve the
current explicit application-layer authorization model.

### Current Constraints Found in the Codebase

- `devradar_tenant` currently conflates login principal and account: verified
  email, avatar, status, plan, minimum severity, alert destination, sessions,
  API tokens, policies, and owned data all converge on one tenant ID.
- Magic-link and GitHub identities resolve directly to a tenant. Sessions and
  API tokens then inject that tenant into request context.
- Every tenant-facing store method accepts `tenantID` first and filters by it.
  This is a strong account boundary but cannot represent a person acting in a
  different account or viewing only selected repositories.
- A UI "image" already means the stable `repository` grouping across all its
  SBOM versions and digests. A repository grant can therefore include future
  digests without enumerating SBOM IDs.
- Repository text is repeated on SBOM rows; there is no first-class image row.
  A composite `(owner_tenant_id, repository)` grant is viable now. Introduce an
  image table only if later requirements need renameable/stable image IDs.
- The existing admin "invite" only upserts a tenant. It is not an invitation,
  does not send an acceptance link, and must not be reused for authorization.
- Transactional email exists through Resend, but delivery is synchronous and
  single-recipient. Batch invitation delivery must not perform unbounded or
  sequential network calls in an HTTP request.
- One-time API-token display is keyed by tenant. With multiple members, one
  member could consume another member's token flash unless it is rekeyed by
  actor or session.
- Alert `read_at` is account-global. Decide whether one member reading an alert
  should mark it read for everyone; otherwise add per-principal receipts.
- The roadmap previously deferred multi-user ownership until a concrete team
  requirement appeared. This request supplies that requirement.

### Operating Assumptions and Invariants

- Workload remains read-heavy (approximately 80/20), single-region and
  multi-AZ, with a target of p99 under 100 ms for authorization-backed reads.
- Grant, acceptance, role change, and revocation are strongly consistent
  PostgreSQL transactions. Do not cache authorization initially; revocation
  must affect an existing session on its next request.
- Email delivery is eventual and idempotent. Delivery failure leaves a pending,
  retryable invitation and never grants access by itself.
- Existing SBOM identity, immutable evidence, scanner behavior, scan scheduling,
  and tenant-owned GCS object paths remain unchanged. Sharing adds read authority
  over the owner's evidence; it never transfers or duplicates ownership.
- API and browser mutations remain deny-by-default. Hiding a form is not an
  authorization control.
- Every new account- or image-scoped query must retain the existing 404
  indistinguishability for unknown versus unauthorized resources.

### Recommended Authorization Model

Introduce a typed request access context with three explicit concepts:

| Field | Meaning |
|---|---|
| Actor | The authenticated tenant/principal; supplies verified email, avatar, admin allowlist identity, and audit actor |
| Account | The tenant whose data and policies the request operates on |
| Access | Account role or repository-scoped viewer grant, including whether mutation is allowed |

Keep the current tenant table as both a principal's home account and an account
record for the first implementation. Add self-owner memberships for all existing
tenants. This is the smallest reversible change: domain `tenant_id` values and
tenant-scoped content hashes do not move. Code must nevertheless use distinct
`ActorID` and `AccountID` names so the compatibility model does not perpetuate
authorization mistakes. A separate user/account schema can be introduced later
if organizations, SSO, or principals without personal accounts require it.

Sessions continue to identify the actor and gain a validated active account.
Every request must revalidate that the actor is an active member of the selected
account and that both actor and account are active. An account selector is
required because an invitee retains their personal account. Invalid or revoked
selections fall back to the personal account rather than exposing stale data.

Recommended roles:

- `owner`: all access, including membership, account deletion, and future
  billing/ownership operations.
- `admin`: the requested same operational access to data, policies, API tokens,
  VEX, alerts, and archive actions, but cannot delete the account or change
  owners.
- `viewer`: reserved for repository-scoped image grants; never an account-wide
  membership in the first release.

Default account invitations to `admin`. If the product requires literal equal
ownership, invite as `owner` and add last-owner, self-removal, recovery, and
ownership-transfer rules before exposure.

### Proposed Schema

Names are directional; final migration names must follow existing conventions.

| Table/change | Required fields and constraints | Purpose |
|---|---|---|
| `devradar_account_member` | `account_tenant_id`, `member_tenant_id`, `role`, `created_by`, `accepted_at`, `revoked_at`, timestamps; unique account/member pair; both tenant FKs cascade | Account membership and role |
| `devradar_invitation` | UUID, inviter/account, normalized email, kind, role, token hash, expiry, delivery state, accepted principal/time, revoked time; unique active invitation per account/email/kind | Durable current-or-future-user invitation |
| `devradar_invitation_image` | invitation ID plus owner tenant/repository; unique pair | Immutable set of images offered by an invitation |
| `devradar_image_grant` | owner tenant, repository, grantee tenant, role=`viewer`, source invitation, accepted/revoked timestamps; unique active owner/repository/grantee tuple | Effective image authorization |
| `devradar_session` change | actor tenant remains; add validated active-account selection only if selection is persisted server-side | Distinguish login from active account |
| `devradar_api_token` change | optional `created_by_member_tenant_id` | Attribute account credential creation |
| `devradar_token_flash` change | key by actor/session plus account, not account alone | Prevent one member seeing another's new token |
| `devradar_audit_event` | account, actor, action, target type/ID, outcome, request correlation, occurred time; append-only | Attribute security-sensitive mutations |
| `devradar_alert_receipt` (conditional) | alert ID, member tenant ID, read time; unique pair | Personal unread state if required |

Invitation targets must be snapshotted in `devradar_invitation_image`; changing
the owner's form selection after email delivery must not silently change what a
pending recipient accepts. Effective grants reference repository identity so
new SBOMs under the same repository become visible automatically.

### Invitation and Email Flow

1. Validate, normalize, deduplicate, and bound the submitted email and image
   lists. Reject the owner's own email and invalid/empty selections.
2. In one transaction, create or refresh idempotent pending invitations,
   snapshot image targets, and enqueue delivery using the email-delivery
   substrate from roadmap item 2. Do not make account/user rows verified merely
   because an inviter typed an address.
3. Send one recipient-specific link containing a random token; store only its
   hash and expiry. Retries reuse the invitation identity and must not create
   duplicate memberships or grants.
4. GET renders a confirmation without consuming the token, preserving the
   existing email-security-scanner defense. If unauthenticated, sign in and
   return to the confirmation using an allowlisted local return path.
5. POST acceptance validates CSRF, token, expiry, invitation state, and exact
   normalized match to the actor's verified email. It transactionally binds the
   stable actor tenant ID and creates the membership or image grants.
6. Revocation sets the membership/grant inactive transactionally. Resend rotates
   the invitation token and expiry. Expired, accepted, and revoked tokens are
   never reusable.

Delivery workers use bounded concurrency, context deadlines, bounded retries
with backoff and jitter, and explicit permanent/transient error classification.
Delivery status and last error must be visible to the inviter without exposing
raw tokens.

### Account-Sharing Behavior

Account membership is the first delivery slice. Once middleware resolves actor,
active account, and role, existing store methods continue receiving the active
account's tenant ID. This limits query churn and preserves current isolation
tests.

An `admin` may use all existing operational account surfaces: overview,
dashboard, work queue, trends, CVEs, alerts, licenses, comparisons, SBOM detail,
VEX submission, archive operations, settings, and API-token management. Owner
checks are mandatory for member/role management and account deletion. Platform
admin authorization always uses the actor's verified email, never the active
account's owner email.

API tokens remain account credentials rather than human credentials. Token
validation resolves only the owning account and cannot inherit a browser
member's other memberships. Creation/revocation is role-gated and audited.

### Image-Sharing Behavior

Deliver image sharing through a separate **Shared with me** surface rather than
merging foreign repositories into the recipient's personal fleet. This avoids
ambiguous account settings, repository-name collisions, misleading fleet totals,
and accidental cross-account mutations.

The first release provides a complete read-only image dossier:

- repository metadata, labels, versions, and current/future digest-pinned SBOMs;
- SBOM metadata, packages, licenses, verification evidence, and scan failures;
- current findings, enrichment, applied VEX state, and finding event history;
- repository severity/posture history; and
- comparisons and upgrade guidance where every involved SBOM belongs to the
  same granted repository.

Owner policy remains authoritative: license verdicts, minimum severity defaults,
VEX suppression, archive state, and attestation evidence are evaluated in the
owner account. Viewers may see the resulting evidence but cannot upload VEX,
change policy, archive, mint tokens, mark account alerts, invite others, or use
owner API credentials. Do not expose whole VEX documents when they contain
statements for unshared repositories; expose only the applied finding overlay.

Repository and SBOM reads must authorize against both the grant and owner:

- repository routes validate `(actor, owner_tenant_id, repository)`;
- SBOM routes join the requested SBOM to an active grant through its owner and
  repository;
- comparison validates both sides against the same grant;
- CVE links return only occurrences inside the granted repository; and
- guessed IDs for other owner repositories return 404.

Initially exclude shared data from fleet overview, work queue, global CVE and
license pages, fleet posture snapshots, account alert inbox, REST API, and CLI.
Adding arbitrary multi-repository aggregates requires scope-aware variants of
those queries and is a separate measured outcome, not part of the dossier MVP.

### Incremental Delivery Plan

1. **Authorization foundation:** forward-only migrations, self-owner membership
   backfill, typed actor/account/access context, account-role middleware, audit
   model, and token-flash isolation. Preserve single-tenant behavior exactly.
2. **Account beta:** invitation acceptance/revocation, account selector, member
   settings, owner/admin guards, account credential attribution, and shadow/test
   use with invited internal accounts.
3. **Image beta:** invitation image snapshots, repository grants, Shared-with-me
   list, repository/SBOM authorization helpers, read-only templates, and explicit
   removal of all mutation controls for viewers.
4. **Optional expansion:** per-user alert receipts, shared-image alerts, scoped
   fleet aggregates, REST/CLI access, account naming, and physical separation of
   user/account tables only when demonstrated requirements justify them.

Each phase must be independently deployable under expand/contract semantics.
Old application revisions must continue working during migration. Do not expose
production sharing until the owner validates the complete invite, accept,
switch, use, revoke, and re-login workflow locally.

### Required Tests and Operational Checks

- Migration tests: self-owner backfill, idempotency, foreign keys, uniqueness,
  cascade semantics, and compatibility with existing tenant deletion.
- Authorization matrix: owner, admin, image viewer, revoked user, suspended
  actor, suspended account, and unrelated tenant across every affected route.
- Cross-account collision: identical repository strings in two accounts never
  authorize each other.
- Future evidence: a new digest submitted after a repository grant appears to
  the viewer without changing the grant.
- Negative image scope: guessed SBOM, CVE, comparison, alert, license, trend, and
  attestation identifiers outside the grant always return 404/no rows.
- Mutation denial: image viewers cannot invoke any browser or API mutation even
  with a valid CSRF token or a hand-crafted request.
- Revocation: an already-authenticated member/viewer loses access on the next
  request; active-account selection cannot preserve stale authority.
- Invitation races: concurrent accept is idempotent; accept versus revoke cannot
  resurrect access; expired/rotated tokens fail; email mismatch fails closed.
- Delivery: retry is idempotent, batch size and concurrency are bounded, partial
  failure remains observable, and email-scanner GETs do not consume access.
- Member isolation: one member cannot consume another's token flash; admin
  allowlisting and audit attribution use the actor, not account owner.
- Query plans: grant-backed repository/SBOM reads retain bounded indexed plans
  and stable keyset pagination at production-shaped cardinality.
- Full gates: migration rehearsal against an isolated production restore,
  `make qualify`, `go build ./...`, and owner workflow validation before beta.

### Exit Measures

- Inviting the same email repeatedly produces one effective membership/grant
  set and never duplicate email side effects under retry.
- A current or future user can accept, switch into an account or open a shared
  image, and see exactly the intended current and future evidence.
- Revocation is effective on the next request and leaves an attributable audit
  event.
- Account members retain existing tenant isolation and operational behavior.
- Image viewers can read the complete dossier but cannot observe another
  repository or perform a mutation.
- No SBOM, finding, event, blob, scan, alert, or policy data is duplicated to
  implement sharing.

### Open Product Decisions

- Confirm whether "exact same access" means `admin` as recommended or literal
  co-owner authority over membership and account deletion.
- Confirm whether image viewers need repository-filtered alerts; default is no.
- Confirm whether shared images must appear in combined fleet aggregates;
  default is a separate Shared-with-me surface.
- Choose invitation TTL, maximum recipients per request, and maximum images per
  invitation before implementation; all must be bounded.
- Decide whether alert unread state is shared by the account or personal to each
  member before account beta.
- Decide whether accounts need a display name or may initially use the original
  owner's email as the account label.

- **User benefit:** teams can collaborate on complete account posture or share
  narrowly scoped image evidence without exporting or duplicating sensitive
  SBOM data.
- **Effort:** M-L for account membership; L for the read-only image dossier;
  XL for scoped fleet aggregates, alerts, and API access.
- **Dependency:** reuse durable email delivery from roadmap item 2 rather than
  creating a second invitation-only delivery system.

## 8. Track Non-Image Artifacts (Binaries, Filesystems)

An SBOM generated for a standalone binary or a filesystem tree is byte-identical
in format to a container-image SBOM, and DevRadar's engine is already
subject-agnostic: scanners run `grype sbom:<file>` / `trivy sbom <file>` without
inspecting the subject, and the delta-causality core keys on
`(tenant, content-digest, format)` — not on anything image-specific. The
`image`/`db`/`tooling` causality model holds for any digest-pinned artifact.

The coupling to "container image" is almost entirely naming, not structure:

- The only behavioral gate is the ingest digest requirement, and it already
  accepts *any* `sha256:` content digest — not an OCI manifest digest
  specifically. A binary SBOM carrying a content hash, or a caller supplying an
  `@sha256:` override, passes today.
- `image_ref`, `repository`, and `version` are free-text label and grouping
  columns; nothing enforces registry grammar. `SplitRef` degrades gracefully on
  a non-image string.
- The `/v1/images*` endpoints, 20-odd UI templates, and product copy name the
  subject "image" cosmetically.

The work is therefore wide-but-shallow, in three separable tiers:

| Tier | Outcome | Effort |
|---|---|---:|
| Functional | Broaden digest extraction to a binary/file component and reword the ingest rejection message; binaries already work with an `image_ref` override | XS |
| Coherent | Rename the domain concept image → artifact/subject across API, UI, columns, and OpenAPI via expand/contract (alias old endpoints, keep columns) | M |
| First-class | Add a `subject_type` discriminator and binary-appropriate grouping (binaries have no registry/tag grammar — group by name or a tenant-supplied identifier) | S–M |

The decision is product scope, not engineering difficulty: whether DevRadar
remains framed as container-image tracking or generalizes to any digest-pinned
artifact. **Deferred until a submitter presents a binary/filesystem SBOM use
case** — the current personas, positioning, and "images from private registries"
pitch are image-framed, and the functional capability is cheap enough to add
on demand rather than pre-build.

- **User benefit:** one posture-tracking loop for binaries and images alike,
  without a second tool.
- **Effort:** XS functional, M for a coherent rename.
- **Open questions:** does the digest come from the artifact hash the submitter
  supplies or from a `file` component in the SBOM; and what is the grouping
  identity for artifacts that have no repository/tag.

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
