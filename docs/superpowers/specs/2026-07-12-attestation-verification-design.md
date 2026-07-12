# Cryptographic Attestation Verification

Date: 2026-07-12

## Objective

Add authenticity as an optional overlay on DevRadar's trust-on-submission model.
A tenant may submit a sigstore/cosign attestation alongside an SBOM; DevRadar
verifies the signature and binds it to the SBOM's subject digest, then retains
durable, auditable evidence of the decision. This is Release 2, Item 4 of
`IDEAS.md` and a prerequisite for repository subscriptions (Item 6). DevRadar
still never pulls images — the CI that produced the SBOM already holds the
bundle and submits it inline.

## Scope

Included:

- Inline `attestation` field (base64 sigstore bundle) on `POST /v1/sboms`.
- Keyless verification (Fulcio cert identity + OIDC issuer + Rekor) and
  public-key cosign verification.
- Subject-digest binding to the exact SBOM bytes (strongest) or the resolved
  image digest, recording which held.
- Predicate-type allow-list validation.
- Durable evidence in `devradar_sbom_attestation` and a denormalized
  `verification_status` (`unverified | verified | failed`) on the SBOM.
- Evidence surfaced on `GET /v1/sboms/{id}` and the SBOM detail UI.

Excluded (deferred, non-blocking):

- User-triggered re-verification on policy change (schema supports it via
  `policy_version`; verification is at-ingest for now, never automatic).
- Multiple attestations per SBOM (one inline bundle in v1).
- Repository-scoped discovery / OCI Referrers (Item 6).

## Non-negotiable invariants

- **Never fatal.** An unconfigured verifier, a failed verification, or a verifier
  error never blocks ingest and never changes findings. Ingest still returns 202.
- **Additive.** Without a trust policy every SBOM stays `unverified`, exactly as
  before this feature.
- **Nil-safe optional dependency.** `pkg/attest` follows the `pkg/claude`
  pattern: `New` returns nil when unconfigured; `Available()` is nil-safe.
- **No overclaiming.** `verified` means the attestation checked out — not that the
  image is safe. Determinism remains the only unconditional guarantee.

## Architecture

- **`pkg/attest`** — the verification domain. `Verifier` interface, `Result`
  (structured evidence), `Policy` (trust config + stable `Version()` hash), a
  `sigstore-go`-backed `Client`, and a `Fake` for tests.
- **`devradar_sbom_attestation`** (migration 027) — evidence overlay modeled on
  the VEX document table: raw envelope in JSONB + structured columns (result,
  mode, binding, subject digest, predicate type, cert identity, issuer, key id,
  transparency-log ref, verifier + policy versions, failure reason). Keyed to
  `sbom_id` with `ON DELETE CASCADE`; unique on `(sbom_id, subject_digest,
  policy_version)` for idempotency.
- **Store** — `SaveAttestation` (transactional: insert evidence + update
  `verification_status`), `GetAttestation` (latest, tenant-scoped).
- **Ingest** — after digest resolution and activation, `verifyAttestation` runs
  best-effort and reflects the outcome in `submitResponse.verification_status`.
- **Config** — `DEVRADAR_ATTEST_*` accessors and `AttestConfigured()` gate,
  following the `GitHubOAuthConfigured` precedent. Trusted root defaults to a
  config'd JSON (network-free); TUF is opt-in.

## Verification semantics

1. Parse the bundle.
2. Verify signature against the trusted material — keyless (identity ∈ allowed
   SANs, issuer ∈ allowed issuers, Rekor inclusion) or public key.
3. Bind: try sbom-bytes (sha256 of stored bytes == subject) first, then
   image-digest; record which held.
4. Validate predicate type against the allow-list.
5. Pass → `verified`; any failed check → `failed` with a recorded reason; a
   bundle that cannot be evaluated → `failed` recorded from the handler. Missing
   attestation → `unverified`.

## Testing

- **Unit** (`pkg/attest`): policy configured/version stability, nil-safety,
  public-key assembly, malformed-bundle error, digest decode, fake paths.
- **Store** (`pkg/data/postgres`): save/read round-trip, verified/failed status
  transition, idempotency, tenant isolation, cascade on SBOM delete.
- **Handler** (`pkg/server`): submit with attestation via an injected fake —
  verified, failed (still 202), verifier error (still 202), no-attestation, nil
  verifier; plus the `GET /v1/sboms/{id}` evidence round-trip.
- **Manual e2e**: `cosign attest-blob` (keyless via GitHub Actions OIDC, or a
  local key) → submit with `--attestation` → confirm `verified` + evidence and a
  resolvable Rekor reference.

## Risks

- **Dependency weight.** `sigstore-go` pulls a large transitive set (TUF client,
  go-containerregistry, AWS SDK, protobuf-specs) into `vendor/`. Accepted; called
  out in the PR. `go mod verify` + `go build ./...` confirmed clean.
- **Real-crypto CI coverage.** Deterministic valid keyless bundles need
  Fulcio/Rekor, which unit tests can't reach; covered by the fake + documented
  manual check until a committed fixture-bundle + trusted-root pair is added.
