# DevRadar full-codebase review — 2026-07-12

Whole-codebase security, best-practices, and optimality audit at `6af8a68`
(v0.12.2). Four reviewers covered the code in parallel (HTTP/auth; data/Postgres;
ingest/scan/untrusted-input; attest/crypto + external I/O); the top crypto
findings were independently re-verified against the vendored `sigstore-go`
source before inclusion here.

> **Status update:** Priority-1 items **A1–A4 are FIXED** (`pkg/attest`,
> `pkg/config`, `pkg/server`; keyless now pins SAN×issuer, empty/absent
> predicates fail closed, and a configured-but-unusable trust policy is fatal at
> startup). Priority-2 (B1–B4) and Priority-3 (C1–C10) are planned for a single
> follow-up release.

## TL;DR

**The security fundamentals are strong.** No SQL injection, no tenant-isolation
leaks, no auth bypass, no XSS, and — importantly — **no path that records an
attestation as `verified` for an invalid signature, missing transparency-log
entry, or mismatched artifact digest.** The unsafe sigstore escape hatches
(`WithoutIdentitiesUnsafe`/`WithoutArtifactUnsafe`) are not used, and empty
policies fail closed.

**But the attestation feature has three real defects** — one functional
(keyless mode doesn't work at all), one authenticity gap (empty-predicate
bypass), one silent-misconfiguration. None causes a false "verified" from a
forged signature, but they undercut the feature's value and should be fixed
before anyone relies on keyless verification. There are also two worthwhile
operational/efficiency fixes in the data layer.

No BLOCKERs. Nothing here warrants an emergency rollback of v0.12.2.

---

## Priority 1 — fix before keyless attestation is relied upon

### A1. Keyless verification is entirely non-functional (fails safe, but dead)
`pkg/attest/sigstore.go:55` — HIGH — CONFIRMED (traced + verified against vendored sigstore-go)

`New()` builds each identity with `verify.NewShortCertificateIdentity("", "", id, "")`
— **empty issuer**. Vendored `NewCertificateIdentity` returns
`"when verifying a certificate identity, must specify Issuer criteria"` for an
empty issuer matcher. So whenever `DEVRADAR_ATTEST_IDENTITIES` is set with no
public key (i.e. every keyless deployment), `New()` returns an error;
`server.go` logs *"attestation verification misconfigured; disabling"* and leaves
`verifier == nil`. **Every keyless submission stays `unverified`.** It fails safe
(never a false positive), but the flagship authenticity feature does nothing in
its primary mode.

Fix: pair each identity with a configured issuer —
`NewShortCertificateIdentity(issuer, "", san, "")` — which also fixes A2. Reject a
keyless policy that has identities but no issuers.

### A2. `Policy.Issuers` allow-list is never enforced
`pkg/attest/policy.go:25` + `sigstore.go:54-60` — HIGH — CONFIRMED

`Issuers` is documented as the OIDC-issuer allow-list and folded into
`Policy.Version()`, but is **never read during verification** — only hashed.
Same root cause as A1: the issuer is dropped when building the cert identity.
Once A1 supplies a non-empty issuer, it must be `policy.Issuers`, not a wildcard
— otherwise a Fulcio cert with the expected SAN issued under a *different* OIDC
issuer would match (SAN values like `.../acme/ci` are not globally unique across
issuers). Fix together with A1.

### A3. Empty/absent predicate type bypasses the SBOM-predicate allow-list
`pkg/attest/sigstore.go:119` — HIGH — CONFIRMED

```go
if out.PredicateType != "" && !c.policy.allowsPredicate(out.PredicateType) { ...fail... }
```

The guard only rejects when `PredicateType != ""`. `PredicateType` is populated
only when the bundle is an in-toto statement. A bundle that verifies against a
trusted identity/key + tlog but is **not an in-toto SBOM statement** (a plain
DSSE/message signature, or a statement with an empty predicate type) yields
`PredicateType == ""`, skips the guard, and is recorded **`verified`**.

Scenario: a trusted CI signer (or anyone holding the trusted cosign key) signs an
arbitrary blob → DevRadar marks the SBOM authentically verified with no proof it
is an SBOM attestation.

Fix: fail closed — require `res.Statement != nil` **and** a non-empty,
allow-listed `PredicateType` for any `verified` outcome.

### A4. Attest key/trusted-root file-read errors are silently swallowed
`pkg/config/env.go:262-271` — HIGH — CONFIRMED

```go
for _, path := range csvList("DEVRADAR_ATTEST_PUBLIC_KEYS") {
    if pem, err := os.ReadFile(path); err == nil { p.PublicKeys = append(...) }
}
if data, err := os.ReadFile(root); err == nil { p.TrustedRoot = data }
```

The doc comment claims the error is "left to the verifier constructor to
surface... never silently weakens the policy without a log line" — but the error
is dropped entirely, not even `slog.Warn`. A typo'd key/root path silently drops
the key or disables the feature (`AttestConfigured()` → false, or `New()` →
`nil,nil`), so an operator believes attestation is enforced when it isn't.

Fix: log every failed read at `Error`; fail closed at startup (refuse to start,
or loudly log "attestation configured but unusable") when a configured path
can't be read.

> Note: A1–A4 are why the feature should be treated as **not yet
> production-relied-upon for keyless**. They're safe (no false "verified"), but
> the happy path is broken/weakened. Worth a focused follow-up PR + a
> fixture-bundle integration test (already a deferred item in IDEAS.md) that
> would have caught A1 immediately.

---

## Priority 2 — operational / efficiency (fix as the fleet grows)

### B1. `SnapshotTenantPosture` does a full cross-tenant finding scan every scan tick
`pkg/data/postgres/posture.go:44` (called `pkg/scan/scan.go:245`) — HIGH (efficiency) — CONFIRMED

Runs at the end of **every** scan run (~every 15 min) and executes two
full re-aggregations of `devradar_finding` across **all** tenants (repository +
tenant projections), each with the correlated `vexSuppressedByDigestCVE`
subquery evaluated **per finding row** — unlike the read paths, which gate the
VEX branch behind `TenantHasSuppressingVEX`. Only the last run of the day
survives (`ON CONFLICT (tenant_id, snapshot_date)`), so ~95/96 daily runs are
thrown-away work, holding a session advisory lock and a scarce scan-pool
connection each tick. Already flagged in the v0.11.0 review; now confirmed by two
reviewers as the single biggest operational risk at scale.

Fix: gate to once/day (skip if today's row is fresh), and/or source the no-VEX
majority from `devradar_sbom_rollup` instead of re-scanning raw findings, and
gate the VEX branch per tenant.

### B2. Missing index: `devradar_scan_failure(sbom_id)`
`pkg/data/postgres` (001_schema.sql) — HIGH (efficiency) — CONFIRMED

The only index is on `occurred_at`, but failure counts are computed as a
**per-row correlated subquery keyed on `sbom_id`** in the hottest list queries
(`ListImages`, `ListRepoImages`, `FleetStats`), and `FailuresBySBOM` filters
`sbom_id` unindexed. Each dashboard/image-list load does N sequential scans of a
forever-growing table. Fix: `CREATE INDEX ... ON devradar_scan_failure(sbom_id)`.

### B3. Missing index for `EventsBySBOM` on the partitioned event log
`pkg/data/postgres/read.go:369` — MEDIUM (efficiency) — CONFIRMED

`devradar_finding_event WHERE sbom_id=$1 ...` — no index leads with `sbom_id`
(all lead with `tenant_id`/`occurred_at`/`cause`). The per-SBOM `/events`
endpoint scans every monthly partition (retained forever) + sorts, per request.
Fix: `CREATE INDEX ... ON devradar_finding_event (sbom_id, occurred_at DESC, id DESC)`
(propagates to partitions), or add a `tenant_id` predicate to use the existing index.

### B4. Canonicalization subprocess is NOT bounded by `ScanTimeout`
`pkg/scan/scan.go:327` — HIGH (availability) — CONFIRMED

`scanWith` correctly wraps each scanner exec in `context.WithTimeout(ScanTimeout)`,
but `Canonicalize` (which shells out to `syft convert` on **attacker-controlled
SPDX bytes**) runs earlier in `scanOne` with the unbounded parent job ctx. A
crafted SPDX SBOM that makes `syft convert` hang stalls the **entire sequential
daily batch** until the Cloud Run task timeout — re-opening exactly the
batch-starvation hole the scanner timeout was built to close, on the same class
of untrusted input.

Fix: wrap the canonicalize call in `scanOne` with a per-SBOM timeout, mirroring
`scanWith`. `exec.CommandContext` will then kill the hung `syft`.

---

## Priority 3 — hardening (low severity, do opportunistically)

- **C1. XFF rate-limit bypass** — `pkg/server/ui.go:612` — MEDIUM. `clientIP`
  trusts the **left-most** `X-Forwarded-For` entry, which on Cloud Run is
  attacker-controlled. Rotating it gives a fresh `login-ip:` key per request,
  defeating the per-IP login limiter (per-email cap and uniform responses still
  bound single-address bombing + enumeration; residual risk is multi-address
  sign-in-email spam). Fix: use the right-most XFF entry / a fixed trusted-proxy
  count.
- **C2. Unbounded feed read** — `pkg/enrich/enrich.go:206` — MEDIUM.
  `io.ReadAll(resp.Body)` on the EPSS/KEV feeds has no `LimitReader` (gcs and
  claude both cap). A misbehaving/redirected endpoint can OOM the scan job. URLs
  are fixed constants (no SSRF). Fix: `io.LimitReader` at ~32 MiB.
- **C3. Scanner output parsed unbounded** — `pkg/scan/scan.go:409` — MEDIUM.
  `gabs.ParseJSONFile` = `os.ReadFile` with no cap on grype/trivy output, whose
  size scales with the attacker's SBOM package count → OOM risk. Fix: stat/limit
  before parse. (Related: `syft convert` stdout buffered unbounded,
  `pkg/sbom/syftconvert.go:70`.)
- **C4. Image-digest attestation binding auto-selected + no policy control** —
  `pkg/attest/sigstore.go:94` — MEDIUM. On any sbom-bytes failure it silently
  retries with the weaker image-digest binding, which proves only that *some*
  trusted attestation exists for the claimed digest — an attacker with a
  legitimate attestation for public image X can submit arbitrary SBOM bytes
  claiming X and get `verified`/`image-digest`. Consistent with trust-on-
  submission, but the `verified` badge overstates it. Fix: let tenants require
  `sbom-bytes`; only fall back on an actual artifact-digest mismatch (not
  identity/signature failure); surface binding strength wherever `verified` shows.
- **C5. Raw API token stored plaintext in `devradar_token_flash`** —
  `pkg/tenant/apitoken.go:117` — LOW. Delete-on-read, 2-min TTL, but the live
  `dr_` secret is at rest in plaintext for that window (backups/WAL/replication).
  Fix: hold the one-time value in server memory/session, or encrypt the column.
- **C6. API tokens never expire** — `pkg/tenant/apitoken.go:54` — LOW. No
  `expires_at` (sessions + login tokens have it). A leaked CI token is valid
  until manually revoked. Fix: optional TTL + last-used staleness pruning.
- **C7. No CSRF on `POST /auth/logout`** — `pkg/server/ui.go:288` — LOW.
  Cross-site forced logout (annoyance only). Fix: wrap in `ValidateCSRF`.
- **C8. `EnsureEventPartitions` runs outside the migration advisory lock** —
  `pkg/data/postgres/postgres.go:95` — LOW. Two replicas booting from
  scale-to-zero can race `CREATE TABLE IF NOT EXISTS <partition>` (not fully
  race-immune in PG); transient failed boot, self-heals on retry. Fix: run it
  inside the migration-locked section, or tolerate the duplicate-relation error.
- **C9. EPSS CVE ids interpolated into query URL unescaped** —
  `pkg/enrich/enrich.go:163` — LOW. CVE strings come from scanner output; a
  crafted "CVE" with `&`/space/`#` corrupts the query (host fixed, no SSRF; worst
  case a dropped batch). Fix: `url.Values` + validate `^CVE-\d{4}-\d+$`.
- **C10. `DEVRADAR_LOCAL_SBOMS` implies DevMode** — `pkg/config/env.go:152` —
  LOW. A storage-selector var silently relaxes two prod guardrails (magic-link
  log-leak + local blob store). Fix: keep DevMode an explicit standalone flag.
- **NITs**: `nonExpiringVerifier` valid-at-any-time (OK — key mode still requires
  a tlog entry); CSP `style-src 'unsafe-inline'` (behind html/template escaping);
  CSRF cookie regenerated per GET (multi-tab usability); duplicate `scan_run` row
  on task retry (row bloat only); repo `risk` keyset cursor float53 headroom
  (not reachable in practice); VEX repo-key matches last path segment only
  (intra-tenant, document it); admin token-revoke ignores `{id}` path segment
  (misleading audit line, operator-gated).

---

## Verified strong (checked, OK — no action)

- **SQL injection** — clean. Every value is `$N`/`pq.Array`; the only `Sprintf`
  into SQL is `$N` position markers, trusted constant fragments
  (`severityRankSQLCol` etc., never request input), and whitelisted `sortCol`
  exprs with a safe default fallback. Cursor values are args, not interpolated.
- **Tenant isolation** — clean. Every tenant-scoped read/write carries
  `WHERE tenant_id = $` or asserts `assertSBOMOwner` before an id-scoped query
  (content-addressed SBOM tenant is immutable, no TOCTOU). Cross-tenant methods
  are confined to `admin.go` (RequireAdmin) and the scan job (documented).
- **AuthN/Z** — API tokens + sessions + login tokens all SHA-256-hashed and
  looked up by hash; index-equality timing is a non-issue on hashes of 256-bit
  secrets. CSRF + OAuth-state use `crypto/subtle.ConstantTimeCompare`.
- **CSRF / OAuth / magic-link** — full CSRF coverage on authed mutating POSTs;
  OAuth has 256-bit single-use state + verified-email; magic-link is single-use
  (delete-and-return), TTL'd, hashed, non-enumerable, refuses to log links in prod.
- **XSS** — `html/template` throughout; every hand-built `template.HTML` escapes
  user-derived values; solid CSP (scripts `'self'`, `object-src`/`base-uri`/
  `frame-ancestors` denied).
- **Untrusted-input defenses** — MaxBytesReader + gzip-bomb guard at ingest,
  blob-read re-caps at the storage boundary, digest resolution fails closed,
  no command injection (argv slices, no shell), temp-file names are
  `filepath.Base` of a sha256 id + `os.CreateTemp` 0600, exec cancellation kills
  the process and reaps it, **two-tier panic recovery** (per-SBOM + per-scanner)
  records failures instead of crashing the daily job.
- **Attestation crypto core** — no unsafe verify options; `WithTransparencyLog(1)`
  + observer timestamps always on; every policy carries `WithArtifactDigest`;
  empty identity policy fails closed in sigstore. No forged-signature path to
  `verified`.
- **Transactions / idempotency** — all multi-statement writers are
  BeginTx→defer Rollback→Commit with no leak path; ApplyScan converges on retry;
  alert outbox is idempotent (ON CONFLICT + monotonic cursor); posture snapshot's
  advisory-lock unlock poisons the conn on failure so it can't return to the pool
  holding the lock.
- **cmd/** — graceful SIGTERM drain (serve `srv.Shutdown`), ctx wired to scan,
  version ldflags.

---

## Suggested sequencing

1. **One PR for the attestation fixes (A1–A4)** — they're related and the
   feature is safe-but-broken until done. Add the fixture-bundle integration test
   at the same time (deferred item in IDEAS.md) — it would have caught A1.
2. **One PR for the data-layer efficiency batch (B1–B3)** — snapshot cadence +
   two indexes; migration 028 for the indexes.
3. **B4 (canonicalize timeout)** — small, standalone availability fix.
4. **Priority-3 hardening** — opportunistic; C1 (XFF) and C2/C3 (unbounded reads)
   first.

All findings are file:line-anchored above. Happy to open issues for any subset
or start on the A1–A4 PR.
