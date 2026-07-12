# DevRadar — Deferred Infrastructure Hardening

Infrastructure and build/deploy hardening items surfaced by external security
reviews and **deliberately deferred** (not yet implemented). These are distinct
from the in-code findings, which have been resolved. Most are "before first
`terraform apply`" hardening rather than live incidents — per `.claude/CLAUDE.md`,
the deploy layer exists but has not had its first apply.

_Last updated: 2026-07-12. Source: external review of v0.13.3._

Priority is relative to each other, not to product work.

---

## 1. Split the hostile-scanner trust boundary (P1)

**Problem.** The serve service and the scan job share **one** runtime service
account (`${prefix}-run`), one DB user, `storage.objectAdmin` on the SBOM bucket,
and access to every application secret (`database_url`, `send_api_key`,
`anthropic_api_key`, `oauth_client_secret`). The scan job runs Grype/Trivy/Syft
over **attacker-controlled SBOM data**; a scanner exploit therefore reaches auth
secrets it never needs, every SBOM object, and migration-capable DB credentials.

**Evidence.** `infra/saas/iam.tf:1` (single `run` SA "used by both the serve
service and the scan job"), `infra/saas/cloudrun.tf:170`, `infra/saas/secrets.tf`
(all four `run_*` secret grants to the one SA).

**Proposed fix.**
- Separate `run-serve` and `run-scan` service accounts. Grant each only what it
  uses: serve → `database_url`, `send_api_key`, `oauth_client_secret`,
  `anthropic_api_key`, bucket read + create; scan → `database_url`, bucket read
  only. NOTE: `anthropic_api_key` belongs to SERVE, not scan — it is used by the
  serve/admin-metrics path (Claude narratives), never by the scan job. So the
  hostile-scanner surface does not need the Anthropic secret at all.
- Narrow the bucket role from `objectAdmin` to `objectCreator` + `objectViewer`
  (writes are content-addressed / write-once; neither runtime needs delete/ACL).
  CAVEAT: `objectCreator` cannot OVERWRITE an existing object, so the
  pending→active self-heal (a re-submit after "upload succeeded, activation
  failed") must treat an already-existing identical content-addressed object as
  success rather than re-Put-and-fail. Since the object is content-addressed
  (same bytes → same path), an existing object is by definition the correct bytes;
  the blob Put should tolerate/ignore an "already exists" precondition. Verify the
  ingest self-heal path before narrowing the role.
- Split out a migrator identity/role with DDL rights so the daily runtime roles
  can be `SELECT/INSERT/UPDATE`-only (see item 11).

**Note.** Deferred by product decision; revisit before the first production
apply, as this is the highest-leverage blast-radius reduction.

---

## 7. Harden build provenance (P1)

**Problem.** The scan image installs scanners by piping **mutable `main`-branch
installer scripts** into a shell; base images and deploys are **tag-based** (not
digest-pinned); CI installs **unpinned** scanner versions (drift vs. the runtime
image); no provenance/SBOM/signature is produced for DevRadar's own images.

**Evidence.**
- `Dockerfile.scan:31-33` — `curl .../main/install.sh | sh` (versions ARE pinned
  as the trailing arg, but the *script itself* is fetched from mutable `main`).
- `Dockerfile.scan:9,23,36` — `golang:1.26` / `debian:12-slim` pinned by tag, not
  `@sha256:` digest.
- `.github/workflows/test-on-call.yaml:42-48` — CI installs scanners with **no
  version arg** (whatever `latest` the script picks), so CI tests against
  different scanner versions than the runtime image ships.
- `.github/workflows/deploy.yaml:36` — `gcloud run ... --image ...:${TAG}`
  (mutable tag; `workflow_dispatch` default is `latest`).

**Proposed fix.**
- Pass the pinned `.settings.yaml` versions (via `yq`) to the CI installer, same
  as the Dockerfile, to remove the drift.
- Pin base images by digest (`debian:12-slim@sha256:…`, `golang:1.26@sha256:…`).
- Pin installer scripts by commit/checksum (or vendor them), not `main`.
- Deploy by image digest, not tag; drop the `latest` dispatch default.
- Add `cosign sign` + SBOM/provenance attestation in the release workflow.

---

## 11. Separate migrations from application startup (P2)

**Problem.** Both runtimes open the DB via `postgres.New`, which **runs
migrations at boot** (advisory-lock runner). So the low-privilege runtime role
also holds DDL rights, and startup-time migrations (transactional backfills,
index creation) will eventually impede zero-downtime rollouts.

**Evidence.** `pkg/data/postgres/postgres.go:88` (migrations run in `New`);
serve (`pkg/server/server.go`) and scan (`pkg/scan/scan.go`) both call it.

**Proposed fix.**
- Run migrations as an explicit release step (a dedicated migrator job/role with
  DDL rights), not on every app boot.
- Adopt expand/contract (backward-compatible) migrations applied before the new
  revision rolls out.
- Add lock/statement timeouts to the migration runner; rehearse against a
  restored backup.

**Note.** Pairs with item 1 (the migrator identity).

---

## 12. Add service-specific operational alarms / SLOs (P2)

**Problem.** `notification_email` is declared but **unused**, and Terraform
defines **no** `google_monitoring_alert_policy` / notification channel / uptime
check anywhere. There is no alerting on request RED signals, scan-execution
health, scheduler failures, backlog age, scanner/enrichment freshness, or DB
saturation.

**Evidence.** `infra/saas/variables.tf:43` (`notification_email`, no consumer);
grep for `google_monitoring_*` in `infra/saas/` returns zero resources.

**Proposed fix.**
- Add a `google_monitoring_notification_channel` (email = `var.notification_email`)
  and wire it into policies for, at minimum:
  - Cloud Run 5xx rate and p99 latency (serve).
  - Scan-job **absent** or **failed** executions.
  - Cloud Scheduler failures.
  - `devradar_scan_failure` rate / oldest pending alert-queue age.
  - Enrichment staleness (max `devradar_cve_enrichment.updated_at` age).
  - Cloud SQL saturation (connections, CPU, disk).
- Add structured request/correlation logging to the serve path.

---

## 13. Complete data-lifecycle controls (P2)

**Problem.** Tenant hard-deletion removes DB rows (cascade) but leaves the
tenant's **GCS SBOM objects orphaned forever**; archived SBOM objects likewise
never age out. The bucket has **no versioning and no retention/lifecycle policy**,
so the audited source artifacts have no protection against overwrite and no
bounded retention.

_(The auth-row half of the original finding — expired login tokens / sessions —
is DONE: `Store.PurgeExpiredAuth`, run from the scan job's end-of-run
housekeeping.)_

**Evidence.** `pkg/tenant/admin.go:145` (`DeleteTenant` — DB only; `pkg/gcs` has
no `Delete` and none is called anywhere); `infra/saas/storage.tf:4`
(`versioning { enabled = false }`, no `lifecycle_rule`, no `retention_policy`).

**Proposed fix.**
- Add `(*gcs.Client).Delete` and call it (best-effort, log-on-failure — never
  block the DB op) from the tenant-delete path (enumerate the tenant's
  `object_path`s before the cascade) and, if desired, the SBOM-archive path.
  Prefer a transactional deletion outbox so a crash can't orphan objects.
- Enable bucket `versioning` and add a `lifecycle_rule` (e.g. delete noncurrent
  versions after N days) and/or a `retention_policy` for the audited artifacts.
- Define an explicit retention/export/deletion policy for archived SBOMs.

---

## 14. Wire code-guard env vars in Terraform (P1 — required before first apply)

Two code-level guards were added that need corresponding infrastructure, or they
are either inert or (previously) deploy-blocking:

- **`DEVRADAR_TOKEN_FLASH_KEY`** — the AES-256 key that encrypts the one-time
  API-token flash at rest. Terraform provisions neither the secret nor the env
  var. The serve code no longer refuses to start when it is unset (that briefly
  broke the v0.13.4 deploy — the container failed its startup probe); it now
  degrades to **plaintext-at-rest with a loud startup warning**. To actually
  encrypt the flash, provision a 32-byte base64 secret and wire it into the serve
  revision's env. Until then the plaintext window is bounded by the flash TTL and
  the expired-flash janitor (`PurgeExpiredAuth` now also purges token-flash rows),
  but the value is still plaintext while live.
- **`DEVRADAR_REQUIRE_COMPLETE_TOOLCHAIN`** — when set, the scan job refuses to
  start unless grype + trivy + syft are all present. Terraform does not set it, so
  production currently permits a partial toolchain silently (one scanner, or
  SPDX-blind without syft). Set it to `true` on the scan job once the image is
  known to ship the full toolchain.

**Proposed fix.** Add both to `infra/saas/cloudrun.tf`: a
`google_secret_manager_secret` + `secret_key_ref` env for the flash key on the
serve service, and a plain `DEVRADAR_REQUIRE_COMPLETE_TOOLCHAIN=true` env on the
scan job. Both are cheap and remove a silent-degradation gap.

---

## Not deferred (context)

For the record, the in-code review items **have** been resolved and are not part
of this backlog: attestation canonical-bytes binding & evidence consistency,
login CSRF, zero-finding convergence, multi-axis causality, batched license
ingest, per-tenant quota soft-caps, expired auth-row janitor, KEV
convergence + daily enrichment cadence, subprocess output bounds (incl. during
execution), toolchain completeness validation, fail-closed token-flash key, VEX
digest-over-repo specificity, SPDX AST expression evaluation, per-(SBOM,scanner)
failure backoff, and the ingest envelope limit. Two review items were
intentionally kept as documented **soft** trade-offs rather than
over-engineered: per-tenant quota exactness under concurrent same-tenant submits,
and VEX repository matching by last path segment (so real vendor OpenVEX docs
apply drop-in).
