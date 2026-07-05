# DevRadar — Deployment

How to deploy DevRadar to the shared Thingz GCP platform (`thingzio`) and how to
ship updates afterward.

> Design context: [README.md](README.md) · [IMPLEMENTATION.md](IMPLEMENTATION.md)
> _Last updated: 2026-07-05._

## What gets deployed

Two Cloud Run units, both on the shared `thingzio-pg` Postgres and shared VPC:

| Unit | Kind | Image | Trigger |
|---|---|---|---|
| `devradar-saas-serve` | Cloud Run **service** (public) | `devradar-serve` (ko, pure Go) | HTTP |
| `devradar-saas-scan` | Cloud Run **job** (single task) | `devradar-scan` (Dockerfile, scanners baked in) | Cloud Scheduler, 02:00 UTC daily |

DevRadar **references** the shared Cloud SQL instance and `thingz` database — it
creates neither. It creates only its own DB user (`devradar`), a GCS bucket for
SBOM bytes, secrets, service accounts, and the two Cloud Run resources.

## Prerequisites

- **Terraform** ≥ 1.13, **gcloud** CLI.
- An operator identity with rights on the `thingzio` project sufficient to create
  service accounts, secrets, Cloud Run, a GCS bucket, and a **Cloud SQL user** on
  the shared instance. (The first `terraform apply` is run by hand — see below.)
- The shared infra (`thingzio/infra`) already applied: VPC `thingzio-vpc`,
  subnet `thingzio-subnet`, Cloud SQL `thingzio-pg`, database `thingz`.
- A **Resend** API key (transactional email — magic-link sign-in, later alerts).
- Optionally an **Anthropic** API key (OpenVEX stubbing / future narratives).

All shared identifiers are baked as variable defaults in `infra/saas/variables.tf`
(`project_id=thingzio`, `region=us-west1`, `db_instance_name=thingzio-pg`,
`db_name=thingz`, `git_repo=thingzio/devradar`). Override via an untracked
`infra/saas/terraform.tfvars` only if a default is wrong — **do not commit
secrets to tfvars.**

---

## Initial setup (once)

### 1. Provision infrastructure

```bash
make tf-init          # terraform init (GCS backend, state prefix "devradar")
make tf-plan          # review — expect ~1 SQL user, 1 bucket, 3 secrets, SAs,
                      #          WIF, AR repo, 1 service, 1 job, 1 scheduler
make tf-apply         # run by hand with an operator identity
```

This creates everything except the two container images (pushed by CI in step 4)
and the secret **values** (step 2). Capture the outputs:

```bash
terraform -chdir=infra/saas output
```

### 2. Populate secret values

Terraform creates the secret *containers* and assembles `devradar-saas-database-url`
from the generated DB password, but the API-key values are set out-of-band:

```bash
# Resend key — required for magic-link sign-in
printf '%s' 'YOUR_RESEND_KEY' | \
  gcloud secrets versions add devradar-saas-send-api-key --data-file=- --project thingzio

# Anthropic key — only if using OpenVEX stubbing / narratives
printf '%s' 'YOUR_ANTHROPIC_KEY' | \
  gcloud secrets versions add devradar-saas-anthropic-api-key --data-file=- --project thingzio
```

### 3. Configure GitHub Actions (keyless deploy via WIF)

In the `thingzio/devradar` repo, create an **environment named `saas`** and set
these repository (or environment) **variables** from the Terraform outputs:

| Variable | Value (source) |
|---|---|
| `WIF_PROVIDER` | `terraform output -raw wif_provider` |
| `DEPLOYER_SA` | `terraform output -raw deployer_sa` |
| `REGION` | `us-west1` |
| `PROJECT_ID` | `thingzio` |

No JSON key is stored — GitHub Actions authenticates to GCP via Workload Identity
Federation, scoped to this repo.

### 4. First release

Tag a release; CI (`.github/workflows/release.yaml`) builds and pushes both
images (serve via ko, scan via `Dockerfile.scan`) and deploys them to the Cloud
Run resources Terraform already created:

```bash
git tag v0.1.0
git push origin v0.1.0
```

Watch the `release` → `deploy` workflows. On success:

```bash
gcloud run services describe devradar-saas-serve --region us-west1 --format 'value(status.url)'
curl -s "$(…)/health"     # -> ok
```

### 5. Verify the pipeline end-to-end

```bash
# Sign in at https://devradar.thingz.io (magic link), mint an API token, then:
export DR_TOKEN=dr_...
# submit an SBOM (see README "Run It Locally" for generating one by digest)
curl -s -X POST https://devradar.thingz.io/v1/sboms \
  -H "Authorization: Bearer $DR_TOKEN" \
  -d "{\"sbom\":\"$(base64 < app.cdx.json | tr -d '\n')\"}"

# run the scan job once now (don't wait for the scheduler)
gcloud run jobs execute devradar-saas-scan --region us-west1 --wait

curl -s https://devradar.thingz.io/v1/images -H "Authorization: Bearer $DR_TOKEN"
```

### 6. Harden

Once the deploy is confirmed, set `deletion_protection = true` on both
`google_cloud_run_v2_service.serve` and `google_cloud_run_v2_job.scan` in
`infra/saas/cloudrun.tf`, then `make tf-apply`.

---

## Routine updates

### Ship new application code

Tag a semver release — that's the whole flow:

```bash
git tag vX.Y.Z && git push origin vX.Y.Z
```

CI builds + pushes both images tagged `vX.Y.Z` and updates the running service +
job to that tag. **DB migrations run automatically** on startup (the advisory-lock
runner applies any new `pkg/data/postgres/sql/migrations/NNN_*.sql`), so schema
changes ship with the code — no manual migration step.

Manual redeploy of an existing tag (e.g. re-point to `latest`) via the
`workflow_dispatch` on `.github/workflows/deploy.yaml`.

### Change infrastructure

Edit `infra/saas/*.tf`, then:

```bash
make tf-plan && make tf-apply
```

### Bump scanner versions

The scanner binaries are pinned in **two places that must stay in sync**:
`.settings.yaml` (`scanners.{grype,trivy,syft}`) and the `ARG` defaults in
`Dockerfile.scan`. Update both, then cut a release — the new scan image carries
the new scanners. (The vulnerability *databases* are not pinned; the job refreshes
them at start.) Expect a one-time wave of `tooling`-caused finding events after a
scanner upgrade — these are recorded but never alerted on (see IMPLEMENTATION.md
"Cause classification").

### Rotate a secret

```bash
printf '%s' 'NEW_VALUE' | gcloud secrets versions add devradar-saas-send-api-key --data-file=- --project thingzio
gcloud run services update devradar-saas-serve --region us-west1   # pick up "latest" version
```

(The DB password is managed by Terraform via `random_password`; rotate it with a
`terraform apply -replace=random_password.db_password`, which also updates the
`devradar-saas-database-url` secret.)

---

## Operations

- **Run a scan now:** `gcloud run jobs execute devradar-saas-scan --region us-west1 --wait`
- **Logs:** `gcloud run services logs read devradar-saas-serve --region us-west1` /
  `gcloud run jobs executions list --job devradar-saas-scan --region us-west1`
- **Scan failures** are recorded in the `devradar_scan_failure` table (not just
  logs) — query it to see per-SBOM/per-scanner errors.
- **DB access** to the shared instance is private-IP only; use the shared
  `thingzio/infra` `tools/db-connect` helper (temporary proxy) for ad-hoc queries.

## Notes & caveats

- **First apply is manual and privileged** — it touches the shared instance
  (creates the `devradar` SQL user). Routine app updates need only the WIF-scoped
  deployer (no shared-instance rights).
- **`terraform validate` passes**, but the first real `plan`/`apply` against the
  live project is the true test — review the plan carefully.
- **Two images, two build paths:** serve is ko (pure Go); scan is a Dockerfile
  (needs grype/trivy/syft at runtime). Keep the Dockerfile scanner ARGs in sync
  with `.settings.yaml`.
- **Not yet wired (deferred):** email/push alerting and scan concurrency pooling —
  see IMPLEMENTATION.md. `SEND_API_KEY` is used for magic-link today; alerting
  will reuse it.
