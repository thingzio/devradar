# DevRadar — Deployment

How to deploy DevRadar to the shared Thingz GCP platform (`thingzio`) and how to
ship updates afterward.

> Design context: [README.md](README.md) · [IMPLEMENTATION.md](IMPLEMENTATION.md)
> _Last updated: 2026-07-11._

## What gets deployed

Two Cloud Run units, both on the shared `thingzio-pg` Postgres and shared VPC:

| Unit | Kind | Image | Trigger |
|---|---|---|---|
| `devradar-saas-serve` | Cloud Run **service** (public) | `devradar-serve` (ko, pure Go) | HTTP |
| `devradar-saas-scan` | Cloud Run **job** (single task) | `devradar-scan` (Dockerfile, scanners baked in) | Cloud Scheduler, every ~15 min (`var.scan_schedule`); per-SBOM 12h staleness window |

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

## Mandatory pre-release database rehearsal

Migrations are forward-only and run at application startup. Before releasing a
build that adds migrations, rehearse them against an isolated restore of the
latest production backup. These commands are for a local PostgreSQL instance
only. Verify every URL resolves to localhost before proceeding; never point
`ADMIN_URL`, `PRE_URL`, or `TEST_URL` at Cloud SQL or another external system.

The retained pre-migration database is immutable evidence. Restore it once,
verify its schema version, and do not drop, migrate, or otherwise modify it.
Only the disposable test clone may be dropped and recreated.

```bash
export ADMIN_URL='postgres://devradar:devradar@localhost:5432/postgres?sslmode=disable'
export PRE_DB='devradar_prod_20260711_pre'
export TEST_DB='devradar_prod_20260711_test'
export PRE_URL="postgres://devradar:devradar@localhost:5432/${PRE_DB}?sslmode=disable"
export TEST_URL="postgres://devradar:devradar@localhost:5432/${TEST_DB}?sslmode=disable"
export PROD_BACKUP='/Users/mchmarny/dev/thingz/db/thingz-20260711-104921.sql.gz'

# Confirm all targets are local before any destructive command.
psql "$ADMIN_URL" -v ON_ERROR_STOP=1 -c \
  "SELECT inet_server_addr(), inet_server_port(), current_database()"

# The plain-SQL backup references these production roles. They must exist
# locally as NOLOGIN roles before restore; create them with a local PostgreSQL
# superuser if this query does not return both rows with rolcanlogin=false.
psql "$ADMIN_URL" -v ON_ERROR_STOP=1 -c \
  "SELECT rolname, rolcanlogin FROM pg_roles
   WHERE rolname IN ('devpulse','cloudsqlsuperuser') ORDER BY rolname"

# Restore the gzip-compressed plain-SQL baseline once. Skip this block when
# PRE_DB already exists; never overwrite or migrate the retained baseline.
createdb --maintenance-db="$ADMIN_URL" --template=template0 "$PRE_DB"
gzip -dc "$PROD_BACKUP" | psql "$PRE_URL" -v ON_ERROR_STOP=1

# The 2026-07-11 release baseline must remain exactly at versions 1..18.
psql "$PRE_URL" -v ON_ERROR_STOP=1 -c \
  "SELECT count(*), min(version), max(version) FROM devradar_schema_version"
```

Record baseline counts for every existing DevRadar business table. Partition
rows are intentionally reported both through the parent and per-partition; the
comparison is still exact because the same query runs against both databases.

```bash
for table in $(psql "$PRE_URL" -Atqc \
  "SELECT tablename FROM pg_tables
   WHERE schemaname='public' AND tablename LIKE 'devradar_%'
     AND tablename <> 'devradar_schema_version'
   ORDER BY tablename"); do
  psql "$PRE_URL" -Atqc "SELECT '$table|' || count(*) FROM \"$table\""
done
```

Recreate only the migrated clone, then apply migrations 19 through 26 through
the real advisory-locked Go migration runner. `TestMigrate_Idempotent` opens the
store (which applies pending migrations) and calls `Migrate` again, proving the
second pass is a no-op.

```bash
psql "$ADMIN_URL" -v ON_ERROR_STOP=1 -c \
  "DROP DATABASE IF EXISTS ${TEST_DB} WITH (FORCE)"
psql "$ADMIN_URL" -v ON_ERROR_STOP=1 -c \
  "CREATE DATABASE ${TEST_DB} WITH TEMPLATE ${PRE_DB} OWNER devradar"

DATABASE_URL="$TEST_URL" go test ./pkg/data/postgres \
  -run '^TestMigrate_Idempotent$' -count=1 -v

# A separate invocation must log no migration applies.
DATABASE_URL="$TEST_URL" go test ./pkg/data/postgres \
  -run '^TestMigrate_Idempotent$' -count=1 -v
```

Validate the migrated contract and compare every baseline table count. The
version query must report `26 | 1 | 26 | true`; all count pairs must match.

```bash
psql "$TEST_URL" -v ON_ERROR_STOP=1 -c \
  "SELECT count(*), min(version), max(version),
          array_agg(version ORDER BY version) =
            ARRAY(SELECT generate_series(1,26)) AS contiguous
   FROM devradar_schema_version"

psql "$TEST_URL" -v ON_ERROR_STOP=1 -c \
  "SELECT column_name, is_nullable
   FROM information_schema.columns
   WHERE table_schema='public'
     AND table_name='devradar_alert_event_queue'
     AND column_name='tenant_id'"

for table in $(psql "$PRE_URL" -Atqc \
  "SELECT tablename FROM pg_tables
   WHERE schemaname='public' AND tablename LIKE 'devradar_%'
     AND tablename <> 'devradar_schema_version'
   ORDER BY tablename"); do
  pre=$(psql "$PRE_URL" -Atqc "SELECT count(*) FROM \"$table\"")
  test=$(psql "$TEST_URL" -Atqc "SELECT count(*) FROM \"$table\"")
  test "$pre" = "$test" || { echo "$table: $pre != $test"; exit 1; }
  echo "$table|$pre|$test"
done
```

Run `EXPLAIN (ANALYZE, BUFFERS)` on the migrated clone using the exact SQL from
`NextAlertEvents`, `AdminProductHealth`, and the Overview `FleetStats` / top
images paths. Use real tenant IDs from the clone and cover both the rollup fast
path and a VEX-aware fallback tenant. Record execution time, buffer and temp
usage, row estimates, scan type, and the indexes selected. Add an index only
when the measured plan demonstrates the need; any correction must be a new
forward migration, never an edit to an applied migration.

Rollback during rehearsal means recloning from the preserved baseline—never
running down-migrations:

```bash
psql "$ADMIN_URL" -v ON_ERROR_STOP=1 -c \
  "DROP DATABASE IF EXISTS ${TEST_DB} WITH (FORCE)"
psql "$ADMIN_URL" -v ON_ERROR_STOP=1 -c \
  "CREATE DATABASE ${TEST_DB} WITH TEMPLATE ${PRE_DB} OWNER devradar"
```

After successful validation, retain the migrated test clone for owner UI
verification:

```bash
make serve DEV_DB="$TEST_URL"
```

**No-release gate:** do not tag, push, deploy, enable a production feature, or
run production Terraform until all migrations are contiguous through 26, the
idempotent rerun is clean, baseline business-table counts match, query plans are
reviewed, `make qualify` and `go build ./...` pass, and the owner validates the
complete local workflow. A failed check returns to the preserved baseline via
reclone. Production rollout still requires explicit owner approval.

---

## Initial setup (once)

### 1. Provision infrastructure

```bash
make tf-init          # terraform init (GCS backend, state prefix "devradar")
make tf-plan          # review — expect ~1 SQL user, 1 bucket, 3 secrets, SAs,
                      #          WIF, AR repo, 1 service, 1 job, 1 scheduler
make tf-apply         # run by hand with an operator identity
```

The Cloud Run service and job are created with a **public placeholder image**
(`var.bootstrap_image`) so this first apply succeeds before any DevRadar image
exists — the real images are pushed and deployed by CI in step 4. Terraform
`ignore_changes` on the image field means CI's deploys are never reverted by a
later `terraform apply`. This creates everything except the real images and the
secret **values** (step 2). Capture the outputs:

```bash
terraform -chdir=infra/saas output
```

### 2. Populate secret values

Terraform creates the secret *containers*, assembles `devradar-saas-database-url`
from the generated DB password, and seeds a **placeholder** version for
`devradar-saas-send-api-key` (so the serve service can deploy before you have a
real key — with the placeholder, magic-link emails are logged, not sent). Add the
real values out-of-band; `ignore_changes` keeps them from being reverted:

```bash
# Resend key — required for magic-link sign-in
printf '%s' 'YOUR_RESEND_KEY' | \
  gcloud secrets versions add devradar-saas-send-api-key --data-file=- --project thingzio

# Anthropic key — only if using OpenVEX stubbing / narratives
printf '%s' 'YOUR_ANTHROPIC_KEY' | \
  gcloud secrets versions add devradar-saas-anthropic-api-key --data-file=- --project thingzio
```

### 3. Configure GitHub Actions (keyless deploy via WIF)

Run the helper — it reads the Terraform outputs and writes the `saas`
environment variables via the `gh` CLI (creating the environment if needed):

```bash
gh auth status          # must be authenticated
tools/setup-gh-env
```

This sets `WIF_PROVIDER`, `DEPLOYER_SA`, `REGION`, `PROJECT_ID` — everything the
`release`/`deploy` workflows need. No JSON key is stored; GitHub Actions
authenticates to GCP via Workload Identity Federation, scoped to this repo.

<details><summary>Setting them by hand instead</summary>

Create an **environment named `saas`** and set each variable from the outputs:
`WIF_PROVIDER` = `terraform output -raw wif_provider`, `DEPLOYER_SA` =
`terraform output -raw deployer_sa`, `REGION` = `us-west1`, `PROJECT_ID` =
`thingzio`.
</details>

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

Bump the semver tag — that's the whole flow (the tag triggers the release
workflow):

```bash
make bump-patch     # v0.1.0 -> v0.1.1   (also: bump-minor, bump-major)
```

`bump` refuses if the tree is dirty or has unpushed commits, then creates a
signed tag and pushes it. Equivalent by hand: `git tag vX.Y.Z && git push origin vX.Y.Z`.

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
- **Shared-project safety:** `google_project_service` is set `disable_on_destroy =
  false`, so a future `terraform destroy` of DevRadar will **not** disable
  project-wide APIs that DevPulse/DevTrace also use. Enabling an already-enabled
  API on apply is a no-op.
- **`terraform validate` passes**, but the first real `plan`/`apply` against the
  live project is the true test — review the plan carefully.
- **Two images, two build paths:** serve is ko (pure Go); scan is a Dockerfile
  (needs grype/trivy/syft at runtime). Keep the Dockerfile scanner ARGs in sync
  with `.settings.yaml`.
- **Not yet wired (deferred):** email/push alerting and scan concurrency pooling —
  see IMPLEMENTATION.md. `SEND_API_KEY` is used for magic-link today; alerting
  will reuse it.
