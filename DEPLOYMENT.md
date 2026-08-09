# DevRadar — Deployment

How to deploy DevRadar to the shared Thingz GCP platform (`thingzio`) and how to
ship updates afterward.

> Design context: [README.md](README.md) · [DEVELOPMENT.md](DEVELOPMENT.md) · [ROADMAP.md](ROADMAP.md)
> _Last updated: 2026-07-14._

## What gets deployed

Three Cloud Run units use the shared `thingzio-pg` Postgres and shared VPC:

| Unit | Kind | Image | Trigger |
|---|---|---|---|
| `devradar-saas-serve` | Cloud Run **service** (public) | `devradar-serve` (ko, pure Go) | HTTP |
| `devradar-saas-scan` | Cloud Run **job** (single task) | `devradar-scan` (Dockerfile, scanners baked in) | Cloud Scheduler, every ~15 min (`var.scan_schedule`); per-SBOM 24h staleness window |
| `devradar-saas-deliver` | Cloud Run **job** (single task) | `devradar-deliver` (ko, pure Go) | Cloud Scheduler, every 5 min; at most 50 leases and five concurrent sends |

DevRadar **references** the shared Cloud SQL instance and `thingz` database — it
creates neither. It creates only its own DB user (`devradar`), a GCS bucket for
SBOM bytes, secrets, service accounts, and the three Cloud Run resources.

## Prerequisites

- **Terraform** ≥ 1.13, **gcloud** CLI.
- An operator identity with rights on the `thingzio` project sufficient to create
  service accounts, secrets, Cloud Run, a GCS bucket, and a **Cloud SQL user** on
  the shared instance. (The first `terraform apply` is run by hand — see below.)
- The shared infra (`thingzio/infra`) already applied: VPC `thingzio-vpc`,
  subnet `thingzio-subnet`, Cloud SQL `thingzio-pg`, database `thingz`.
- A **Resend** API key for magic-link sign-in.
- Optionally an **Anthropic** API key for admin metrics analysis.

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
export PRE_DB='devradar_prod_20260714_020645_pre'
export TEST_DB='devradar_prod_20260714_020645_test'
export PRE_URL="postgres://devradar:devradar@localhost:5432/${PRE_DB}?sslmode=disable"
export TEST_URL="postgres://devradar:devradar@localhost:5432/${TEST_DB}?sslmode=disable"
export PROD_BACKUP='/Users/mchmarny/dev/thingz/db/thingz-20260714-020645.sql.gz'

# Confirm the client endpoint, port, and database are local before any
# destructive command. inet_server_addr() reports the container's bridge
# address under Docker, not the localhost endpoint used by the client.
psql "$ADMIN_URL" -v ON_ERROR_STOP=1 -c '\conninfo'
psql "$ADMIN_URL" -v ON_ERROR_STOP=1 -c \
  "SELECT inet_server_port(), current_database()"

# The plain-SQL backup references these production roles. They must exist
# locally as NOLOGIN roles before restore; create them with a local PostgreSQL
# superuser if this query does not return both rows with rolcanlogin=false.
psql "$ADMIN_URL" -v ON_ERROR_STOP=1 -c \
  "SELECT rolname, rolcanlogin FROM pg_roles
   WHERE rolname IN ('devpulse','cloudsqlsuperuser') ORDER BY rolname"

# Restore the gzip-compressed plain-SQL baseline once. Skip this block when
# PRE_DB already exists; never overwrite or migrate the retained baseline.
gzip -t "$PROD_BACKUP"
createdb --maintenance-db="$ADMIN_URL" --template=template0 "$PRE_DB"
gzip -dc "$PROD_BACKUP" | psql "$PRE_URL" -v ON_ERROR_STOP=1

# The 2026-07-14 release baseline must remain exactly at versions 1..29.
psql "$PRE_URL" -v ON_ERROR_STOP=1 -c \
  "SELECT count(*), min(version), max(version),
          array_agg(version ORDER BY version) =
            ARRAY(SELECT generate_series(1,29)) AS contiguous
   FROM devradar_schema_version"
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

Recreate only the migrated clone, then apply migrations 30 through 32 through
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
version query must report `32 | 1 | 32 | true`; all count pairs must match.

```bash
psql "$TEST_URL" -v ON_ERROR_STOP=1 -c \
  "SELECT count(*), min(version), max(version),
          array_agg(version ORDER BY version) =
            ARRAY(SELECT generate_series(1,32)) AS contiguous
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
images paths. Use real account IDs from the clone and cover both the rollup fast
path and a VEX-aware fallback account. Record execution time, buffer and temp
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

Migrations 030–032 must additionally preserve every legacy account/user mapping,
create no duplicate memberships, retain multi-account users when one account is
deleted, and keep every query explicitly account-filtered. Do not rename the
physical `devradar_tenant` table or `tenant_id` columns during this rollout.

**No-release gate:** do not tag, push, deploy, enable a production feature, or
run production Terraform until all migrations are contiguous through 32, the
idempotent rerun is clean, baseline business-table counts match, query plans are
reviewed, `make qualify` and `go build ./...` pass, and the owner validates the
complete local workflow. A failed check returns to the preserved baseline via
reclone. Production rollout still requires explicit owner approval.

---

## Initial setup (once)

### 1. Provision infrastructure

```bash
make tf-init          # terraform init (GCS backend, state prefix "devradar")
make tf-plan          # review — expect ~1 SQL user, 1 bucket, 6 secrets, SAs,
                      #          WIF, AR repo, 1 service, 2 jobs, 2 schedulers
make tf-apply         # run by hand with an operator identity
```

The Cloud Run service and jobs are created with an **immutable digest-pinned
public bootstrap image** (`var.bootstrap_image`) so this first apply succeeds
before any DevRadar image exists. The delivery Scheduler is created paused, so
that bootstrap image never runs on the automatic schedule with delivery
secrets. CI resolves each real release tag to a digest, updates the delivery
consumer first and serve producer last, then resumes delivery only after every
update succeeds. Terraform `ignore_changes` preserves the deployed images and
Scheduler state on later applies. This creates everything except the real
images and operator-supplied secret **values** (step 2). It also generates
separate token-flash and invitation-delivery keys and stores their first secret
versions. Capture the outputs:

```bash
terraform -chdir=infra/saas output
```

### 2. Populate secret values

Terraform creates six secret *containers*. It assembles
`devradar-saas-database-url` from the generated DB password and generates
`devradar-saas-token-flash-key` and `devradar-saas-delivery-key` with separate
`random_id` resources; none need tfvars or out-of-band population. The other
three seed a **placeholder** version so the
serve service can deploy before real values exist. They are populated two
different ways — match each to its source of truth or the next `terraform apply`
will revert it:

**`devradar-saas-send-api-key` (Resend, required) — out-of-band.** It carries
`ignore_changes`, so add the real key by hand and Terraform leaves it alone (with
the placeholder, magic-link emails are logged, not sent):

```bash
printf '%s' 'YOUR_RESEND_KEY' | \
  gcloud secrets versions add devradar-saas-send-api-key --data-file=- --project thingzio
```

**`devradar-saas-anthropic-api-key` (optional admin metrics analysis) and
`devradar-saas-oauth-client-secret` (optional GitHub sign-in) — tfvars-driven.**
These have **no** `ignore_changes`; tfvars is the source of truth. Set them in the
gitignored `infra/saas/terraform.tfvars` and re-apply — do **not** add versions with
`gcloud`, as the next apply would overwrite them:

```hcl
# infra/saas/terraform.tfvars (gitignored — never committed)
anthropic_api_key         = "YOUR_ANTHROPIC_KEY"
github_oauth_client_id    = "YOUR_OAUTH_CLIENT_ID"      # public identifier (plain env var)
github_oauth_client_secret = "YOUR_OAUTH_CLIENT_SECRET"
```

```bash
make tf-apply          # rotates the tfvars-driven secrets to their real values
```

Leaving either var empty keeps the placeholder, which the app treats as unset (the
AI summary stays off; the UI stays email-only).

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
Cloud Scheduler does not expose job resource attributes to IAM Conditions, so
the deployer's Scheduler custom role is project-scoped but contains only
`cloudscheduler.jobs.get`, `cloudscheduler.jobs.pause`, and
`cloudscheduler.jobs.enable`. It cannot create, delete, run, or change jobs.

<details><summary>Setting them by hand instead</summary>

Create an **environment named `saas`** and set each variable from the outputs:
`WIF_PROVIDER` = `terraform output -raw wif_provider`, `DEPLOYER_SA` =
`terraform output -raw deployer_sa`, `REGION` = `us-west1`, `PROJECT_ID` =
`thingzio`.
</details>

### 4. First release

Tag a release; CI (`.github/workflows/release.yaml`) builds and pushes all three
images (serve and deliver via ko, scan via `Dockerfile.scan`) and deploys them
to the Cloud Run resources Terraform already created:

```bash
git tag v0.1.0
git push origin v0.1.0
```

Watch the `release` → `deploy` workflows. On success:

```bash
gcloud run services describe devradar-saas-serve --region us-west1 --format 'value(status.url)'
gcloud run jobs describe devradar-saas-deliver --region us-west1 --format 'value(name)'
curl -s "$(…)/health"     # -> ok
```

The release workflow resolves the three pushed images to full digest-pinned
references and passes that immutable bundle to deploy. Deploy validates each
literal registry/repository prefix and digest before it pauses delivery, then
updates delivery, scan, and serve in order and resumes the schedule as its final
operation. This is deliberately forward-only: it never rolls images back. Every
mutation prefix is compatible—old producer/new consumer or new producer/new
consumer; the workflow can never install a new producer over an old consumer.

Before retrying any failed deployment, inspect both the Scheduler state and the
exact image references on all three Cloud Run resources. Authentication,
validation, or pause failure performs no image mutation and may leave the
Scheduler in its prior state. Once pause succeeds, any later failure, timeout,
or cancellation before the final resume leaves delivery paused. Rerun
`.github/workflows/deploy.yaml` through `workflow_dispatch` with the same three
full `@sha256:` image references. The immutable updates are idempotent, so the
rerun accepts an already-paused Scheduler, safely converges from any mutation
prefix, and resumes only after every update succeeds. Never manually resume the
Scheduler after a partial image mutation. If cancellation races the final
resume request, all three image updates have already succeeded; inspect state
and rerun the same immutable bundle before further operator action.

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

Once the deploy is confirmed, set `deletion_protection = true` on the service
and both jobs in `infra/saas/cloudrun.tf`, then `make tf-apply`.

---

## Routine updates

### Account-sharing rollout gate — currently disabled

Account sharing is not shipped. Terraform owns
`DEVRADAR_ACCOUNT_SHARING_ENABLED` through `account_sharing_enabled`, which
defaults to `false`. Keep the Terraform variable false in production until the
owner completes the validation below and separately approves rollout. Do not
set the Cloud Run environment variable out of band because a later Terraform
apply would revert it. The flag gates invitation creation, management, and
acceptance; normal single-user account access remains available while it is off.

The rollout unit is one immutable bundle containing the delivery, scan, and
serve images at exact SHA-256 digests. The deploy workflow validates all three
references before mutation, pauses the delivery Scheduler, updates the delivery
consumer before the serve producer, and resumes only after every update
succeeds. Any failure leaves delivery paused. Inspect state and rerun the same
three digest references byte-for-byte; never substitute tags, mix bundles,
manually resume a partial rollout, or enable sharing on mixed revisions.

The serve revision must have the same base64-encoded 32-byte
`DEVRADAR_DELIVERY_KEY` as the `devradar-deliver` job. Enabling sharing without
that key fails server startup. The delivery job also requires the durable key
and production Resend credential and fails closed when either is absent or
invalid. Delivery failure never grants membership.

Before enabling the flag, restore and migrate an isolated production backup
through migrations 030–032, run `make qualify` and `go build ./...`, and have
the owner validate:

1. ordinary signup creates no user or account before verified token consumption;
2. invitations use an expiring, single-use fragment bearer and matching verified email;
3. delivery retry/idempotency produces no duplicate recipient-visible message;
4. `reader`, `editor`, and `admin` permissions match the documented role matrix;
5. account switching never leaks another account's data or credentials;
6. role change and revocation take effect on the next request;
7. deleting one account preserves multi-account users and their other memberships;
8. platform administration uses the actor's email and account-scoped API-token operations.

Only an explicit owner decision after that evidence authorizes setting
`account_sharing_enabled = true` in the gitignored
`infra/saas/terraform.tfvars`, reviewing `make tf-plan`, and running
`make tf-apply`. Do not mark the ROADMAP outcome shipped merely because the code
and migrations are present.

### Ship new application code

Apply infrastructure changes before releasing an image that depends on them.
In particular, Terraform **must** be applied before deploying any image that
requires `DEVRADAR_TOKEN_FLASH_KEY` or `DEVRADAR_DELIVERY_KEY`; otherwise the
serve or delivery process fails startup validation. This rollout remains
owner-gated: review `make tf-plan`, obtain explicit owner approval, then run
`make tf-apply` before tagging the release.

Bump the semver tag — that's the whole flow (the tag triggers the release
workflow):

```bash
make bump-patch     # v0.1.0 -> v0.1.1   (also: bump-minor, bump-major)
```

`bump` refuses if the tree is dirty or has unpushed commits, then creates a
signed tag and pushes it. Equivalent by hand: `git tag vX.Y.Z && git push origin vX.Y.Z`.

CI builds and pushes all three images for `vX.Y.Z`, resolves the completed
publication to one immutable three-image bundle, and updates the running
service and jobs by digest. **DB migrations run automatically** on startup (the
advisory-lock runner applies any new
`pkg/data/postgres/sql/migrations/NNN_*.sql`), so schema changes ship with the
code — no manual migration step.

Five durable database worker-slot leases bound aggregate provider concurrency
across overlapping job executions. Slot leases survive database connection or
process loss and expire after the Cloud Run execution timeout; per-delivery
account/attempt leases continue to fence each outbox transition.

Manual deployment through `workflow_dispatch` on
`.github/workflows/deploy.yaml` does not accept a tag. Supply all three full
references through the `delivery_image`, `scan_image`, and `serve_image`
inputs, each with exactly one lowercase 64-hex SHA-256 digest:

```text
delivery_image = us-west1-docker.pkg.dev/thingzio/devradar-saas-images/devradar-deliver@sha256:<64 lowercase hex>
scan_image     = us-west1-docker.pkg.dev/thingzio/devradar-saas-images/devradar-scan@sha256:<64 lowercase hex>
serve_image    = us-west1-docker.pkg.dev/thingzio/devradar-saas-images/devradar-serve@sha256:<64 lowercase hex>
```

For a failed deployment, inspect Scheduler and Cloud Run image state first,
then rerun with the same three references byte-for-byte. Never substitute a
mutable tag or manually resume after a partial image mutation.

### Change infrastructure

Edit `infra/saas/*.tf`, then:

```bash
make tf-plan && make tf-apply
```

### Bump scanner versions

The scanner binaries are pinned in **two places that must stay in sync**:
`.settings.yaml` (`scanners.{grype,trivy,syft}`) and the `ARG` defaults in
`Dockerfile.scan`. Update both, then cut a release — the new scan image carries
the new scanners. (The vulnerability *databases* are not pinned; a tick with due
work refreshes them before scanning.) Expect a one-time wave of `tooling`-caused
finding events after a scanner upgrade — these are recorded but never alerted on
(see DEVELOPMENT.md "Reproducibility and causality").

### Rotate a secret

The **Resend key** is out-of-band (`ignore_changes`) — add a version and refresh
the service:

```bash
printf '%s' 'NEW_VALUE' | gcloud secrets versions add devradar-saas-send-api-key --data-file=- --project thingzio
gcloud run services update devradar-saas-serve --region us-west1   # pick up "latest" version
```

The **Anthropic key** and **GitHub OAuth client secret** are tfvars-driven — edit
their values in `infra/saas/terraform.tfvars` and `make tf-apply`. Do not rotate
these with `gcloud`; the next apply would overwrite the hand-added version.

(The DB password is managed by Terraform via `random_password`; rotate it with a
`terraform apply -replace=random_password.db_password`, which also updates the
`devradar-saas-database-url` secret.)

The **token-flash key** is Terraform-generated and does not rotate during routine
applies. Rotate it only with explicit owner approval:

```bash
terraform -chdir=infra/saas apply -replace=random_id.token_flash_key
```

Replacement creates a new pinned secret version and rolls the serve service to
it. Wait for the apply and Cloud Run revision rollout to finish before resuming
release activity. Rotation invalidates any unread token flashes; their maximum
lifetime is two minutes.

The **delivery key** is independently Terraform-generated. Rotate it only with
explicit owner approval after disabling invitation creation and verifying no
pending or leased outbox row retains ciphertext; the worker intentionally has
no old-key fallback:

```bash
terraform -chdir=infra/saas apply -replace=random_id.delivery_key
```

---

## Operations

- **Run a scan now:** `gcloud run jobs execute devradar-saas-scan --region us-west1 --wait`
- **Run delivery now:** `gcloud run jobs execute devradar-saas-deliver --region us-west1 --wait`
- **Logs:** `gcloud run services logs read devradar-saas-serve --region us-west1` /
  `gcloud run jobs executions list --job devradar-saas-scan --region us-west1` /
  `gcloud run jobs executions list --job devradar-saas-deliver --region us-west1`
- **Scan failures** are recorded in the `devradar_scan_failure` table (not just
  logs) — query it to see per-SBOM/per-scanner errors.
- **DB access** to the shared instance is private-IP only; use the shared
  `thingzio/infra` `tools/db-connect` helper (temporary proxy) for ad-hoc queries.

Local `make deliver` requires a controlling interactive terminal. In development
without Resend, the complete invitation link is written only to `/dev/tty`;
redirected or noninteractive execution fails closed without leasing outbox rows.
Use the same durable key as the local serve process:

```bash
export DEVRADAR_DELIVERY_KEY="$(openssl rand -base64 32)"
export DEVRADAR_ACCOUNT_SHARING_ENABLED=true
make serve       # terminal 1
make deliver     # terminal 2, attached to /dev/tty
```

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
- **Three images, two build paths:** serve and deliver are ko (pure Go); scan is
  a Dockerfile (needs grype/trivy/syft at runtime). Keep the Dockerfile scanner
  ARGs in sync with `.settings.yaml`.
- **Deferred:** webhook delivery and scan concurrency pooling. See
  [ROADMAP.md](ROADMAP.md). `SEND_API_KEY` serves magic-link and invitation
  email.
