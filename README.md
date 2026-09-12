# DevRadar

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

Track how the vulnerabilities in your container images change over time.

You submit an SBOM; DevRadar repeatedly matches that frozen package inventory
against current vulnerability data and records every change as an event. It
answers the question a scanner cannot — not "what vulnerabilities exist right
now" but **"what changed, when, and is it getting better or worse."**

> **This is a reference implementation, not a product.** Apache-2.0,
> self-hostable, maintained on a best-effort basis. There are no plans, no
> pricing, and no SLA. See
> [CONTRIBUTING.md](CONTRIBUTING.md#project-governance) for what that means in
> practice.

A demo instance runs at [devradar.thingz.io](https://devradar.thingz.io) — this
code with the maintainer's data in it, useful for seeing the output before
running your own.

## Quick start

```shell
git clone https://github.com/thingzio/devradar && cd devradar
make db-up     # local Postgres via docker compose
make seed      # seed a test account
make serve     # run the server
```

Full walkthrough, including submitting your first SBOM: [Run It Locally](#run-it-locally).
[`devradarctl`](https://github.com/thingzio/devradarctl) is the CLI.

> The local Postgres binds port **5432**. DevPulse and DevTrace do the same, so
> only run one of the three stacks at a time.

## What it does

DevRadar is a container vulnerability *tracking* service built around a single
input: the SBOM. An account submits a Software Bill of Materials for a specific
image digest; DevRadar repeatedly matches that inventory with multiple scanners
and records every change as an event.

Instead of pulling and scanning images itself, DevRadar consumes SBOMs submitted
through an authenticated API. Each SBOM is pinned to an image digest,
content-addressed, and stored once. A scheduled job matches due SBOMs with Grype
and Trivy, normalizes results into a scanner-agnostic schema, and appends a
change event whenever a finding is added, fixed, re-rated, or resolved. Because
the SBOM is a frozen inventory, result changes can be attributed to image,
database, or tooling inputs.

The architecture needs no image pulls, registry access, or VM fleet, so DevRadar
can track images from **private registries it could never access** — the SBOM
crosses the trust boundary, not credentials.

**Licenses, too.** The same SBOM already names a license for every package, so
DevRadar also captures an **open-source license inventory** at submission, with
no extra scan. It classifies each package into an obligation category
(permissive / weak- & strong-copyleft / proprietary / unknown), visualizes the
fleet's license landscape, and supports an opt-in **compliance policy** that
flags packages carrying a denied license. See `GET /v1/licenses`,
`GET /v1/sboms/{id}/licenses`, and the `/licenses` UI page.

## Related projects

DevRadar is one of three independent tools that answer different supply-chain
questions. Each stands alone; none depends on the others.

| | |
|---|---|
| **DevRadar** (this repo) | Are the container images I depend on accumulating unpatched vulnerabilities? |
| [DevPulse](https://github.com/thingzio/devpulse) | Is this project healthy — who maintains it, and is activity growing or thinning? |
| [DevTrace](https://github.com/thingzio/devtrace) | What do we know about the people contributing to it? |

---

## Who it is for

- **Anyone shipping or depending on container images** who wants the time
  dimension a scanner does not give: is this getting better or worse?
- **Platform engineers** whose CI already produces SBOMs with Syft,
  `docker sbom`, or BuildKit — submission is one more step in a pipeline that
  already has the artifact.
- **Teams under NIST SSDF or EU CRA expectations**, where continuous monitoring
  of shipped artifacts with a timestamped audit trail is becoming required
  rather than optional. DevRadar produces that evidence as a side effect of its
  scan cycle.

The distinction that matters most in practice: *"a new CVE was disclosed against
a package I already ship"* is a different problem from *"my new image introduced
a vulnerable package,"* and DevRadar separates them.

---

## Why

### Short

Vulnerability scanners tell you what's wrong right now. DevRadar tells you what changed, when it changed, and whether it's getting better or worse. Continuous rescanning of a fixed inventory turns point-in-time scanning into a trend line — the difference between a fire alarm and a smoke detector.

### Long

Most teams run a scanner in CI, get a report, and either fix things or don't. What they lack is the time dimension. Is this image accumulating vulnerabilities? Did today's scanner-DB update surface 12 new criticals, or did the image actually change? Is the maintainer patching, or are CVEs piling up?

DevRadar provides that time dimension. By repeatedly matching the same SBOM and recording every change as an event, it produces a vulnerability trend line for every image digest an account tracks. Because the SBOM is a frozen package inventory, the cause of every change is explicit:

- **A new finding on an unchanged digest** → the vulnerability database learned something new (a CVE was disclosed, or an existing one was re-rated). The image didn't change; the world's knowledge of it did.
- **A new finding on a new digest** → the image itself changed and introduced it.
- **A finding disappears or gains a fix** → the exposure was resolved.

This is only possible because DevRadar scans a stable inventory. A service that re-pulls and re-scans images conflates "the image changed" with "the scanner DB changed" and cannot cleanly separate them.

For teams operating under NIST SSDF or EU Cyber Resilience Act requirements, continuous vulnerability monitoring of shipped artifacts — with a reproducible, timestamped audit trail — is becoming an expectation, not a nice-to-have. DevRadar generates that evidence as a side effect of its recurring scan cycle.

---

## The Core Idea: Scan the SBOM, Not the Image

DevRadar never pulls a container image. The account's CI already generates an SBOM; DevRadar consumes it. This single decision removes an entire category of problems and unlocks a capability competitors can't easily match.

**What it removes:**

- No registry authentication — no Docker Hub subscription, no PATs, no NGC keys, no Secret Manager for registry creds.
- No rate limits, no Docker Hub ToS ambiguity, no Cloudflare ASN detection.
- No image egress cost (the dominant line item in a pull-based design).
- No VM fleet, no Cloud Tasks queue, no digest-checker, no self-termination logic. Daily scanning is one Cloud Run Job of pure CPU.

**What it unlocks:**

- **Private-registry coverage.** DevRadar can track images it could never pull — internal images behind a corporate registry, air-gapped artifacts, anything an account can generate an SBOM for. The SBOM crosses the boundary; credentials never leave the account. This is the headline capability, not a footnote.
- **Determinism.** The same SBOM + the same scanner DB version always produces the same findings. "Show me this image's vulnerabilities as of DB version X" is reproducible forever — a compliance and audit primitive.

### What DevRadar Guarantees (and What It Doesn't)

DevRadar operates on a **trust-on-submission** model. It guarantees:

- **Determinism / reproducibility** — identical SBOM + identical scanner DB → identical findings, always.
- **Clean change causality** — every delta on a fixed SBOM is DB-driven; a new SBOM for the same image is image-driven. The digest boundary is explicit in the data.

By default DevRadar does **not** guarantee **authenticity** — that a submitted SBOM faithfully represents the image digest it claims. Without an attestation it cannot verify this (it never pulls the image), so a wrong digest or stale inventory yields results that reflect what the account submitted. Garbage in, garbage out — by design, and clearly bounded.

**Authenticity is now available as an optional overlay.** An account may submit a sigstore/cosign attestation alongside the SBOM (an `attestation` field on `POST /v1/sboms`). When a trust policy is configured, DevRadar verifies the signature (keyless via Fulcio identity/issuer + Rekor, or a configured public key) and binds it to the SBOM's subject digest — either to the exact SBOM bytes (strongest) or to the resolved image digest. The outcome moves the SBOM's `verification_status` to `verified` or `failed`, and the full evidence (mode, identity/issuer or key, predicate type, transparency-log reference, verifier + policy versions) is retained in `devradar_sbom_attestation` for audit. Verification is strictly additive: it is never required, an unconfigured deployment leaves every SBOM `unverified`, and a verification failure never blocks ingest. DevRadar still guarantees determinism regardless.

### Is Scanning an SBOM as Accurate as Scanning the Image?

A common objection to SBOM-based scanning is that it's less accurate than scanning the image directly. For an **all-layers** SBOM this is far narrower than the objection implies, and the residual gap is manageable rather than structural. The key is to split scanning into two independent steps:

- **Matching** (package list → CVEs) is **identical** either way. Grype/Trivy run the same matcher over the same packages against the same DB whether the input is an SBOM or an image. There is no accuracy difference in this step — and recurring matching is where DevRadar's value lives.
- **Cataloging** (image → package list) is the only place a gap can exist, and it's a property of the SBOM *generator*, not of "SBOM vs image" as categories.

That reduces the whole question to: does the SBOM's catalog equal what the scanner would have cataloged itself?

| Situation | Gap vs. direct image scan |
|---|---|
| All-layers SBOM, generated by the scanner's own cataloger family (e.g. Syft SBOM → Grype) | **None** — bit-for-bit the same operation |
| All-layers SBOM, cross-tool (e.g. Syft SBOM → Trivy matcher) | **Small, bidirectional** — analyzer differences of a few percent; each tool catches things the other misses |
| Statically-linked binaries, vendored deps without a manifest | **Real but shared** — direct image scanning is only marginally better; both are weak, because the identifying metadata simply isn't there |
| A newer cataloger would find more, but the digest hasn't changed | **DevRadar-specific staleness** — affects cataloging only, not CVE matching; resolves automatically when a new digest yields a fresh SBOM |

**Two practical takeaways, both reflected in the design:**

1. **Faithfulness is highest when the SBOM comes from the scanner's own cataloger, all layers, deep binary classification enabled.** Grype is Syft-native, so a Syft-generated CycloneDX SBOM is the zero-gap path. Running Trivy as the second scanner is a deliberate cross-check — divergence between the two *is itself signal*, surfacing cataloger disagreement.
2. **Cataloging is frozen per digest; matching stays live.** This is a feature, not a bug: it's exactly what gives DevRadar clean change causality. New CVEs against the existing inventory — the overwhelming majority of day-to-day change — are always caught. Newly-cataloged packages arrive with the next digest. DevRadar records the SBOM's generator tool and version at ingest so this boundary is auditable.

The honest summary: for an all-layers SBOM, DevRadar's accuracy is a *generator-quality* question you can control, not an inherent penalty of not pulling the image.

---

## How It Works

```
┌──────────────────────────────────────────────────────────────┐
│  Account CI pipeline                                         │
│  syft / docker sbom / buildkit  →  SBOM (CycloneDX or SPDX)  │
└─────────────────────────┬────────────────────────────────────┘
                          │ POST /v1/sboms  (authenticated)
┌─────────────────────────▼────────────────────────────────────┐
│  Ingest API (Cloud Run service)                              │
│  - authenticate account credential, enforce quota            │
│  - validate + size-cap the SBOM (untrusted input)            │
│  - extract subject image ref + digest from SBOM              │
│  - content-address by sha256(bytes); dedupe                  │
│  - store bytes in GCS, THEN activate row (pending→active)    │
└─────────────────────────┬────────────────────────────────────┘
                          │ (SBOM now in the active set)
┌─────────────────────────▼────────────────────────────────────┐
│  Scan Job (Cloud Run Job, ~every 15 min, pure CPU)           │
│  for each DUE SBOM (never scanned, or last scan > 12h ago):  │
│    - grype  sbom:<file>   → normalize                        │
│    - trivy  sbom  <file>  → normalize                        │
│    - UPSERT current state into `findings`                    │
│    - append `finding_events` ONLY where state changed        │
│    - write one `scan_runs` summary row (with db_version)     │
└─────────────────────────┬────────────────────────────────────┘
                          │ findings + change events
┌─────────────────────────▼────────────────────────────────────┐
│  Read API + server-rendered UI                               │
│  - findings, alerts, work queue, comparisons, and trends     │
│  - email/webhook delivery remains on the roadmap             │
└──────────────────────────────────────────────────────────────┘
```

The scan job is triggered frequently by Cloud Scheduler (default every ~15 min, `var.scan_schedule`) rather than once nightly, but each SBOM is only *due* when it has never been scanned or its last scan is older than the staleness window (`DEVRADAR_SCAN_MAX_AGE`, code default 12h; the reference deployment sets it to 24h via `var.scan_max_age`). So a freshly-submitted SBOM is picked up on the next tick (low latency) while any given SBOM is rescanned at most once or twice a day depending on the configured window (bounded load): cron frequency controls latency, the staleness window controls load, independently. Freshness is tracked per scanner, so an SBOM stays due until *every* scanner (grype + trivy) has a recent run. An idle tick skips scanner DB refresh entirely. With work present, each scanner refreshes a missing or older-than-24-hour DB once and freezes it for the run. No fleet is required.

---

## Data Model (Conceptual)

The store is Cloud SQL PostgreSQL. Migrations are authoritative; the conceptual shape is:

| Table | Role | Growth |
|---|---|---|
| `users` | One row per verified person, independent of account ownership | Static |
| `accounts` | Owns SBOMs, policies, alert routing, and API credentials | Static |
| `account_members` | Grants one user an `admin`, `editor`, or `reader` role in an account | Per accepted membership |
| `sboms` | One row per unique submitted SBOM (content-addressed, digest-pinned, immutable) | Per submission |
| `scan_runs` | One row per SBOM per scanner result; summary counts + version axes | Append-only |
| `findings` | **Current** state: one row per unique finding per SBOM per scanner (UPSERT) | Bounded — latest state only |
| `finding_events` | Append-only change log; a row **only when** a finding is added, fixed, re-rated, or resolved | Slow — zero rows on a quiet day |

**Why an event log instead of daily snapshots.** A fixed SBOM has a frozen package inventory, so day-over-day findings are ~99% identical. Storing a full snapshot every day would write hundreds of millions of duplicate rows per year. Instead DevRadar keeps *current state* (`findings`, UPSERT) plus an append-only change log (`finding_events`). The read API and alert evaluator consume the same committed event stream.

**Retention.** `finding_events` is retained **indefinitely** in v1 — the audit trail is the product, and events are cheap. The table is partitioned monthly by `occurred_at` from day one, so future retention tiers (per access plan) or roll-ups (detailed CVE data for the last N days, aggregated trend before that) are additive — a policy or a derived read-model, never a migration.

### Account identity and sharing contract — unshipped

The implementation distinguishes three identities:

- A **user** is one verified person and email identity.
- An **account** owns evidence, policies, alerts, and API credentials.
- A **membership** grants one user one role in an account. A user may belong to
  multiple accounts and selects the active account for each browser session.

Roles are account-wide and equal for every member holding that role:

| Role | Read account | Personal state | Submit/archive evidence | Settings, credentials, members |
|---|---:|---:|---:|---:|
| `reader` | Yes | Yes | No | No |
| `editor` | Yes | Yes | Yes | No |
| `admin` | Yes | Yes | Yes | Yes |

API tokens belong to an account, not a user or membership. They authenticate
automation directly into that account and never inherit a human role.

Platform account deletion first suspends the account and preserves its exact
SBOM object-path inventory, then deletes those objects one by one before
finalizing database deletion. Storage or database failure leaves the account
suspended for an idempotent retry; it is never reactivated automatically, and
users retain memberships in their other accounts.

When account sharing is enabled, an admin chooses an email and exact role.
DevRadar persists a pending invitation and an encrypted delivery-outbox row;
delivery failure grants nothing. The bearer token travels only in the URL
fragment (`#token=...`), is single-use and expiring, and is accepted only by a
signed-in user whose verified email matches the recipient. Acceptance creates
or reactivates the membership atomically. Revocation is immediate on the next
request because account access is revalidated from PostgreSQL rather than
cached; the user's identity and memberships in other accounts remain intact.

`DEVRADAR_ACCOUNT_SHARING_ENABLED` gates invitation creation, management, and
acceptance and defaults to false. Migrations 030–032 add user/account identity,
audited account state, invitations, and the delivery outbox without renaming
the compatibility `devradar_tenant` table or `tenant_id` columns. This is not a
shipped feature: do not enable it, deploy it, or mark its ROADMAP outcome
complete until the owner has validated signup, invite, delivery, acceptance,
role changes, revocation, account switching, and API-token behavior and has
made an explicit rollout decision.

---

## Multi-Scanner by Design

DevRadar normalizes multiple scanners into one scanner-agnostic finding, so no single scanner's quirks define the data. v1 ships **Grype and Trivy** together — running two from the start prevents overfitting the schema to either one. Additional scanners register as converters without touching the rest of the pipeline.

This design (a `Scanner` interface that runs the tool and a `Converter` interface that normalizes its JSON) draws on patterns proven in [vimp](https://github.com/mchmarny/vimp). DevRadar reimplements the model natively, with no vimp dependency, and changes the scanner input from an image reference to an SBOM file. See [DEVELOPMENT.md](DEVELOPMENT.md).

---

## Cost Model

Pure compute, no egress, no VMs, no registry subscriptions. At ~1,000 tracked SBOMs:

| Item | Monthly |
|---|---|
| Ingest API (Cloud Run service, scales to zero) | ~$1–3 |
| Scheduled scan workload (Cloud Run Job, ~2 vCPU × ~90 min/day) | ~$8 |
| GCS SBOM storage (content-addressed, ~130 KB gzipped avg) | <$1 |
| Cloud SQL `db-custom-1-3840` + 50 GB SSD | ~$65 |
| Scanner DB downloads (inbound to GCP) | $0 |
| Cloud Scheduler | <$1 |
| **Total** | **~$75/month** |

The dominant cost is the database, not the pipeline. There is no egress line item — the single largest cost in any pull-based scanning design — because DevRadar never pulls an image.

---

## Roadmap

See [ROADMAP.md](ROADMAP.md). Near-term work is production hardening, SBOM
quality assessment, email/webhook delivery, and deterministic CI automation.

---

## Run It Locally

The full pipeline runs on your machine with Docker (Postgres) and the scanner
binaries — no GCP required. In local mode SBOM bytes are stored on disk (a shared
folder the API and scan job both use) instead of GCS.

Local object filenames are derived from the complete object URI. Existing
`.sboms` directories created by older versions used an ambiguous flattened
mapping and must be reset (`rm -rf .sboms`) before starting the updated server.

### Prerequisites

- Go (version in [`.settings.yaml`](.settings.yaml)) and Docker
- [`syft`](https://github.com/anchore/syft) to generate SBOMs
- [`grype`](https://github.com/anchore/grype) and [`trivy`](https://github.com/aquasecurity/trivy) to scan them

```bash
brew install syft grype trivy        # macOS; see each project for other platforms
```

### 1. Start Postgres and seed an account

```bash
make db-up                           # starts Postgres in Docker, runs migrations on first serve
make seed                            # creates a local user/account, prints an API token
export DR_TOKEN=dr_...               # copy the token from the seed output
```

### 2. Start the API server

```bash
make serve                           # http://localhost:8080 (leave running in this terminal)
```

The UI uses passwordless magic-link sign-in; without an email sender configured
(`SEND_API_KEY`), the server logs the sign-in link instead of emailing it (see
the UI section below). For local API testing, `make seed` is simpler. Check it:

```bash
curl -s http://localhost:8080/health         # -> ok
```

### 3. Quick path — one command per image

`tools/sbom-submit` does the whole thing for you: resolve the image's manifest
digest (`crane`), generate an all-layers CycloneDX SBOM (`syft`), and submit it.
Just give it an image reference:

```bash
export DR_TOKEN=dr_...            # mint in the UI (prod) or 'make seed' (local)
# DR_BASE_URL defaults to https://devradar.thingz.io; set it for a local server.

go run ./tools/sbom-submit quay.io/jetstack/cert-manager-cainjector:v1.20.2
# or: make submit IMAGE=quay.io/jetstack/cert-manager-cainjector:v1.20.2
```

It requires `syft` and `crane` on PATH. This is the recommended path for CI and
day-to-day use — the rest of this section explains what it does under the hood
(and how to submit a pre-generated SBOM file instead).

### 3a. Generate an SBOM manually — by digest

Two rules give DevRadar the most accurate, correctly-pinned SBOM:

1. **By digest, not by tag.** Scanning `image:tag` records only the tag (and
   layer digests) — not the image's manifest digest, which DevRadar needs to pin
   the inventory. Resolve the digest first, then scan `image@sha256:...`.
2. **All layers, not just the squashed top.** `--scope all-layers` catalogs
   packages in every layer, including ones deleted in a later layer. This is the
   configuration the [accuracy analysis](#is-scanning-an-sbom-as-accurate-as-scanning-the-image)
   assumes; the default `squashed` scope can miss packages and understate findings.

```bash
# resolve the current digest for a tag
docker pull -q alpine:3.19
DIGEST=$(docker inspect --format '{{index .RepoDigests 0}}' alpine:3.19 | sed 's/.*@//')

# CycloneDX (recommended — grype and trivy both read it cleanly), all layers
syft -q --scope all-layers -o cyclonedx-json=alpine.cdx.json "registry:alpine@$DIGEST"

# SPDX also works (DevRadar canonicalizes SPDX -> CycloneDX before scanning)
syft -q --scope all-layers -o spdx-json=alpine.spdx.json "registry:alpine@$DIGEST"
```

Trivy can also generate SBOMs (`trivy image --format cyclonedx --output x.cdx.json alpine@$DIGEST`).

> **Gotcha — `image:tag@sha256:...` does NOT work.** Every registry tool accepts
> the combined `tag@digest` reference, but Syft, given it, records the *tag* and
> silently drops the digest — the SBOM then has no digest and DevRadar rejects it.
> Generate **digest-only** (`image@sha256:...`, no `:tag`), or use the override
> below.

### 4. Submit the SBOM

```bash
make submit SBOM=alpine.cdx.json
# -> HTTP 202: {"sbom_id":"...","digest":"sha256:...","existing":false}
```

`make submit` wraps a small helper (`tools/sbom-submit`) that reads the file and
base64-encodes it into the request body. **Prefer the helper (or a file-based
body) over inline curl** — a real-image SBOM is easily multiple MB, and passing
that base64 blob as a `-d` command-line argument overflows the shell's
`ARG_MAX` (`Argument list too long`). It's a shell limit, not a DevRadar one:
the API accepts up to **20 MiB** decoded (and gzip-compressed bodies — see
below). Two robust ways to POST directly:

```bash
# a) write the JSON body to a file, then stream it with --data @file (no arg limit)
python3 - alpine.cdx.json > body.json <<'PY'
import base64, json, sys
print(json.dumps({"sbom": base64.b64encode(open(sys.argv[1],"rb").read()).decode()}))
PY
curl -s -X POST http://localhost:8080/v1/sboms \
  -H "Authorization: Bearer $DR_TOKEN" -H "Content-Type: application/json" \
  --data @body.json

# b) small SBOMs only — inline base64 is fine under a few hundred KB
curl -s -X POST http://localhost:8080/v1/sboms \
  -H "Authorization: Bearer $DR_TOKEN" \
  -d "{\"sbom\":\"$(base64 < alpine.cdx.json | tr -d '\n')\"}"
```

`tools/sbom-submit` also accepts a pre-generated SBOM **file** (this is the file
mode `make submit SBOM=...` uses), with an optional `image_ref` override for
SBOMs generated by tag with no embedded digest:

```bash
DR_BASE_URL=https://devradar.thingz.io DR_TOKEN=dr_... \
  go run ./tools/sbom-submit alpine.cdx.json [repo@sha256:...]
```

For most uses, prefer the [image path](#3-quick-path--one-command-per-image)
above — it generates the SBOM correctly for you.

#### Submitting an SBOM generated by tag (image_ref override)

If a tool produced an SBOM without an embedded digest (generated by tag, or the
`tag@digest` gotcha above), pass the digest-pinned reference as `image_ref` and
DevRadar uses that to pin it — the SBOM contents are unchanged:

```bash
# e.g. registry.k8s.io/pause, whose SBOM syft leaves without a digest
DIGEST=$(crane digest registry.k8s.io/pause:3.9)          # or: docker inspect ...
syft -q -o cyclonedx-json=pause.cdx.json "registry:registry.k8s.io/pause:3.9"

# via make: pass the full image@sha256 reference as REF
make submit SBOM=pause.cdx.json REF="registry.k8s.io/pause@$DIGEST"

# or the raw call — image_ref carries the digest
curl -s -X POST http://localhost:8080/v1/sboms \
  -H "Authorization: Bearer $DR_TOKEN" \
  -d "{\"sbom\":\"$(base64 < pause.cdx.json | tr -d '\n')\", \
       \"image_ref\":\"registry.k8s.io/pause@$DIGEST\"}"
```

The `image_ref` override must contain an `@sha256:` digest; without one the
submission is still rejected (DevRadar never pins to a mutable tag). Prefer
digest-only generation where you can — the override is the fallback for tools or
images that don't embed the digest.

### 5. Scan and read results

```bash
make scan                            # runs grype + trivy over all active SBOMs once

# CUJ-1: images I track — grouped by repository (one row per image), paginated
curl -s http://localhost:8080/v1/images -H "Authorization: Bearer $DR_TOKEN"

# CUJ-2: the SBOMs (versions/digests) for one image, newest generation first
curl -s "http://localhost:8080/v1/images/sboms?repo=quay.io/jetstack/cert-manager-cainjector" \
  -H "Authorization: Bearer $DR_TOKEN"

# CUJ-3: how one image's vulnerabilities changed over time, across ALL its digests
curl -s "http://localhost:8080/v1/images/timeline?repo=quay.io/jetstack/cert-manager-cainjector" \
  -H "Authorization: Bearer $DR_TOKEN"

# one SBOM's metadata + severity breakdown (use sbom_id from step 4)
curl -s http://localhost:8080/v1/sboms/<sbom_id>          -H "Authorization: Bearer $DR_TOKEN"

# current findings and change history for one SBOM
curl -s http://localhost:8080/v1/sboms/<sbom_id>/findings -H "Authorization: Bearer $DR_TOKEN"
curl -s http://localhost:8080/v1/sboms/<sbom_id>/events   -H "Authorization: Bearer $DR_TOKEN"

# license inventory — captured at submission, no scan needed
curl -s http://localhost:8080/v1/licenses                  -H "Authorization: Bearer $DR_TOKEN"  # fleet rollup
curl -s http://localhost:8080/v1/sboms/<sbom_id>/licenses  -H "Authorization: Bearer $DR_TOKEN"  # per package, classified + policy verdict

# VEX — suppress findings via an OpenVEX assertion (read-time overlay, never mutates findings)
curl -s http://localhost:8080/v1/vex                       -H "Authorization: Bearer $DR_TOKEN"  # list submitted documents
curl -s -X POST http://localhost:8080/v1/vex \
  -H "Authorization: Bearer $DR_TOKEN" -H "Content-Type: application/json" \
  --data @openvex.json                                                                           # submit (raw OpenVEX JSON, max 5 MiB)

# stop tracking an image (archive — drops from scans + images; history kept)
curl -s -X DELETE http://localhost:8080/v1/sboms/<sbom_id> -H "Authorization: Bearer $DR_TOKEN"
```

Note the license endpoints work **before** `make scan` — they read the ingest-time
inventory, not scan results. Set a compliance policy in the `/licenses` UI to flag
packages carrying a denied license category.

**Full API reference.** Every endpoint is documented at **`/api`** (a human-readable
page) and **`/openapi.yaml`** (a machine-readable OpenAPI 3.1 spec for Postman,
codegen, etc.) — both public, no login required.

**Pagination.** List endpoints (`/v1/images`, `/v1/images/sboms`,
`/v1/images/timeline`, `/v1/sboms/{id}/events`) return at most `?limit` rows
(default 100, max 1000) and include a `next_cursor` when more exist — pass it
back as `?cursor=<token>` for the next page. Cursors are opaque; keyset-based, so
paging is stable under concurrent writes.

SBOMs may also be submitted **gzip-compressed** (base64 the gzip bytes); the
server detects and decompresses them, with a decompression-bomb guard.

**Severity threshold.** Every read endpoint filters by a minimum severity —
`medium` by default, set per account (in the UI, or `min_severity` on the
compatibility account row). Override per request, independently on each
endpoint, with `?min_severity=`:

```bash
curl -s "http://localhost:8080/v1/sboms/<sbom_id>/findings?min_severity=critical" -H "Authorization: Bearer $DR_TOKEN"
```

`/v1/images` always lists every tracked image (the list is an inventory —
images never disappear). The threshold trims each image's `counts` breakdown to
levels at or above it — sub-threshold buckets are omitted from the response
rather than shown as `0`. `relevant` (sum of the shown buckets) and `total`
(*all* findings) are always present, so you can tell lower-severity findings
exist. Unrated (`unknown`) findings are always kept, regardless of the
threshold — an unrated CVE could be anything.

Re-run `make scan` after the vulnerability DB updates (or a scanner upgrade) to
see change events accumulate — an unchanged SBOM against an unchanged DB produces
no new events.

### The token-minting UI (passwordless magic-link)

The UI at `/` lets a human sign in without a password—by magic link or optional
GitHub OAuth—to create and revoke API tokens. Magic links have a 15-minute TTL
and are single use. Sign-up and sign-in are the same flow.

For local API testing, `make seed` is simpler (it mints a token directly). To
exercise the UI locally **without** an email provider, the server logs the
magic link instead of sending it:

```bash
make serve                                  # in another terminal
curl -s -X POST http://localhost:8080/auth/login -d "email=you@example.com"
# then copy the "magic link (email sending disabled)" URL from the serve log
# and open it in a browser — you're signed in.
```

To actually send sign-in email (needed in any real deployment),
set the shared platform email secret before `make serve`:

```bash
export SEND_API_KEY=...                      # Resend API key (shared: SEND_API_KEY)
export EMAIL_FROM="DevRadar <no-reply@thingz.io>"   # optional; has a default
```

Local invitation delivery is a separate, interactive command. Use the same
durable key for the serve and delivery processes:

```bash
export DEVRADAR_DELIVERY_KEY="$(openssl rand -base64 32)"
export DEVRADAR_ACCOUNT_SHARING_ENABLED=true
make serve       # creates invitation/outbox rows; keep running
make deliver     # in another interactive terminal; delivers one batch
```

Without Resend in development, `make deliver` writes the complete invitation
link only to its controlling `/dev/tty`. Redirection, a pipe, CI, or any other
noninteractive invocation fails closed without leasing an outbox row. Never
copy the fragment bearer into logs.

### Common tasks

```bash
make help          # list all targets
make test          # unit + integration tests (needs 'make db-up')
make test-unit     # unit tests only (integration tests skip without a DB)
make scan          # run one scan pass
make db-connect    # psql shell into local Postgres
make db-down       # stop Postgres
```

---

## How it fits with the other deployments

The three tools are independent, but the maintainer's reference deployment runs
all of them in one Google Cloud project, which is worth knowing if you are
reading the private `thingzio/infra` repository under `run/devradar` and wondering why some resources are referenced rather than
created:

- **Cloud SQL** — one shared PostgreSQL instance and database. Each service
  connects as its own user and prefixes its tables (`devradar_*`). DevRadar
  isolates accounts at the application layer through a `tenant_id` predicate;
  DevPulse uses PostgreSQL row-level security for the same job.
- **Cloud Run** — each service owns its own service and jobs, built with
  `ko`/GoReleaser and deployed keylessly through Workload Identity Federation.
- **Secret Manager** — application credentials. DevRadar never stores registry
  credentials, because it never pulls an image.
- **Shared VPC, Artifact Registry, monitoring** — attached rather than created.
- **AI** — optional Claude analysis is confined to the admin metrics view. It is
  never part of deterministic scanning, alert evaluation, policy, or attestation
  verification.

None of this is required to run DevRadar. A self-hoster supplies their own
values for all of it — see
[`run/devradar/terraform.tfvars.example`](https://github.com/thingzio/infra/blob/main/run/devradar/terraform.tfvars.example) and
[DEPLOYMENT.md](DEPLOYMENT.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Documentation fixes are especially
welcome and are the easiest first contribution.

Security reports go through
[GitHub Security Advisories](https://github.com/thingzio/devradar/security/advisories/new),
not public issues — see [SECURITY.md](SECURITY.md).

## License

[Apache 2.0](LICENSE). See [NOTICE](NOTICE) for attribution.
