# DevRadar — Product Brief

## Info

| Field | Value |
|-------|-------|
| **Name** | DevRadar |
| **URL** | https://devradar.thingz.io |
| **Parent** | Thingz (https://thingz.io) |
| **Category** | Container Security / Vulnerability Intelligence |
| **Status** | v1 implemented — ingest + scan + read API run end-to-end locally; infra (Terraform/CI) written, awaiting first deploy |

> Implementation reference (API, data model, SQL schema, scanner design): [IMPLEMENTATION.md](IMPLEMENTATION.md)
> Jump to: [Run It Locally](#run-it-locally)

This document is the high-level design for **v1**: authenticated SBOM submission, daily Grype + Trivy rescanning, event-log deltas, and a read API/UI to retrieve findings and changes. v1 is **pull-based** — push alerts (email/webhook) and Claude narratives are post-MVP; the event log that powers them is built from day one.

---

## What

**1 sentence:**
DevRadar tracks how the vulnerabilities in your container images change over time — you submit an SBOM, and DevRadar rescans it daily against the latest vulnerability data, so you can see exactly what changed, when, and whether it's getting better or worse.

**3 sentences:**
DevRadar is a container vulnerability *tracking* service built around a single input: the SBOM. A tenant submits a Software Bill of Materials for a specific image digest; DevRadar rescans that frozen package inventory every day with multiple scanners and records every change as an event. It answers not "what vulnerabilities exist right now" — any scanner does that — but "what changed since yesterday, when, and is it getting better or worse."

**Paragraph:**
DevRadar is the vulnerability layer of the Thingz open source intelligence platform. Where DevPulse tracks whether a project is healthy and DevTrace evaluates whether a contributor is trustworthy, DevRadar answers the third question: are the container images you depend on accumulating unpatched vulnerabilities over time? Instead of pulling and scanning images itself, DevRadar consumes SBOMs that tenants submit through an authenticated API. Each SBOM is pinned to an image digest, content-addressed, and stored once. A daily job rescans every active SBOM with Grype and Trivy, normalizes the results into a scanner-agnostic schema, and appends a change event whenever a finding is added, fixed, re-rated, or resolved. Because the SBOM is a frozen inventory, the only variable across daily scans is the vulnerability database — which makes every recorded change unambiguous. The architecture is pure compute (no image pulls, no registries, no VM fleet), which means DevRadar can track images from **private registries it could never access** — the SBOM crosses the trust boundary, not credentials.

---

## Who

### Primary Personas

**Security / Supply Chain Risk Analyst**
Monitors the vulnerability posture of container images the organization ships or depends on. Uses DevRadar to track CVE deltas over time — a new critical CVE appearing in a base image triggers investigation, not a full re-audit. Combines DevRadar vulnerability data with DevTrace contributor trust scores and DevPulse project health metrics for a complete supply chain risk picture.

**Platform / Infrastructure Engineer**
Owns the CI pipeline that already produces SBOMs (via Syft, `docker sbom`, BuildKit, etc.). Wires SBOM submission into the build so every published image is tracked automatically. Cares about the distinction between "a new CVE was disclosed against a package I already ship" (DB-driven) and "my new image introduced a vulnerable package" (image-driven).

**OSPO Lead / Open Source Program Manager**
Oversees the organization's open source dependency strategy. Uses DevRadar alongside DevPulse to monitor both project health and artifact security. A project that's healthy (active contributors, fast reviews) but shipping images with unpatched criticals is a different risk profile than a declining project with clean images.

---

## Why

### Short

Vulnerability scanners tell you what's wrong right now. DevRadar tells you what changed, when it changed, and whether it's getting better or worse. Continuous rescanning of a fixed inventory turns point-in-time scanning into a trend line — the difference between a fire alarm and a smoke detector.

### Long

Most teams run a scanner in CI, get a report, and either fix things or don't. What they lack is the time dimension. Is this image accumulating vulnerabilities? Did today's scanner-DB update surface 12 new criticals, or did the image actually change? Is the maintainer patching, or are CVEs piling up?

DevRadar provides that time dimension. By rescanning the same SBOM daily and recording every change as an event, it produces a vulnerability trend line for every image digest a tenant tracks. Because the SBOM is a frozen package inventory, the cause of every change is unambiguous:

- **A new finding on an unchanged digest** → the vulnerability database learned something new (a CVE was disclosed, or an existing one was re-rated). The image didn't change; the world's knowledge of it did.
- **A new finding on a new digest** → the image itself changed and introduced it.
- **A finding disappears or gains a fix** → the exposure was resolved.

This is only possible because DevRadar scans a stable inventory. A service that re-pulls and re-scans images conflates "the image changed" with "the scanner DB changed" and cannot cleanly separate them.

For teams operating under NIST SSDF or EU Cyber Resilience Act requirements, continuous vulnerability monitoring of shipped artifacts — with a reproducible, timestamped audit trail — is becoming an expectation, not a nice-to-have. DevRadar generates that evidence as a side effect of its daily scan cycle.

---

## The Core Idea: Scan the SBOM, Not the Image

DevRadar never pulls a container image. The tenant's CI already generates an SBOM; DevRadar consumes it. This single decision removes an entire category of problems and unlocks a capability competitors can't easily match.

**What it removes:**

- No registry authentication — no Docker Hub subscription, no PATs, no NGC keys, no Secret Manager for registry creds.
- No rate limits, no Docker Hub ToS ambiguity, no Cloudflare ASN detection.
- No image egress cost (the dominant line item in a pull-based design).
- No VM fleet, no Cloud Tasks queue, no digest-checker, no self-termination logic. Daily scanning is one Cloud Run Job of pure CPU.

**What it unlocks:**

- **Private-registry coverage.** DevRadar can track images it could never pull — internal images behind a corporate registry, air-gapped artifacts, anything the tenant can generate an SBOM for. The SBOM crosses the boundary; credentials never leave the tenant. This is the headline capability, not a footnote.
- **Determinism.** The same SBOM + the same scanner DB version always produces the same findings. "Show me this image's vulnerabilities as of DB version X" is reproducible forever — a compliance and audit primitive.

### What DevRadar Guarantees (and What It Doesn't)

DevRadar operates on a **trust-on-submission** model. It guarantees:

- **Determinism / reproducibility** — identical SBOM + identical scanner DB → identical findings, always.
- **Clean change causality** — every delta on a fixed SBOM is DB-driven; a new SBOM for the same image is image-driven. The digest boundary is explicit in the data.

It does **not** guarantee **authenticity** — that a submitted SBOM faithfully represents the image digest it claims. DevRadar cannot verify this without pulling the image. If a tenant submits an SBOM with the wrong digest or a stale inventory, the results reflect what they attested to. Garbage in, garbage out — by design, and clearly bounded.

Signed SBOM attestations (cosign / in-toto / SLSA), where DevRadar verifies the signature and that its subject digest matches, are a planned upgrade for tenants who need authenticity. The v1 schema carries a `verification_status` field so this slots in without migration.

### Is Scanning an SBOM as Accurate as Scanning the Image?

A common objection to SBOM-based scanning is that it's less accurate than scanning the image directly. For an **all-layers** SBOM this is far narrower than the objection implies, and the residual gap is manageable rather than structural. The key is to split scanning into two independent steps:

- **Matching** (package list → CVEs) is **identical** either way. Grype/Trivy run the same matcher over the same packages against the same DB whether the input is an SBOM or an image. There is no accuracy difference in this step — and matching is where DevRadar's daily value lives.
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
│  Tenant CI pipeline                                          │
│  syft / docker sbom / buildkit  →  SBOM (CycloneDX or SPDX)  │
└─────────────────────────┬────────────────────────────────────┘
                          │ POST /v1/sboms  (authenticated)
┌─────────────────────────▼────────────────────────────────────┐
│  Ingest API (Cloud Run service)                              │
│  - authenticate tenant, enforce quota                        │
│  - validate + size-cap the SBOM (untrusted input)            │
│  - extract subject image ref + digest from SBOM              │
│  - content-address by sha256(bytes); dedupe                  │
│  - store bytes in GCS; row in `sboms` (status: active)       │
└─────────────────────────┬────────────────────────────────────┘
                          │ (SBOM now in the active set)
┌─────────────────────────▼────────────────────────────────────┐
│  Daily Scan Job (Cloud Run Job, ~02:00 UTC, pure CPU)        │
│  for each active SBOM:                                        │
│    - grype  sbom:<file>   → normalize                        │
│    - trivy  sbom  <file>  → normalize                        │
│    - UPSERT current state into `findings`                    │
│    - append `finding_events` ONLY where state changed        │
│    - write one `scan_runs` summary row (with db_version)     │
└─────────────────────────┬────────────────────────────────────┘
                          │ findings + change events
┌─────────────────────────▼────────────────────────────────────┐
│  Read API + UI (v1: pull)                                    │
│  - tenant retrieves current findings & change history        │
│    (GET /v1/images, /v1/sboms/{id}/findings, /events)        │
│  - push alerts (email/webhook) + Claude narratives: post-MVP │
└──────────────────────────────────────────────────────────────┘
```

The scanner binaries are pinned and baked into the Cloud Run Job image; the vulnerability database is refreshed once at job start and then frozen for the run, so every daily run uses a single, less-than-24-hours-old DB version. Scanning an SBOM is pure CPU — no network, no I/O beyond the SBOM file — so ~1,000 SBOMs complete in well under two hours on a single 2‑vCPU job. No fleet required.

---

## Data Model (Conceptual)

The store is Cloud SQL PostgreSQL. Full DDL is in [IMPLEMENTATION.md](IMPLEMENTATION.md); the shape:

| Table | Role | Growth |
|---|---|---|
| `tenants` | One row per tenant; owns SBOMs and alert routing | Static |
| `sboms` | One row per unique submitted SBOM (content-addressed, digest-pinned, immutable) | Per submission |
| `scan_runs` | One row per SBOM per scanner per day; summary counts + scanner `db_version` | Append-only |
| `findings` | **Current** state: one row per unique finding per SBOM per scanner (UPSERT) | Bounded — latest state only |
| `finding_events` | Append-only change log; a row **only when** a finding is added, fixed, re-rated, or resolved | Slow — zero rows on a quiet day |

**Why an event log instead of daily snapshots.** A fixed SBOM has a frozen package inventory, so day-over-day findings are ~99% identical. Storing a full snapshot every day would write hundreds of millions of duplicate rows per year. Instead DevRadar keeps *current state* (`findings`, UPSERT) plus a *change log* (`finding_events`, append-only). The change log **is** the delta history — no nightly diff job, no snapshot table. The read API's "what changed" view (and post-MVP alerts) falls directly out of new `added` events.

**Retention.** `finding_events` is retained **indefinitely** in v1 — the audit trail is the product, and events are cheap. The table is partitioned monthly by `occurred_at` from day one, so future retention tiers (per access plan) or roll-ups (detailed CVE data for the last N days, aggregated trend before that) are additive — a policy or a derived read-model, never a migration.

---

## Multi-Scanner by Design

DevRadar normalizes multiple scanners into one scanner-agnostic finding, so no single scanner's quirks define the data. v1 ships **Grype and Trivy** together — running two from the start prevents overfitting the schema to either one. Additional scanners register as converters without touching the rest of the pipeline.

This design (a `Scanner` interface that runs the tool, a `Converter` interface that normalizes its JSON, both behind a registry with format auto-detection) draws on the patterns proven in [vimp](https://github.com/mchmarny/vimp), which implements them for Grype, Trivy, Snyk, Clair, OSV, and Anchore. DevRadar applies the same model — reimplemented natively, with no dependency on vimp — changing the scanner input from an image reference to an SBOM file. See [IMPLEMENTATION.md](IMPLEMENTATION.md).

---

## Cost Model

Pure compute, no egress, no VMs, no registry subscriptions. At ~1,000 tracked SBOMs:

| Item | Monthly |
|---|---|
| Ingest API (Cloud Run service, scales to zero) | ~$1–3 |
| Daily Scan Job (Cloud Run Job, ~2 vCPU × ~90 min/day) | ~$8 |
| GCS SBOM storage (content-addressed, ~130 KB gzipped avg) | <$1 |
| Cloud SQL `db-custom-1-3840` + 50 GB SSD | ~$65 |
| Scanner DB downloads (inbound to GCP) | $0 |
| Cloud Scheduler | <$1 |
| **Total** | **~$75/month** |

The dominant cost is the database, not the pipeline. There is no egress line item — the single largest cost in any pull-based scanning design — because DevRadar never pulls an image.

---

## Roadmap

v1 is deliberately narrow: authenticated SBOM submission, daily Grype + Trivy rescan, event-log deltas, and a **pull** read API/UI for findings and changes. Planned directions, each additive to the same scan/delta core:

- **Push alerting (email/webhook)** — v1 is pull-only. Because the event log already tags every change with a cause, an alerter is a thin consumer: notify the submitting tenant on new `added` CRITICAL/HIGH events (`cause IN ('image','db')`, never on a scanner upgrade). The SBOM carries the tenant; the tenant carries the destination — no extra identity plumbing.
- **AI-assisted OpenVEX stubbing (opt-in)** — a separate, opt-in endpoint that drafts an [OpenVEX](https://github.com/openvex) document for an image's findings. DevRadar already knows the subject digest, CVE, package/version, and fix state — the mechanical skeleton of a VEX statement. Claude turns each finding into a starting narrative and a candidate justification, but every statement defaults to `under_investigation` and is clearly marked AI-generated: **DevRadar stubs, the human decides.** It cannot determine true exploitability from an SBOM (that depends on how code is used), so it never asserts `not_affected` by default. The user expands the stub into a real VEX. See [IMPLEMENTATION.md](IMPLEMENTATION.md).
- **Signed SBOM attestations** — verify cosign/in-toto/SLSA signatures and subject-digest match; move a tenant from `unverified` to `attested`. Adds authenticity on top of determinism.
- **SBOM source #2: service-generated for public images** — for public images a tenant can't or won't SBOM themselves, DevRadar pulls once, generates the SBOM with Syft, and feeds the identical core. This is the original public-catalog vision, reachable as a *source*, not a rewrite.
- **More scanners** — register additional converters (Snyk, OSV, Clair) as corroborating sources per finding.
- **Retention tiers & roll-ups** — per-plan history caps and aggregated long-range trend views derived from the event log.

---

## Run It Locally

The full pipeline runs on your machine with Docker (Postgres) and the scanner
binaries — no GCP required. In local mode SBOM bytes are stored on disk (a shared
folder the API and scan job both use) instead of GCS.

### Prerequisites

- Go (version in [`.settings.yaml`](.settings.yaml)) and Docker
- [`syft`](https://github.com/anchore/syft) to generate SBOMs
- [`grype`](https://github.com/anchore/grype) and [`trivy`](https://github.com/aquasecurity/trivy) to scan them

```bash
brew install syft grype trivy        # macOS; see each project for other platforms
```

### 1. Start Postgres and seed a tenant

```bash
make db-up                           # starts Postgres in Docker, runs migrations on first serve
make seed                            # creates a local tenant, prints an API token
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

### 3. Generate an SBOM — by digest

**Generate SBOMs by digest, not by tag.** Scanning `image:tag` records only the
tag (and layer digests) — not the image's manifest digest, which DevRadar needs
to pin the inventory. Resolve the digest first, then scan `image@sha256:...`:

```bash
# resolve the current digest for a tag
docker pull -q alpine:3.19
DIGEST=$(docker inspect --format '{{index .RepoDigests 0}}' alpine:3.19 | sed 's/.*@//')

# CycloneDX (recommended — grype and trivy both read it cleanly)
syft -q -o cyclonedx-json=alpine.cdx.json "registry:alpine@$DIGEST"

# SPDX also works (DevRadar canonicalizes SPDX -> CycloneDX before scanning)
syft -q -o spdx-json=alpine.spdx.json "registry:alpine@$DIGEST"
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

`make submit` wraps a small helper (`tools/sbom-submit`) that base64-encodes the
file into the request — avoiding shell arg-length limits with large SBOMs. The
raw call, for reference:

```bash
curl -s -X POST http://localhost:8080/v1/sboms \
  -H "Authorization: Bearer $DR_TOKEN" \
  -d "{\"sbom\":\"$(base64 < alpine.cdx.json | tr -d '\n')\"}"
```

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

# list tracked images with their severity breakdown
curl -s http://localhost:8080/v1/images -H "Authorization: Bearer $DR_TOKEN"

# one SBOM's metadata + severity breakdown (use sbom_id from step 4)
curl -s http://localhost:8080/v1/sboms/<sbom_id>          -H "Authorization: Bearer $DR_TOKEN"

# current findings and change history for one SBOM
curl -s http://localhost:8080/v1/sboms/<sbom_id>/findings -H "Authorization: Bearer $DR_TOKEN"
curl -s http://localhost:8080/v1/sboms/<sbom_id>/events   -H "Authorization: Bearer $DR_TOKEN"

# change history for an image ACROSS digests (ref is a query param — refs have slashes)
curl -s "http://localhost:8080/v1/images/timeline?ref=alpine" -H "Authorization: Bearer $DR_TOKEN"

# stop tracking an image (archive — drops from scans + images; history kept)
curl -s -X DELETE http://localhost:8080/v1/sboms/<sbom_id> -H "Authorization: Bearer $DR_TOKEN"
```

SBOMs may also be submitted **gzip-compressed** (base64 the gzip bytes); the
server detects and decompresses them, with a decompression-bomb guard.

**Severity threshold.** Every read endpoint filters by a minimum severity —
`medium` by default, set per tenant (in the UI, or `min_severity` on the tenant
row). Override per request, independently on each endpoint, with `?min_severity=`:

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

The UI at `/` lets a human sign in — **no password, no OAuth** — to create and
revoke API tokens. Enter an email, receive a one-time sign-in link (15-min TTL,
single use), click it to get a session. Sign-up and sign-in are the same flow;
the tenant is created and its email marked verified on first successful link.

For local API testing, `make seed` is simpler (it mints a token directly). To
exercise the UI locally **without** an email provider, the server logs the
magic link instead of sending it:

```bash
make serve                                  # in another terminal
curl -s -X POST http://localhost:8080/auth/login -d "email=you@example.com"
# then copy the "magic link (email sending disabled)" URL from the serve log
# and open it in a browser — you're signed in.
```

To actually send email (needed in any real deployment, and for alerts later),
set the shared platform email secret before `make serve`:

```bash
export SEND_API_KEY=...                      # Resend API key (shared: SEND_API_KEY)
export EMAIL_FROM="DevRadar <no-reply@devradar.thingz.io>"   # optional; has a default
```

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

## Thingz.io Service Family

DevRadar is the third service in the Thingz open source intelligence platform. Each service covers a distinct dimension of supply chain risk:

| Service | Question It Answers | Scope |
|---------|-------------------|-------|
| **[DevPulse](https://devpulse.thingz.io)** | Is this project healthy? | Project-level health analytics — contributor retention, bus factor, velocity, review culture, release cadence |
| **[DevTrace](https://devtrace.thingz.io)** | Can we trust this contributor? | Per-contributor trust scoring — 23 signals across identity, engagement, community, and behavioral patterns |
| **[DevRadar](https://devradar.thingz.io)** | Are these container images accumulating vulnerabilities? | Container vulnerability tracking — CVE time-series, scan deltas, SBOM-based daily rescanning |

### How They Complement Each Other

**DevPulse + DevRadar:** A project with strong health metrics but images accumulating unpatched criticals indicates a packaging or release pipeline problem — the project is alive but its artifacts aren't keeping up. Conversely, a declining project with clean images today is a *future* risk — when the maintainer leaves, vulnerability response time will spike.

**DevTrace + DevRadar:** DevTrace flags contributors with suspicious behavioral patterns *before* code is merged. DevRadar detects the downstream effect — if a compromised contributor introduces a vulnerable dependency, DevRadar catches the CVE delta in the next scan cycle. Together they cover both the contributor trust vector (pre-merge) and the artifact integrity vector (post-publish).

**All three together:** An OSPO or security team can build a complete risk profile for any open source dependency:
1. **DevPulse** — Is the project well-maintained? Will vulnerabilities get patched?
2. **DevTrace** — Are the people contributing to it trustworthy? Could this be another xz-utils?
3. **DevRadar** — Are the published container images actually getting safer over time?

### Shared Infrastructure

All three services run on GCP in the `thingzio` project (`us-west1`) and follow one platform contract — DevRadar references shared resources and creates only its own (details in [IMPLEMENTATION.md](IMPLEMENTATION.md)):
- **Cloud SQL PostgreSQL** — one shared instance (`thingzio-pg`) and database (`thingz`); each service connects as its own DB user and prefixes its tables (`devradar_*`). DevRadar isolates tenants at the application layer (`WHERE tenant_id = $1`), like DevTrace; DevPulse uses Row-Level Security.
- **Cloud Run** — each service owns its service/job; DevRadar runs a serve service (`devradar-saas-serve`) and a daily scan job (`devradar-saas-scan`), built with `ko`/GoReleaser and deployed via Workload Identity Federation.
- **Secret Manager** — centralized credentials; DevRadar uses it only for its DB URL, the email-send key (`SEND_API_KEY`, magic-link + alerts), and the Anthropic key — **never for registry credentials** (it has none).
- **Shared VPC, Artifact Registry, monitoring** — DevRadar attaches to the shared VPC, pushes to its own `devradar-saas-images` repo, and reuses the shared DB alert policies.
- **AI** — like its siblings, DevRadar uses Claude, but narrowly: to turn a day's raw change events into a human-readable delta narrative on alerts (and, opt-in, to stub OpenVEX documents — see roadmap). The core value is still the deterministic data pipeline, not AI generation.

### Key Talking Points

- "We scan packages. We scan containers. We scan infrastructure. Almost nothing tracks whether the *projects* are healthy, the *contributors* are trustworthy, and the *images* are getting safer over time. Thingz covers all three."
- "DevPulse tells you a project is declining. DevTrace flags a suspicious contributor. DevRadar shows the images are accumulating criticals. Each signal alone is a data point — together they're an actionable risk picture."
- "You give us the SBOM, we give you the trend line — even for images we could never pull ourselves."
