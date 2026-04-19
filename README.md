# DevRadar — Container Vulnerability Tracking Pipeline

> Implementation reference (code samples, Packer, Terraform, SQL schema): [IMPLEMENTATION.md](IMPLEMENTATION.md)

## Overview

vectr scans public container images from five registries on a daily schedule, persists time-series vulnerability records, and computes CVE deltas between scans. The pipeline is designed around a single core insight: **most images don't change day-to-day**. A digest-check gate before every pull collapses actual pull volume by 80–90%, which eliminates rate-limit pressure, reduces egress cost, and removes ToS ambiguity with Docker Hub.

The execution model uses ephemeral GCE VMs built from a custom Ubuntu image with all scanners pre-installed and vulnerability databases pre-warmed. VMs pull work from a Cloud Tasks queue, process up to 100 images, and self-terminate. VM count scales with queue depth, not corpus size.

---

## Design Principles

**Digest-check before every pull.** A HEAD request against the registry manifest API returns the current digest without counting as a pull. Compare against the stored digest; only queue a full pull when the digest has changed. At steady state this reduces pull volume from ~700/day to ~70–100/day.

**Pull by digest, not by tag.** Tags are mutable — `postgres:16` can silently move to a new underlying image. Always pull and record by digest (`image@sha256:...`). A tag moving to a new digest is itself a detectable event.

**Scanners and vulnerability DBs are baked into the VM image.** Scanner binaries and DB snapshots are embedded at image build time via Packer. Workers do not download scanner DBs at runtime. DB freshness is maintained by rebuilding the VM image nightly via Cloud Build.

**Work is queue-driven, not baked into the VM.** VMs pull tasks from Cloud Tasks at runtime. This decouples corpus management from execution, allows retry on failure, and enables dynamic scaling based on actual queue depth.

**VMs self-terminate after draining their work.** No long-running fleet. Each VM processes up to 100 images then deletes itself. Cost is proportional to actual work done.

---

## Registry Constraints

| Registry | Pull Limit | Auth | Notes |
|---|---|---|---|
| Docker Hub (`registry-1.docker.io`) | 100/6h unauthenticated per IP | Paid Team ($15/mo) required at corpus scale | Behind Cloudflare ASN-level detection; ephemeral IPs detectable. One paid authenticated account is the only correct approach. Each arch counts as a separate pull — pin to `linux/amd64`. |
| GHCR (`ghcr.io`) | No documented limit; ~44k req/min burst | Read-only PAT recommended | Free for public image egress; 30-day notice promised before any change. |
| NVIDIA NGC (`nvcr.io`) | Undocumented, IP-based | NGC account + API key required | CUDA/PyTorch images are 4–15 GB each. Digest-check gate is non-negotiable; scan on change only, not daily. |
| `registry.k8s.io` | No documented limit | No | CNCF project images may be spread across registries; resolve source at corpus-build time. |
| Quay.io (`quay.io`) | Undocumented throttle on heavy automation | No for public images | Source registry must be stored in corpus metadata per image. |

---

## Component Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Cloud Scheduler (nightly, 02:00 UTC)                   │
└─────────────────────┬───────────────────────────────────┘
                      │ triggers
┌─────────────────────▼───────────────────────────────────┐
│  Cloud Run Job: digest-checker                          │
│  - reads corpus from database                           │
│  - HEAD /v2/{image}/manifests/{tag} per image           │
│  - compares digest against stored value                 │
│  - enqueues changed images → Cloud Tasks                │
│  - updates corpus last_checked timestamp                │
└─────────────────────┬───────────────────────────────────┘
                      │ enqueues tasks
┌─────────────────────▼───────────────────────────────────┐
│  Cloud Tasks: scan-queue                                │
│  - one task per (image_ref, digest, scanners[])         │
│  - 3600s lease duration                                 │
│  - 3 retries with exponential backoff (30s–600s)        │
└─────────────────────┬───────────────────────────────────┘
                      │ triggers (queue depth > 0)
┌─────────────────────▼───────────────────────────────────┐
│  Cloud Function: vm-spawner                             │
│  - reads queue depth                                    │
│  - spawns ceil(depth / 100) GCE VMs                     │
│  - uses instance template (Packer-built custom image)   │
│  - passes queue, bucket, zone via instance metadata     │
└─────────────────────┬───────────────────────────────────┘
                      │ creates
┌─────────────────────▼───────────────────────────────────┐
│  GCE VM Fleet (ephemeral, e2-standard-2, preemptible)  │
│  - authenticates to registries via Secret Manager       │
│  - pulls tasks from Cloud Tasks (one at a time)         │
│  - docker pull image@digest                             │
│  - trivy scan → JSON                                    │
│  - grype scan → JSON                                    │
│  - upload results → GCS                                 │
│  - docker rmi (free disk after each image)              │
│  - self-terminate when queue empty or 100 pulls done    │
└─────────────────────┬───────────────────────────────────┘
                      │ writes raw results
┌─────────────────────▼───────────────────────────────────┐
│  GCS: vectr-scan-results/                               │
│  - trivy/{image_slug}/{digest}.json                     │
│  - grype/{image_slug}/{digest}.json                     │
│  - raw scanner JSON retained 90 days then deleted       │
└─────────────────────┬───────────────────────────────────┘
                      │ triggers (object finalize)
┌─────────────────────▼───────────────────────────────────┐
│  Cloud Function: result-ingestor                        │
│  - normalizes Trivy + Grype JSON into unified schema    │
│  - writes ScanRecord rows to database                   │
│  - computes delta against previous scan                 │
│  - writes ScanDelta rows to database                    │
│  - triggers alert delivery if delta is non-empty        │
└─────────────────────────────────────────────────────────┘
```

---

## Data Model

Five tables. The `findings` table dominates storage and must be partitioned by month.

| Table | Description | Growth rate |
|---|---|---|
| `images` | One row per unique image tag in corpus | Static (~1,450 rows) |
| `image_digests` | One row per unique digest observed; immutable; stores GCS SBOM path | ~10,000/year |
| `scan_runs` | One row per scanner per digest per day; summary counts only | ~1M rows/year |
| `findings` | One row per CVE per scan run; the bulk of all data | ~159M rows/year |
| `scan_deltas` | Pre-computed deltas between consecutive scans; includes compact JSONB delta payloads for alert delivery | ~1M rows/year |

**Sizing at steady state (1,450-image corpus, 2 scanners, 150 findings/image average):**

| Horizon | findings rows | Total DB size |
|---|---|---|
| End of year 1 | ~159M | ~36 GB |
| End of year 2 | ~318M | ~70 GB |
| End of year 3 (2-year retention) | steady state | ~100 GB |

Partitioning `findings` by month (on `scanned_at`) allows dropping old partitions without table rewrites.

---

## SBOM Architecture (Recommended Evolution)

The pipeline splits into two permanently separated phases, eliminating daily image pulls entirely after the initial seed.

**Phase A — SBOM generation** (triggered only on digest change)
```
digest changed → pull image → syft generate SBOM → store in GCS → delete image
```

**Phase B — Daily vulnerability scan** (no network, no pull, pure CPU)
```
daily cron → download SBOM from GCS → grype sbom:file.json → store findings in DB
```

Phase B runs completely offline. No registry contact, no rate limits, no egress cost, no Docker credentials needed. The only input is the SBOM file and the local vulnerability DB.

### SBOM Size

SBOM size is a function of package count, not image size. A 15 GB NVCR CUDA image and a 50 MB Alpine image with similar package counts produce SBOMs of similar size.

| Image type | Packages | SBOM size (CycloneDX JSON) | Gzipped |
|---|---|---|---|
| Alpine minimal | ~20 | ~30 KB | ~8 KB |
| Debian slim | ~100 | ~200 KB | ~45 KB |
| Ubuntu full | ~400 | ~700 KB | ~150 KB |
| Node.js app image | ~600 | ~1.1 MB | ~220 KB |
| NVCR CUDA base | ~800 | ~1.5 MB | ~300 KB |
| NVCR PyTorch full | ~1,200+ | ~2.5 MB | ~500 KB |

Corpus-weighted average: ~600 KB uncompressed, ~130 KB gzipped per SBOM. GCS storage is negligible (~$0.09/month after year one at 4.4 GB gzipped).

### Scan Compute (Phase B)

Grype scanning an SBOM is pure CPU — no I/O, no network. On a 2-vCPU Cloud Run Job:

- ~3 seconds per SBOM
- 1,450 images × 3s = ~72 minutes total per daily run
- One Cloud Run Job handles the full corpus serially; no fleet needed

### SBOM Accuracy Caveat

Syft generates the SBOM from the image at a point in time. If a CVE is later found in a package that Syft didn't catalog (statically linked binaries, embedded language runtimes without package manifests), the SBOM will miss it. Direct image scanning catches some of these through deeper heuristics.

For vectr's use case — tracking known CVE database changes against a fixed package inventory — this is acceptable. New CVEs against known packages are caught correctly. When a digest changes and a new SBOM is generated, a newer Syft version may catalog packages the previous version missed; scanner version upgrades propagate naturally through the corpus.

---

## Infrastructure

| Component | Technology | Notes |
|---|---|---|
| Nightly trigger | Cloud Scheduler | 02:00 UTC daily |
| Digest checker | Cloud Run Job | Stateless; reads corpus, emits tasks |
| Scan queue | Cloud Tasks | 3600s lease, 3 retries, 10 dispatches/s max |
| VM spawner | Cloud Function | Spawns `ceil(depth/100)` VMs |
| Scan workers | GCE `e2-standard-2` preemptible | Custom Packer image; self-terminate |
| VM image build | Packer + Cloud Build | Rebuilt nightly; scanners and DBs baked in |
| Raw results storage | GCS | 90-day TTL on raw JSON; SBOM storage permanent |
| Normalized data | Cloud SQL PostgreSQL | See sizing above |
| Registry credentials | Secret Manager | Per-registry secrets; accessed by workers at runtime |
| IaC | Terraform | All resources managed; instance template references Packer image family |

**VM fleet IAM**: Scanner service account holds `cloudtasks.enqueuer`, `storage.objectCreator`, `secretmanager.secretAccessor`, and `compute.instanceAdmin.v1` (for self-termination). In production, scope `compute.instanceAdmin.v1` to a specific instance name prefix to limit blast radius.

---

## Cost Model

### Original Architecture (daily pull + scan)

| Item | Monthly |
|---|---|
| Docker Hub Team subscription | $15 |
| GCE preemptible VMs (~30 VM-hours/month) | ~$0.51 |
| GCS storage, 90-day TTL | ~$1.00 |
| Internet egress (3,000 pulls × 500 MB avg = 1.5 TB) | ~$120 |
| Cloud Tasks, Cloud Run Job, Cloud Scheduler | <$1 |
| **Total** | **~$137/month** |

Seed phase (all ~1,450 images pulled once): ~$300–400 additional egress. NVCR images should be seeded separately on a weekly digest-check cadence rather than daily.

### SBOM Architecture

| Item | Monthly |
|---|---|
| Docker Hub Team subscription (Phase A pulls only) | $15 |
| GCE preemptible, Phase A (seed ~10 hr; steady ~2 hr/month) | ~$2 |
| GCS SBOM storage | ~$0.50 |
| Cloud Run Job, Phase B daily scan (72 min/day × 2 vCPU) | ~$6 |
| Cloud SQL `db-custom-1-3840` + 50 GB SSD | ~$65 |
| Vulnerability DB downloads (15 GB/month inbound) | $0 |
| Cloud Scheduler + Cloud Tasks | <$1 |
| **Total** | **~$90/month** |

The SBOM architecture saves ~$47/month versus daily pulls, primarily from eliminated egress. The gap grows with corpus size — at 5,000 images the pull-every-day model becomes untenable; the SBOM model scales linearly on compute only.

### Database Hosting

| Option | Tier | Cost/month | Notes |
|---|---|---|---|
| Cloud SQL | `db-custom-1-3840` (1 vCPU, 3.75 GB, 50 GB SSD) | ~$65 | Recommended through month 6; storage autoscales |
| Cloud SQL | `db-custom-2-7680` (2 vCPU, 7.5 GB, 150 GB SSD) | ~$145 | Upgrade path for year 1–2 as findings table grows |
| Neon (serverless Postgres) | Pro (50 GB) | $19 | Good for early stage; scales to zero; schema branching useful for migrations; cold start matters for latency-sensitive paths |

---

## Operational Notes

**Scanner version pinning.** Bake specific versions into the Packer image. Do not use `latest`. The Trivy CI compromise in February 2026 (PAT theft via aqua-bot) demonstrates that scanner supply chains are a real attack surface. Pin, verify checksums, and rebuild the VM image intentionally on upgrades.

**Trivy DB freshness.** Pre-warmed DBs age. Rebuild the VM image nightly via Cloud Build so workers always start with a DB less than 24 hours old. Workers use `--skip-db-update` to prevent runtime downloads.

**Disk pressure.** GPU images from NVCR can be 10–15 GB. The `docker rmi` after each scan is mandatory. `e2-standard-2` with 100 GB pd-ssd gives headroom for ~6 large images simultaneously. For bulk NVCR scanning, consider `e2-standard-4` with 200 GB disk.

**Preemption handling.** Preemptible VMs can be reclaimed with 30s notice. Cloud Tasks leases are 3600s. On preemption, the lease expires and the task is requeued automatically — no additional preemption handling is required in the worker.

**Multi-arch.** Each architecture counts as a separate pull on Docker Hub. Pin to `linux/amd64` unless architecture comparison is a product feature.
