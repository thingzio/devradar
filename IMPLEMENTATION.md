# DevRadar — Implementation Reference

> High-level design: see [README.md](README.md)

## Overview

DevRadar tracks how the vulnerabilities in a container image change over time by rescanning its SBOM daily. It never pulls images. A tenant submits an SBOM (pinned to an image digest) through an authenticated API; a daily Cloud Run Job rescans every active SBOM with Grype and Trivy, normalizes the results into a scanner-agnostic schema, and records every change as an append-only event.

DevRadar is the third service on the shared Thingz platform and follows the conventions of its siblings DevPulse and DevTrace — same `pkg/` layout, `database/sql`+`lib/pq` store, embedded advisory-lock migrations, `ko`/GoReleaser build, and the shared `thingzio-pg` Postgres instance. Where the siblings diverge, DevRadar's choices and their rationale are in [Platform Alignment](#platform-alignment). The specifics of plugging into shared infra are in [Shared-Infrastructure Contract](#shared-infrastructure-contract).

The system's runtime pieces, all Cloud Run, no VMs, no queue, no registry access:

1. **Ingest API + minimal UI** — Cloud Run *service* (`devradar-saas-serve`). Accepts, validates, content-addresses, and stores SBOMs (API-token auth); serves a small GitHub-OAuth UI for minting/revoking API tokens (session auth).
2. **Daily Scan Job** — Cloud Run *job* (`devradar-saas-scan`). Rescans active SBOMs, writes current state + change events.
3. **Alerting** — triggered by new critical/high `added` events; emails the submitting tenant, optionally with a Claude-generated narrative.
4. **Store** — shared Cloud SQL PostgreSQL (`thingz` database, `devradar_`-prefixed tables).

The scanner design (a `Scanner` interface to run the tool, a `Converter` interface to normalize its JSON, both behind a registry) is adapted from [vimp](https://github.com/mchmarny/vimp). DevRadar changes the scanner *input* from an image reference to an SBOM file and adds the time-series event model.

---

## Design Principles

**Scan a frozen inventory.** The SBOM is immutable once submitted. Because the package inventory never changes, the only variable across daily scans is the scanner's vulnerability database. This makes every change unambiguous: a new finding on an unchanged SBOM is DB-driven; a new finding requires a new SBOM (new digest) to be image-driven.

**Store change, not snapshots.** Day-over-day findings on a fixed SBOM are ~99% identical. DevRadar keeps *current state* (`devradar_finding`, UPSERT) plus an append-only *change log* (`devradar_finding_event`). The change log is the delta history — there is no nightly diff job and no snapshot table.

**Trust on submission, but record provenance.** DevRadar cannot verify that an SBOM faithfully represents its claimed digest without pulling the image. It doesn't try. Every SBOM carries a `verification_status` (`unverified` in v1) so signed-attestation verification can be added later without migration.

**Normalize across scanners.** No single scanner's output shape defines the data. Both Grype and Trivy run from day one, normalized into one `Vulnerability` type. New scanners register as converters.

**Pin everything.** Scanner and tool versions are pinned in `.settings.yaml` (the platform-wide single source of truth, consumed by Make + CI), baked into the job image, and recorded per scan run. Reproducibility is the product; the pinned version is a first-class, auditable fact.

---

## SBOM Scanning Accuracy

The concern that scanning an SBOM is less accurate than scanning the image directly is real but far narrower than usually stated, provided the SBOM is generated over **all layers**. The residual gap is a generator-quality question DevRadar can manage, not a structural penalty.

Split scanning into two independent steps:

- **Matching** (package list → CVEs): **identical** for SBOM and image. The scanner runs the same matcher over the same packages against the same DB regardless of input. This is where DevRadar's daily value lives, and it has zero accuracy difference.
- **Cataloging** (image → package list): the *only* place a gap can appear, and it is a property of the SBOM generator, not of the SBOM-vs-image distinction.

So accuracy reduces to a single question: does the SBOM's catalog equal what the scanner would have cataloged itself?

| Situation | Gap vs. direct image scan |
|---|---|
| All-layers SBOM from the scanner's own cataloger family (Syft SBOM → Grype) | **None** — Grype uses Syft as its cataloger, so this is bit-for-bit the same operation |
| All-layers SBOM, cross-tool (Syft SBOM → Trivy matcher) | **Small, bidirectional** — Trivy's native analyzers differ from Syft's by a few percent; each catches things the other misses |
| Static binaries (Go/Rust/C), vendored deps without a manifest | **Real but shared** — the identifying metadata isn't present; direct image scanning is only marginally better. Deep binary classifiers (Syft's) catch *some*, and if enabled at generation the SBOM inherits them |
| Newer cataloger would find more, digest unchanged | **DevRadar-specific staleness** — affects cataloging only, not matching; resolves when a new digest yields a fresh SBOM |

**The staleness point is specific to the frozen-SBOM model and worth stating plainly:** DevRadar scans against the cataloger version that generated the SBOM. If a future Syft adds, say, better Rust binary detection, DevRadar won't pick up newly-catalogable packages until a **new digest** triggers a fresh SBOM. But this affects *cataloging* only — new CVEs against already-cataloged packages (the vast majority of daily change) are matched perfectly against the fresh DB every day. This is the same tradeoff that makes change causality clean: cataloging frozen per digest, matching live daily.

**Design consequences (implemented):**

1. **Recommend Syft-generated CycloneDX, all layers.** Document that faithfulness is highest when the SBOM comes from the scanner's own cataloger family with deep binary classification on. Grype-on-Syft is the zero-gap path.
2. **Run Trivy as a deliberate cross-check.** Divergence between Grype and Trivy on the same SBOM surfaces cataloger disagreement — signal, not noise. The `finding_events`/`findings` model already keys by scanner, so per-scanner differences are first-class.
3. **Record generator provenance at ingest.** `sboms.tool` / `sboms.tool_version` (from CycloneDX `metadata.tools` or SPDX `creationInfo.creators`) make the cataloging boundary auditable — "this finding set reflects Syft 1.x cataloging" — and let a future check flag SBOMs from generators known to under-catalog. Best-effort: captured when present, never required.

---

## Scanner Execution Model

**v1 shells out to scanner binaries; it does not import them as libraries.** Both Grype (`github.com/anchore/grype`) and Trivy (`github.com/aquasecurity/trivy`) are Go and *can* be called in-process, but for DevRadar the subprocess model is correct:

- **Version integrity.** As pinned binaries, each scanner's version is an artifact in `.settings.yaml` and is recorded per `devradar_scan_run.db_version`. As libraries, scanner versions become entries in DevRadar's own `go.mod`, entangled with its dependency graph — directly threatening the "same version → same findings" guarantee.
- **Two scanners, one process = dependency conflict.** Grype and Trivy share overlapping, incompatible transitive dependencies (both build on `github.com/anchore/...`). Vendored into one binary they fight; as separate binaries in one container image they are hermetically isolated.
- **Fault isolation on untrusted input.** DevRadar parses attacker-controllable SBOMs. A malformed SBOM that panics or OOMs an in-process scanner would take down the whole batch. A subprocess crash is one recorded failure; the run continues.
- **Trivy's library API is explicitly unstable.** It is documented as internal and churns across minor versions, while pulling a large unwanted dependency tree (cloud SDKs, misconfig/secret scanners).
- **Cost is negligible.** SBOM scanning is a ~1–3s CPU batch operation; subprocess spawn overhead is single-digit milliseconds. There is no latency budget to protect.

**The `Scanner` interface is the seam that keeps in-process cheap to add later.** The one backend with real upside is Grype-in-process — its library API is clean and it could load the vuln DB once and reuse it across all SBOMs in a run (a throughput win at scale). If that becomes worthwhile, a `grypeLibScanner` satisfying the same interface drops in with **zero change** to normalization, storage, or the event model.

```go
// pkg/scanner/scanner.go
package scanner

import "context"

// Scanner runs a vulnerability scanner against an SBOM file and returns the
// path to its raw JSON output. Implementations may shell out to a binary
// (execScanner) or, in the future, call a scanner library in-process — callers
// depend only on this interface.
type Scanner interface {
	// Name is the scanner identifier, e.g. "grype", "trivy".
	Name() string

	// IsAvailable reports whether the scanner can run in this environment.
	IsAvailable() bool

	// ScanSBOM scans the SBOM at sbomPath and writes raw JSON to outPath.
	ScanSBOM(ctx context.Context, sbomPath, outPath string) error

	// ConverterName is the converter used to normalize this scanner's output.
	ConverterName() string
}

// Registry holds the registered scanners.
type Registry struct{ scanners []Scanner }

func NewRegistry() *Registry { return &Registry{} }

func (r *Registry) Register(s Scanner) { r.scanners = append(r.scanners, s) }

func (r *Registry) Available() []Scanner {
	out := make([]Scanner, 0, len(r.scanners))
	for _, s := range r.scanners {
		if s.IsAvailable() {
			out = append(out, s)
		}
	}
	return out
}

// DefaultRegistry returns the v1 scanner set: Grype + Trivy, both exec-based.
func DefaultRegistry() *Registry {
	r := NewRegistry()
	r.Register(NewGrypeScanner())
	r.Register(NewTrivyScanner())
	return r
}
```

The exec backend is a thin wrapper; the only DevRadar-specific detail is the SBOM input syntax each scanner expects (`grype sbom:<file>`, `trivy sbom <file>`).

```go
// pkg/scanner/grype.go
package scanner

import (
	"context"
	"os/exec"
)

type grypeScanner struct{}

func NewGrypeScanner() Scanner { return &grypeScanner{} }

func (g *grypeScanner) Name() string          { return "grype" }
func (g *grypeScanner) ConverterName() string { return "grype" }
func (g *grypeScanner) IsAvailable() bool     { return isInstalled("grype") }

func (g *grypeScanner) ScanSBOM(ctx context.Context, sbomPath, outPath string) error {
	// grype reads an SBOM via the "sbom:" scheme; no network, no image pull.
	// DB updates are disabled — the pinned DB is baked into the job image.
	cmd := exec.CommandContext(ctx, "grype",
		"sbom:"+sbomPath,
		"-q",
		"-o", "json",
		"--file", outPath,
	)
	cmd.Env = append(cmd.Environ(), "GRYPE_DB_AUTO_UPDATE=false")
	return runCmd(ctx, cmd, outPath)
}
```

```go
// pkg/scanner/trivy.go
package scanner

import (
	"context"
	"os/exec"
)

type trivyScanner struct{}

func NewTrivyScanner() Scanner { return &trivyScanner{} }

func (t *trivyScanner) Name() string          { return "trivy" }
func (t *trivyScanner) ConverterName() string { return "trivy" }
func (t *trivyScanner) IsAvailable() bool     { return isInstalled("trivy") }

func (t *trivyScanner) ScanSBOM(ctx context.Context, sbomPath, outPath string) error {
	// trivy scans an SBOM directly. --skip-db-update: the pinned DB is baked in.
	cmd := exec.CommandContext(ctx, "trivy", "sbom",
		"--quiet",
		"--scanners", "vuln",
		"--format", "json",
		"--skip-db-update",
		"--output", outPath,
		sbomPath,
	)
	return runCmd(ctx, cmd, outPath)
}
```

`runCmd` (adapted from vimp) runs the command under the context, kills the process on cancellation, and validates that the output file exists and contains parseable JSON before returning success — so a scanner that dies on a malformed SBOM surfaces as a clean per-SBOM error rather than corrupt data.

```go
// pkg/scanner/exec.go
package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"

	"github.com/pkg/errors"
)

func isInstalled(bin string) bool {
	_, err := exec.LookPath(bin)
	return err == nil
}

func runCmd(ctx context.Context, cmd *exec.Cmd, outPath string) error {
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb

	if err := cmd.Start(); err != nil {
		return errors.Wrapf(err, "start: %s", cmd.String())
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case <-ctx.Done():
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		return ctx.Err()
	case err := <-done:
		info, statErr := os.Stat(outPath)
		if statErr != nil || info.Size() < 2 {
			return errors.Wrapf(err, "no/empty output: %s (stderr: %s)", cmd.String(), errb.String())
		}
		return validateJSON(outPath)
	}
}

func validateJSON(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var raw json.RawMessage
	return json.NewDecoder(f).Decode(&raw)
}
```

---

## Normalized Data Model (from vimp)

DevRadar normalizes every scanner into one deliberately minimal, scanner-agnostic type. This is vimp's `data.Vulnerability`, kept as the lowest common denominator so no scanner's idiosyncrasies leak into the schema.

```go
// pkg/data/vuln.go
package data

import (
	"crypto/sha256"
	"fmt"
)

// Vulnerability is a normalized finding, scanner-agnostic.
type Vulnerability struct {
	Exposure string  `json:"exposure"` // vulnerability ID, e.g. CVE-2024-1234
	Package  string  `json:"package"`
	Version  string  `json:"version"`
	Severity string  `json:"severity"` // lowercase: critical|high|medium|low|negligible|unknown
	Score    float32 `json:"score"`    // CVSS base score, source-precedence resolved
	IsFixed  bool    `json:"fixed"`
}

// GetID is the natural identity of a finding within a scan: (exposure, package, version).
// It is the dedup key and the join key for delta computation.
func (v *Vulnerability) GetID() string {
	s := fmt.Sprintf("%s/%s/%s", v.Exposure, v.Package, v.Version)
	return fmt.Sprintf("%x", sha256.Sum256([]byte(s)))
}
```

### Converters

The `Converter` interface and its registry are adopted from vimp verbatim (auto-detection via `CanHandle`, lookup by name). Both converters parse with `gabs` rather than typed structs, which is what lets the score logic walk a **source-precedence list** instead of hardcoding one CVSS provider — the fix for the common "Trivy reports vendor CVSS, not NVD, so score is silently 0" bug.

```go
// pkg/converter/converter.go
package converter

import (
	"context"

	"github.com/Jeffail/gabs/v2"
	"github.com/mchmarny/devradar/pkg/data"
)

type Converter interface {
	Name() string
	CanHandle(c *gabs.Container) bool
	Convert(ctx context.Context, c *gabs.Container) ([]*data.Vulnerability, error)
}
```

Grype and Trivy converters carry over directly from vimp (`internal/converter/grype`, `internal/converter/trivy`). Key detail preserved from vimp's Trivy converter — resolve CVSS across sources in priority order, taking V3 over V2:

```go
// getScore walks CVSS sources in precedence order (e.g. "nvd", "redhat"),
// preferring V3 over V2. Prevents silently storing 0.0 when the preferred
// source is absent.
func getScore(cvss *gabs.Container, sources ...string) float32 {
	for _, s := range sources {
		c := cvss.Search(s)
		if !c.Exists() {
			continue
		}
		if v3 := c.Search("V3Score"); v3.Exists() {
			return parser.ToFloat32(v3.Data())
		}
		if v2 := c.Search("V2Score"); v2.Exists() {
			return parser.ToFloat32(v2.Data())
		}
	}
	return 0
}
```

---

## Ingest API (Cloud Run service)

Accepts an authenticated SBOM submission, treats the body as untrusted, extracts the subject digest, content-addresses the bytes, and stores. Idempotent by construction: the same SBOM bytes produce the same `sha256`, so resubmission dedupes.

### Endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/v1/sboms` | Submit an SBOM. Returns the SBOM id (content hash) and its resolved image ref + digest. |
| `GET`  | `/v1/images` | List the tenant's tracked images (latest state per digest). |
| `GET`  | `/v1/images/{ref}/timeline` | Event history for an image ref across digests. |
| `GET`  | `/v1/sboms/{id}/findings` | Current findings for one SBOM. |
| `GET`  | `/v1/sboms/{id}/events` | Change events for one SBOM. |

### Untrusted-input handling

The SBOM is attacker-controllable. The handler enforces, before any parsing:

- **Size cap** on the request body (e.g. 20 MB) via `http.MaxBytesReader`.
- **Decompression cap** if the body is gzipped — bounded reader on the decompressed stream to prevent decompression bombs.
- **Format + schema validation** — must be recognizable CycloneDX or SPDX at a supported version (latest minus 1–2 minor); reject otherwise.
- **Subject resolution** — the image ref + digest must be extractable (below); reject if not. DevRadar refuses to store an SBOM it can't pin to a digest.

### Subject digest extraction

The image ref and digest live in different places across formats and generators; this is the fiddliest part of ingest and gets its own normalization step.

- **CycloneDX** — `metadata.component` of type `container`; digest from its `hashes` (SHA-256) or a `purl`/property carrying `@sha256:...`.
- **SPDX** — the root `DESCRIBES` package; digest from `checksums` (SHA256) or `externalRefs` (PURL).

If no digest can be resolved, ingest fails closed — an SBOM without a pinned subject can't participate in digest-boundary delta causality, which is the whole point.

```go
// pkg/sbom/subject.go
package sbom

// Subject is the image an SBOM describes, plus the generator that produced it.
type Subject struct {
	ImageRef string // e.g. registry.example.com/team/api:1.4.2  (may be private)
	Digest   string // sha256:...
	Format   string // cyclonedx | spdx
	SpecVer  string // e.g. 1.6
	Tool     string // generator name from metadata (e.g. "syft"); bounds cataloging freshness
	ToolVer  string // generator version
}

// Resolve extracts the subject from raw SBOM bytes, trying CycloneDX then SPDX.
// Returns an error if no image digest can be determined. Generator tool/version
// are best-effort (CycloneDX metadata.tools, SPDX creationInfo.creators) —
// recorded for auditability of the cataloging boundary, never required.
func Resolve(raw []byte) (*Subject, error) { /* format detect → digest + generator extract */ }
```

### Handler sketch

```go
// pkg/server/ingest.go
func (s *Server) handleSubmitSBOM(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenant := TenantFromContext(ctx) // set by RequireAPIToken middleware (Bearer dr_... token)

	r.Body = http.MaxBytesReader(w, r.Body, maxSBOMBytes)
	raw, err := readMaybeGzip(r.Body, maxSBOMBytes)
	if err != nil {
		http.Error(w, "sbom too large or unreadable", http.StatusRequestEntityTooLarge)
		return
	}

	subj, err := sbom.Resolve(raw)
	if err != nil {
		http.Error(w, "cannot resolve image digest from sbom", http.StatusUnprocessableEntity)
		return
	}

	id := fmt.Sprintf("%x", sha256.Sum256(raw)) // content address

	if err := s.gcs.PutIfAbsent(ctx, sbomObjectPath(tenant.ID, id), raw); err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}

	// Idempotent: ON CONFLICT (id) DO NOTHING. Resubmission is a no-op.
	if err := s.store.UpsertSBOM(ctx, &store.SBOM{
		ID: id, TenantID: tenant.ID,
		ImageRef: subj.ImageRef, Digest: subj.Digest,
		Format: subj.Format, SpecVersion: subj.SpecVer,
		Tool: subj.Tool, ToolVersion: subj.ToolVer, // cataloging-freshness provenance
		VerificationStatus: "unverified",
		Status:             "active",
	}); err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]string{
		"sbom_id": id, "image_ref": subj.ImageRef, "digest": subj.Digest,
	})
}
```

---

## Daily Scan Job (Cloud Run Job)

Runs once daily. For each active SBOM, runs every available scanner, normalizes, and writes current state + change events in one transaction per (sbom, scanner). Pure CPU — the only external I/O is reading the SBOM from GCS and writing to Postgres.

```go
// cmd/scan-job/main.go  (sketch)
func run(ctx context.Context, st *store.Store, gcs *gcsClient) error {
	scanners := scanner.DefaultRegistry().Available()
	convs := converter.DefaultRegistry()

	sboms, err := st.ListActiveSBOMs(ctx) // streamed / paged in practice
	if err != nil {
		return err
	}

	for _, sb := range sboms {
		local, err := gcs.Download(ctx, sb.ObjectPath) // to a temp file
		if err != nil {
			st.RecordScanFailure(ctx, sb.ID, "", "download", err) // failure surface, not swallowed
			continue
		}

		for _, sc := range scanners {
			outPath := tempOut(sb.ID, sc.Name())
			if err := sc.ScanSBOM(ctx, local, outPath); err != nil {
				st.RecordScanFailure(ctx, sb.ID, sc.Name(), "scan", err)
				continue
			}
			c, err := gabs.ParseJSONFile(outPath)
			if err != nil {
				st.RecordScanFailure(ctx, sb.ID, sc.Name(), "parse", err)
				continue
			}
			conv, err := convs.Detect(c)
			if err != nil {
				st.RecordScanFailure(ctx, sb.ID, sc.Name(), "detect", err)
				continue
			}
			vulns, err := conv.Convert(ctx, c)
			if err != nil {
				st.RecordScanFailure(ctx, sb.ID, sc.Name(), "convert", err)
				continue
			}

			// One transaction: summary row + current-state upsert + change events.
			if err := st.ApplyScan(ctx, sb, sc.Name(), scannerDBVersion(sc), vulns); err != nil {
				st.RecordScanFailure(ctx, sb.ID, sc.Name(), "persist", err)
			}
		}
	}
	return nil
}
```

### `ApplyScan` — the delta engine

This is where current state and the event log are written. The logic, per `(sbom, scanner)`:

1. Load the previous current-state set for this `(sbom_id, scanner)`.
2. Compute the incoming set from `vulns`, keyed by `GetID()`.
3. **Added** — in incoming, not in previous → insert into `findings`, append `finding_events(type='added')`.
4. **Resolved** — in previous, not in incoming → delete from `findings`, append `finding_events(type='resolved')`.
5. **Changed** — in both but severity/score/fixed differs → update `findings`, append `finding_events(type='rerated' | 'fixed')`.
6. **Unchanged** — in both, identical → **no write**. This is the common case and the reason the event log stays small.
7. Always insert one `scan_runs` summary row (counts + `db_version`), so every scan is provable even on a zero-event day.

Because the incoming set is derived from a frozen SBOM, an `added` event on an unchanged digest is definitionally DB-driven; the event stores the `db_version` that produced it, making the cause auditable.

Idempotency: the whole method is safe to re-run (Cloud Run Job retries). Re-running the same (sbom, scanner, db_version) recomputes the identical incoming set → produces zero new events. Current-state writes are UPSERTs; event inserts are guarded by a natural key (below).

---

## PostgreSQL Schema

DevRadar shares one Postgres database (`thingz` on `thingzio-pg`) with DevPulse and DevTrace. Isolation follows the platform contract: **every table is prefixed `devradar_`**, and DevRadar connects as its own DB user (`devradar`). See [Shared-Infrastructure Contract](#shared-infrastructure-contract) for the instance-level detail.

**Tenant isolation is application-level** (`WHERE tenant_id = $1` on every tenant-scoped query), mirroring DevTrace — *not* DevPulse's Row-Level Security. This is a deliberate choice: DevRadar's scan job is inherently **cross-tenant** (it iterates every active SBOM), so a per-request `app.tenant_id` GUC would fight the batch writer. App-level scoping works naturally with a pooled connection and a job that reads across all tenants, at the cost of relying on every *read* query carrying the predicate — see [Tenant Isolation](#tenant-isolation) for the reasoning and the guardrails. `devradar_finding_event` is partitioned monthly from day one.

```sql
-- ── Identity & auth (shapes mirror devtrace_tenant / _session / _api_token) ────

-- A tenant is a GitHub identity. Owns SBOMs, API tokens, and alert routing.
CREATE TABLE devradar_tenant (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    github_id     BIGINT NOT NULL UNIQUE,
    username      TEXT NOT NULL,
    email         TEXT,                                -- alert destination
    avatar_url    TEXT,
    plan          TEXT NOT NULL DEFAULT 'free',
    status        TEXT NOT NULL DEFAULT 'active',      -- active | suspended
    tos_accepted_at TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_devradar_tenant_username ON devradar_tenant(username);

-- Browser sessions (minted by the UI after GitHub OAuth). id = SHA-256(token).
CREATE TABLE devradar_session (
    id          TEXT PRIMARY KEY,                      -- hex SHA-256 of the opaque cookie token
    tenant_id   UUID NOT NULL REFERENCES devradar_tenant(id) ON DELETE CASCADE,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_devradar_session_tenant ON devradar_session(tenant_id);

-- API tokens (minted in the UI, used by CI to submit SBOMs). Only the hash is stored.
CREATE TABLE devradar_api_token (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES devradar_tenant(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,                       -- human label, e.g. "ci-prod"
    token_hash    TEXT NOT NULL UNIQUE,                -- hex SHA-256 of the "dr_..." token
    last_used_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_devradar_api_token_tenant ON devradar_api_token(tenant_id);

-- ── Core domain ───────────────────────────────────────────────────────────────

-- One row per unique submitted SBOM. Content-addressed (id = sha256 of bytes),
-- digest-pinned, immutable. Bytes live in GCS; this is the index over them.
CREATE TABLE devradar_sbom (
    id                  TEXT PRIMARY KEY,              -- sha256 of raw bytes
    tenant_id           UUID NOT NULL REFERENCES devradar_tenant(id) ON DELETE CASCADE,
    image_ref           TEXT NOT NULL,                 -- may be a private registry
    digest              TEXT NOT NULL,                 -- sha256:...
    format              TEXT NOT NULL,                 -- cyclonedx | spdx
    spec_version        TEXT NOT NULL,
    tool                TEXT,                          -- generator, e.g. "syft" (from SBOM metadata)
    tool_version        TEXT,                          -- generator version — bounds the cataloging freshness
    object_path         TEXT NOT NULL,                 -- gs://.../{tenant}/{id}
    verification_status TEXT NOT NULL DEFAULT 'unverified', -- unverified | attested
    status              TEXT NOT NULL DEFAULT 'active',     -- active | archived
    submitted_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, digest, format)
);
CREATE INDEX idx_devradar_sbom_active ON devradar_sbom(status) WHERE status = 'active';
CREATE INDEX idx_devradar_sbom_image_ref ON devradar_sbom(tenant_id, image_ref);

-- One row per SBOM per scanner per run. Proof-of-scan + DB-version attribution.
CREATE TABLE devradar_scan_run (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sbom_id      TEXT NOT NULL REFERENCES devradar_sbom(id) ON DELETE CASCADE,
    scanner      TEXT NOT NULL,                        -- grype | trivy
    db_version   TEXT NOT NULL,                        -- pinned scanner DB version
    scanned_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    finding_count  INT NOT NULL,
    critical_count INT NOT NULL,
    high_count     INT NOT NULL,
    medium_count   INT NOT NULL,
    low_count      INT NOT NULL,
    UNIQUE (sbom_id, scanner, db_version, scanned_at)
);

-- CURRENT state: one row per unique finding per (sbom, scanner). UPSERT target.
-- Bounded — it only ever holds the latest known findings, never history.
CREATE TABLE devradar_finding (
    sbom_id     TEXT NOT NULL REFERENCES devradar_sbom(id) ON DELETE CASCADE,
    scanner     TEXT NOT NULL,
    finding_id  TEXT NOT NULL,                         -- data.Vulnerability.GetID()
    exposure    TEXT NOT NULL,                         -- CVE-...
    package     TEXT NOT NULL,
    version     TEXT NOT NULL,
    severity    TEXT NOT NULL,
    score       REAL NOT NULL,
    is_fixed    BOOLEAN NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (sbom_id, scanner, finding_id)
);
CREATE INDEX idx_devradar_finding_exposure ON devradar_finding(exposure);
CREATE INDEX idx_devradar_finding_severity ON devradar_finding(severity);

-- APPEND-ONLY change log. The delta history and the alert source.
-- A row exists ONLY when a finding changed. Partitioned monthly, retained forever.
CREATE TABLE devradar_finding_event (
    id           BIGINT GENERATED ALWAYS AS IDENTITY,
    tenant_id    UUID NOT NULL,                        -- denormalized for fast per-tenant queries + alerting
    sbom_id      TEXT NOT NULL,
    scanner      TEXT NOT NULL,
    finding_id   TEXT NOT NULL,
    event_type   TEXT NOT NULL,                        -- added | resolved | rerated | fixed
    exposure     TEXT NOT NULL,
    package      TEXT NOT NULL,
    version      TEXT NOT NULL,
    severity     TEXT NOT NULL,                        -- severity at event time
    score        REAL NOT NULL,
    prev_severity TEXT,                                -- for rerated
    prev_score    REAL,
    db_version   TEXT NOT NULL,                        -- scanner DB that produced the change
    scan_run_id  UUID NOT NULL,
    occurred_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Idempotency: a given change is recorded once per DB version.
    UNIQUE (sbom_id, scanner, finding_id, event_type, db_version, occurred_at)
) PARTITION BY RANGE (occurred_at);

-- Monthly partitions (create ahead via pg_partman or a scheduled job).
CREATE TABLE devradar_finding_event_2026_07 PARTITION OF devradar_finding_event
    FOR VALUES FROM ('2026-07-01') TO ('2026-08-01');
CREATE INDEX idx_devradar_fe_tenant_time ON devradar_finding_event(tenant_id, occurred_at DESC);
CREATE INDEX idx_devradar_fe_alerting ON devradar_finding_event(tenant_id, event_type, severity, occurred_at DESC);

-- Failure surface: per-SBOM/per-scanner errors, not swallowed. Drives ops alerting.
CREATE TABLE devradar_scan_failure (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    sbom_id     TEXT NOT NULL,
    scanner     TEXT,
    stage       TEXT NOT NULL,                         -- download|scan|parse|detect|convert|persist
    error       TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

Note the DDL is written **idempotent** (`CREATE TABLE IF NOT EXISTS` / `CREATE INDEX IF NOT EXISTS` in the real files, elided here for readability) and applied by the embedded advisory-lock migration runner described in [Platform Alignment](#platform-alignment) — the same pattern both siblings use.

### Why the event log instead of the original `findings`-per-day table

The original design appended every finding on every scan — ~159M rows/year, of which ~99% are byte-identical to the prior day because a fixed SBOM's inventory doesn't change. The event model stores *current state* (bounded) plus *changes* (a handful of rows on a normal day). Same query power for "what did this image look like on date X" (replay events up to X, or read `devradar_scan_run` + reconstruct), far less storage, and alerts are a trivial `SELECT` over `devradar_finding_event` instead of a nightly diff job.

### Retention & roll-up (forward-looking, additive)

`devradar_finding_event` is retained **forever** in v1. Because it is partitioned monthly by `occurred_at`, later policies are additive and require no migration:

- **Per-plan caps** — a retention job drops or archives partitions older than the tenant's plan allows.
- **Roll-ups** — a derived `devradar_finding_event_rollup` table (per `image_ref` × month × severity: counts, net delta) materialized from the event log gives long-range trend views while detailed CVE-level events are kept only for the last N days. The raw log stays the source of truth.

---

## Alerting

Triggered by the scan job (or a short poll over recent events). When an `added` event of severity `critical` or `high` lands for a tenant, notify that tenant (the submitter is always known — they own the SBOM).

```sql
-- New actionable events since the last alert watermark for a tenant.
SELECT e.exposure, e.package, e.severity, e.score, s.image_ref, e.occurred_at
FROM devradar_finding_event e
JOIN devradar_sbom s ON s.id = e.sbom_id
WHERE e.tenant_id = $1
  AND e.event_type = 'added'
  AND e.severity IN ('critical','high')
  AND e.occurred_at > $2            -- last alert watermark
ORDER BY e.occurred_at;
```

Alert routing needs no registry knowledge, no external identity resolution — the SBOM carries the tenant, the tenant carries the destination (`devradar_tenant.email`). This is a direct benefit of the submit-time ownership model.

**Delta narratives (Claude).** Raw events are precise but terse. DevRadar mirrors the sibling pattern of using Claude to turn a day's change set into a one-line human summary — e.g. *"Criticals rose by 3: new CVEs in openssl and glibc from a vulnerability-DB update; the image did not change."* This runs in the scan/alert path with the **Haiku** model (high-volume, cheap — same split the siblings use: Haiku for batch, Sonnet for interactive). The Anthropic client is nil-safe: if `ANTHROPIC_API_KEY` is unset the alert still fires with the raw event list, so narrative generation is strictly additive and never a hard dependency. See [Platform Alignment → Claude](#claude-optional-delta-narratives).

---

## OpenVEX Stubbing (opt-in, AI-assisted)

A separate, **opt-in** endpoint that drafts an [OpenVEX](https://github.com/openvex/spec) document for an image's findings. It is deliberately *not* part of the scan or alert path — the deterministic pipeline stays deterministic, and a tenant explicitly asks for this AI-assisted artifact.

### What DevRadar can and cannot do here

DevRadar already holds, per finding, the raw material of a VEX statement: the subject image digest (the VEX `product`), the CVE (`vulnerability`), the affected `package`/`version` (a PURL subcomponent), and whether a fix exists (`is_fixed`). That is the *mechanical skeleton*.

What DevRadar **cannot** derive from an SBOM is **exploitability** — whether a present CVE actually affects the product. OpenVEX's four statuses are `not_affected`, `affected`, `fixed`, `under_investigation`; deciding `not_affected` requires knowing how the code is *used* (is the vulnerable function reachable? in the execution path? mitigated by a control?). That is human/tooling knowledge outside DevRadar's inputs.

**So the contract is: DevRadar stubs, the human decides.** Every generated statement defaults to `under_investigation`. Claude drafts a starting `impact_statement` and proposes a candidate OpenVEX `justification` enum (e.g. `vulnerable_code_not_in_execute_path`, `component_not_present`) *as a suggestion to edit*, never as an assertion. DevRadar **never emits `not_affected` by default** — auto-asserting non-impact is exactly the dangerous case.

> **Overclaiming discipline (same as the trust model).** An AI-drafted VEX that a user rubber-stamps unreviewed is *worse* than no VEX — it launders a guess into an assertion downstream consumers may trust. The draft nature must be unmissable: default `under_investigation` status, explicit `"generated_by": "devradar+claude"` provenance with model and timestamp, and a required-review notice in the response. VEX authenticity is the tenant's, not DevRadar's.

### Shape

- **Endpoint:** `POST /v1/sboms/{id}/vex` (opt-in; API-token auth). Optional body selects a subset of findings (e.g. only CRITICAL/HIGH) and the target format (OpenVEX JSON).
- **Model:** **Sonnet**, not Haiku — this is interactive, quality-sensitive drafting where the narrative matters (the siblings' "Sonnet for interactive" split). Unlike delta narratives, Claude is **required** for this feature: with no API key the endpoint returns `501 Not Implemented`, because the stub *is* the AI output.
- **Generation:** DevRadar assembles the deterministic skeleton from `devradar_finding` (product digest, per-CVE package/version/fix), then asks Claude to fill `impact_statement` + candidate `justification` per statement. The document is emitted as spec-compliant OpenVEX with all statements `under_investigation`.
- **Ownership:** the stub is a **draft artifact the tenant owns**, not DevRadar-derived truth. Persist it with its provenance (stored in a `devradar_vex_draft` table: `id`, `tenant_id`, `sbom_id`, `document JSONB`, `model`, `generated_at`) so the tenant can download, edit, expand, and round-trip a completed VEX back. DevRadar does not treat a draft as authoritative about the tenant's product.

### Why this is a good fit, not scope creep

VEX answers the question DevRadar's findings *provoke* — "it's present, but does it affect me?" — which nothing else in the pipeline addresses. The mechanical half is already in the data model; only the exploitability narrative needs AI, and that half is honestly bounded as human-owned. It reuses the same nil-safe Anthropic client, adds one endpoint and one table, and touches neither the scan path nor the event model.

---

## Deployment

All GCP, in the shared `thingzio` project (`us-west1`). No VMs, no Cloud Tasks, no registry credentials.

| Component | Technology | Notes |
|---|---|---|
| Ingest API + minimal UI | Cloud Run service `devradar-saas-serve` | Scales to zero; serves the JSON API and the OAuth/token-minting UI |
| Daily scan | Cloud Run Job `devradar-saas-scan` | ~2 vCPU; scanners + pinned DBs baked into the image; triggered by Cloud Scheduler |
| Images | `ko` via GoReleaser (no Dockerfile) | Pushed to Artifact Registry `us-west1-docker.pkg.dev/thingzio/devradar-saas-images/<name>` |
| Scheduling | Cloud Scheduler | Triggers the scan job ~02:00 UTC |
| SBOM bytes | GCS bucket `devradar-saas-sboms` (DevRadar-owned) | Content-addressed objects; the shared infra's DB-backup bucket is not for app data |
| Store | Shared Cloud SQL `thingzio-pg`, database `thingz`, user `devradar` | `db-custom-1-3840` — DevRadar does **not** provision the instance |
| Secrets | Secret Manager | `devradar-saas-database-url`, `devradar-saas-oauth-client-secret`, `devradar-saas-anthropic-api-key` |

This is the **two-deployable-unit** shape (DevPulse's model: a service + a scheduled Job), chosen over DevTrace's single-binary-with-background-goroutines because DevRadar's daily scan is a long batch over *all* tenants — a Cloud Run Job is independently retriable and scaled, and lets the API service scale to zero between requests.

**Scanner/DB versioning.** Two version concerns, two files:

- **`.settings.yaml`** — the platform single-source-of-truth (Go version, `ko`/`goreleaser`/`golangci-lint`/`tfsec` versions, coverage threshold), consumed by the Makefile and CI via `yq`, identical to both siblings.
- **Pinned scanner versions** live alongside it and are baked into the scan-job image; `db_version` recorded on every `devradar_scan_run` ties each finding to the exact DB that produced it. The job image is rebuilt (nightly) to refresh the baked scanner DBs so each run starts <24h stale.

---

## Platform Alignment

DevRadar is the third service on the shared Thingz platform and follows the conventions established by DevPulse and DevTrace. Where the two siblings diverge, DevRadar's choice and its reason are called out.

### Layout & entrypoints

- **`pkg/`-only, no `internal/`** (both siblings). Everything importable lives under `pkg/`.
- **Two thin `cmd/` entrypoints**, each a ~30-line `main` that sets up the logger, installs `signal.NotifyContext` for SIGINT/SIGTERM, and calls a package `Run(ctx, Options{Version, Commit, Date})`; version/commit/date are `-ldflags`-injected `main` vars.
  - `cmd/devradar-serve` → `server.Run` (Ingest API + UI).
  - `cmd/devradar-scan` → `scan.Run` (daily job).

### Config

Environment variables only — **no config file, no flags** (both siblings). A `pkg/config/env.go` exposes typed accessor *functions* (`GetEnv`, `GetEnvAsInt`, `GetEnvBool`, `GetEnvAsDuration`, …) with defaults baked in and each documenting its env override. Service-scoped tunables are prefixed `DEVRADAR_`; infra vars are unprefixed (`DATABASE_URL`, `PORT`, `BASE_URL`, `ANTHROPIC_API_KEY`). `GCPProjectID()` defaults to `thingzio`.

### Database access

- **`database/sql` + `github.com/lib/pq`** (blank-imported `postgres` driver), **not pgx** — both siblings. A `Store` wraps `*sql.DB`; a `PoolConfig` sets `application_name=devradar-*`, max-open/idle, and lifetimes; `NewFromEnv` reads `DATABASE_URL`.
- **Embedded numbered SQL migrations** with a **home-grown advisory-lock runner** (no external migration lib): `//go:embed sql/migrations/*.sql`, files `NNN_name.sql`, version parsed from the numeric prefix, applied on a single pinned connection under `pg_advisory_lock(<const>)` (pick a DevRadar-specific lock int, e.g. the ASCII of `"devradar"` truncated to bigint), tracked in `devradar_schema_version(version PK, applied_at)` with `INSERT ... ON CONFLICT DO NOTHING`. `001` is a squashed idempotent schema; migrations run at startup before serving. This serializes concurrent boots from scale-to-zero.
- Raw SQL as `const` strings with positional `$N` params; hand-written row scanners; `COALESCE(col,'')` for nullable text.

### HTTP server

- **stdlib `net/http.ServeMux`** with Go 1.22+ method patterns (`"POST /v1/sboms"`, `"GET /v1/images/{ref}/timeline"`); path params via `r.PathValue`. No third-party router.
- Outer middleware `recoverPanics(securityHeaders(mux))`; per-route composition by functional wrapping. Hardened `http.Server` timeouts (Read 30s / ReadHeader 5s / Write 60s / Idle 120s / MaxHeaderBytes 64KB), listens `0.0.0.0:8080` (`PORT` override), graceful shutdown on ctx cancel.
- **`GET /health` → 200** as the Cloud Run startup probe (migrations run before `ListenAndServe`, so readiness == listening). No separate readiness endpoint.
- JSON APIs return a `{"error": "..."}` envelope; the UI uses `html/template` with `//go:embed templates/*.html` + `static/*`.

### Auth & tenancy

DevRadar carries **both** sibling auth models because it needs both surfaces:

- **API tokens** (DevTrace's pattern) for the primary path — CI submitting SBOMs. Raw token `"dr_" + hex(32 random bytes)`, shown once; only the hex **SHA-256 hash** is stored (`devradar_api_token.token_hash`). `RequireAPIToken(db)` middleware reads `Authorization: Bearer`, 401 JSON on failure.
- **GitHub OAuth → session cookie** for the minimal UI, where a human logs in to mint/revoke API tokens. Opaque 32-byte token, SHA-256-hashed as `devradar_session.id`, 7-day TTL; cookie is `__Host-session` on HTTPS else `session`, `HttpOnly`/`Secure`/`SameSite=Lax`. `RequireAuth(db, loginURL)` middleware; state-changing UI POSTs use double-submit-cookie CSRF.
- `RequireAdmin(db)` gates admin ops on a `DEVRADAR_ADMIN_USERS` allowlist and returns **404** (not 403) to hide route existence.
- Tenant is injected into `context` under a private key; `TenantFromContext(ctx)` retrieves it. Suspended tenants → 403 (API) / redirect (UI).

### Tenant Isolation

**Application-level `tenant_id` scoping, no RLS** — mirroring DevTrace, diverging from DevPulse. Every tenant-scoped *read* threads `WHERE tenant_id = $1`; ownership-checked mutations use `WHERE id = $1 AND tenant_id = $2`.

*Why not DevPulse's RLS:* RLS keys off a per-connection `app.tenant_id` GUC set by a dedicated-connection middleware. DevRadar's **scan job is inherently cross-tenant** — it iterates every active SBOM across all tenants in one batch — so the GUC model would force the writer onto the "bypass when no tenant" policy anyway, buying complexity without protecting the path that matters. App-level scoping composes cleanly with a pooled connection and the batch writer.

*Guardrails* (since there's no DB backstop): the `Store` is the only place raw SQL lives; every tenant-scoped query method takes `tenantID` as its first argument (not optional); and integration tests assert cross-tenant reads return empty. If a compliance requirement later demands defense-in-depth, RLS can be layered onto the tenant-facing read tables (`devradar_finding_event`, `devradar_finding`, `devradar_sbom`) without disturbing the scan job — noted as a reversible upgrade.

### Build, deploy, CI

- **`ko` via GoReleaser**, no Dockerfile (both siblings). `CGO_ENABLED=0`, `-trimpath`, `-s -w -X main.version/commit/date`; images pushed to `us-west1-docker.pkg.dev/thingzio/devradar-saas-images/<name>`, `linux/amd64`.
- **Makefile** self-documenting targets: `tidy` (fmt + mod tidy + vendor), `lint` (go/yaml/tf), `test` (`-race -covermode=atomic`), `test-coverage` (threshold from `.settings.yaml`), `integration` (testcontainers Postgres), `vulncheck`, `qualify`, `db-up`/`db-down`, `tf-*`, `bump-*`.
- **CI** (`.github/workflows/`): reusable test-on-push, release-on-tag (GoReleaser + deploy), deploy via **Workload Identity Federation** (`gcloud run services update` / `jobs update`). Composite actions load tool versions from `.settings.yaml` via `yq`. Vendored deps (`-mod=vendor`).

### Observability

- **`log/slog`** JSON handler to **stderr**, every line tagged with `version` and a `source` (`"serve"`/`"scan"`) via `slog.With`; level Debug when `DEVRADAR_DEBUG` set. Structured key/value throughout; Cloud Run captures stdout/stderr.
- **No app-level OpenTelemetry/Prometheus** (neither sibling instruments) — rely on Cloud Run/Cloud Monitoring and Terraform-defined log-based metrics + alert policies. The shared infra already alerts on DB CPU/connections/disk/etc.

### Claude (optional delta narratives)

A hand-rolled Anthropic **Messages API** client via plain `net/http` (no SDK), mirroring both siblings: headers `x-api-key` + `anthropic-version: 2023-06-01`, 30s timeout, response capped with `io.LimitReader`, retry on 429/529. **Nil-safe**: `New()` returns `nil` when the API key is unset and callers guard `if client != nil`, so Claude is never a hard dependency. Model resolves from `DEVRADAR_ANTHROPIC_MODEL` / `ANTHROPIC_MODEL`, default **Haiku** (`claude-haiku-4-5-20251001`) for the high-volume scan/alert path. Key delivered via Secret Manager `devradar-saas-anthropic-api-key`.

---

## Shared-Infrastructure Contract

DevRadar plugs into `thingzio/infra` exactly as the siblings do — it **references** shared resources and **creates only its own**. There is no shared Terraform module; each service copies the `infra/saas/` skeleton and references shared infra via input variables with hardcoded `thingzio` defaults (not `terraform_remote_state`).

**Shared (referenced, never created by DevRadar):**

| Resource | Identifier |
|---|---|
| GCP project | `thingzio` |
| Region | `us-west1` |
| VPC / subnet | `projects/thingzio/global/networks/thingzio-vpc` / `.../subnetworks/thingzio-subnet` |
| Cloud SQL instance | `thingzio-pg` (Postgres 16), connection `thingzio:us-west1:thingzio-pg` |
| Shared database | `thingz` |
| Terraform state | bucket `thingzio-infra-state`, DevRadar prefix `devradar` |

**Created by DevRadar's own `infra/saas/`:**

1. `database.tf` — `data "google_sql_database_instance" "shared"` (reference) + `google_sql_user "app"` named **`devradar`** with a `random_password`. DevRadar does *not* create a database; it uses the shared `thingz` DB with `devradar_`-prefixed tables.
2. `secrets.tf` — `devradar-saas-database-url` assembled as a Cloud SQL **unix-socket** DSN: `host=/cloudsql/thingzio:us-west1:thingzio-pg dbname=thingz user=devradar password=... sslmode=disable`; plus `devradar-saas-oauth-client-secret`, `devradar-saas-anthropic-api-key`. Each granted to the run SA via `secretmanager.secretAccessor`.
3. `iam.tf` — run SA `devradar-saas-run` (roles `cloudsql.client`, `cloudsql.instanceUser`, `artifactregistry.reader`, `logging.logWriter`, `monitoring.metricWriter`, plus `storage.objectAdmin` on its SBOM bucket); deployer SA `github-actions-devradar-saas`; WIF pool/provider bound to `assertion.repository == 'thingzio/devradar'`.
4. `cloudrun.tf` — the `devradar-saas-serve` **service** and `devradar-saas-scan` **job**, both mounting the Cloud SQL socket (`volumes { cloud_sql_instance { instances = ["thingzio:us-west1:thingzio-pg"] } }` at `/cloudsql`), VPC egress `PRIVATE_RANGES_ONLY` onto `thingzio-subnet`, `DATABASE_URL` from the secret.
5. `storage.tf` — GCS bucket `devradar-saas-sboms` for SBOM bytes (the shared `thingzio-db-backups` bucket is DB-only).
6. `artifact-registry.tf` — `devradar-saas-images` Docker repo. `scheduler.tf` — Cloud Scheduler trigger for the scan job. `providers.tf` — GCS backend `prefix = "devradar"`.

> Do not replicate DevTrace's committed-plaintext-secrets `terraform.tfvars` — use untracked tfvars or Secret Manager-sourced values.

---

## Component Layout (target)

```
cmd/
  devradar-serve/  main.go        # Cloud Run service: Ingest API + minimal UI
  devradar-scan/   main.go        # Cloud Run Job (daily scan)
pkg/
  config/          env.go         # env-var accessor funcs (DEVRADAR_ prefix)
  server/                          # HTTP handlers, router, auth middleware, untrusted-input guards, templates/static
  middleware/                      # RequireAPIToken, RequireAuth, RequireAdmin, CSRF, recovery, securityHeaders
  tenant/                          # tenant, session, api-token models (mirror devtrace/pkg/tenant)
  sbom/                            # format detect + subject/digest/generator extraction
  scanner/                         # Scanner interface, exec backends (grype, trivy), registry
  converter/                       # Converter interface + grype/trivy normalizers (from vimp)
  parser/                          # gabs helpers (from vimp)
  claude/          client.go       # nil-safe Anthropic Messages client (delta narratives)
  data/
    vuln.go                        # normalized Vulnerability (from vimp)
    postgres/                      # Store, PoolConfig, advisory-lock migrate, per-domain query files
      sql/migrations/*.sql         # NNN_name.sql; 001 squashed idempotent schema (devradar_ tables)
  logging/         cli.go          # slog JSON to stderr, version/source tagged
  health/
infra/saas/                        # Terraform: references shared thingzio-pg + VPC, creates DevRadar resources
.settings.yaml                     # platform SoT: Go + tool versions, coverage threshold (yq-consumed)
.goreleaser.yaml  Makefile         # ko build + self-documenting targets
```

Reuse surface from **vimp**: `scanner`, `converter`, `parser`, `data/vuln.go`. Reuse surface from **devtrace/devpulse**: `config`, `data/postgres` (Store + migrate runner), `tenant`, `middleware`, `server` scaffolding, `logging`, `claude`, Makefile/CI/Terraform skeleton. DevRadar-specific: `sbom` (subject extraction), the event-model store queries, and the SBOM-scanning scan job.
