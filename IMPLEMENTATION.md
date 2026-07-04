# DevRadar — Implementation Reference

> High-level design: see [README.md](README.md)

## Overview

DevRadar tracks how the vulnerabilities in a container image change over time by rescanning its SBOM daily. It never pulls images. A tenant submits an SBOM (pinned to an image digest) through an authenticated API; a daily Cloud Run Job rescans every active SBOM with Grype and Trivy, normalizes the results into a scanner-agnostic schema, and records every change as an append-only event.

The system is four components, all Cloud Run, no VMs, no queue, no registry access:

1. **Ingest API** — Cloud Run *service*. Accepts, validates, content-addresses, and stores SBOMs.
2. **Daily Scan Job** — Cloud Run *job*. Rescans active SBOMs, writes current state + change events.
3. **Alerting** — triggered by new critical/high `added` events; notifies the submitting tenant.
4. **Store** — Cloud SQL PostgreSQL.

The scanner design (a `Scanner` interface to run the tool, a `Converter` interface to normalize its JSON, both behind a registry) is adapted from [vimp](https://github.com/mchmarny/vimp). DevRadar changes the scanner *input* from an image reference to an SBOM file and adds the time-series event model.

---

## Design Principles

**Scan a frozen inventory.** The SBOM is immutable once submitted. Because the package inventory never changes, the only variable across daily scans is the scanner's vulnerability database. This makes every change unambiguous: a new finding on an unchanged SBOM is DB-driven; a new finding requires a new SBOM (new digest) to be image-driven.

**Store change, not snapshots.** Day-over-day findings on a fixed SBOM are ~99% identical. DevRadar keeps *current state* (`findings`, UPSERT) plus an append-only *change log* (`finding_events`). The change log is the delta history — there is no nightly diff job and no snapshot table.

**Trust on submission, but record provenance.** DevRadar cannot verify that an SBOM faithfully represents its claimed digest without pulling the image. It doesn't try. Every SBOM carries a `verification_status` (`unverified` in v1) so signed-attestation verification can be added later without migration.

**Normalize across scanners.** No single scanner's output shape defines the data. Both Grype and Trivy run from day one, normalized into one `Vulnerability` type. New scanners register as converters.

**Pin everything.** Scanner binaries and their DB versions are pinned in `.versions.yaml`, baked into the job image, and recorded per scan run. Reproducibility is the product; the pinned version is a first-class, auditable fact.

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

- **Version integrity.** As pinned binaries, each scanner's version is an artifact in `.versions.yaml` and is recorded per `scan_run.db_version`. As libraries, scanner versions become entries in DevRadar's own `go.mod`, entangled with its dependency graph — directly threatening the "same version → same findings" guarantee.
- **Two scanners, one process = dependency conflict.** Grype and Trivy share overlapping, incompatible transitive dependencies (both build on `github.com/anchore/...`). Vendored into one binary they fight; as separate binaries in one container image they are hermetically isolated.
- **Fault isolation on untrusted input.** DevRadar parses attacker-controllable SBOMs. A malformed SBOM that panics or OOMs an in-process scanner would take down the whole batch. A subprocess crash is one recorded failure; the run continues.
- **Trivy's library API is explicitly unstable.** It is documented as internal and churns across minor versions, while pulling a large unwanted dependency tree (cloud SDKs, misconfig/secret scanners).
- **Cost is negligible.** SBOM scanning is a ~1–3s CPU batch operation; subprocess spawn overhead is single-digit milliseconds. There is no latency budget to protect.

**The `Scanner` interface is the seam that keeps in-process cheap to add later.** The one backend with real upside is Grype-in-process — its library API is clean and it could load the vuln DB once and reuse it across all SBOMs in a run (a throughput win at scale). If that becomes worthwhile, a `grypeLibScanner` satisfying the same interface drops in with **zero change** to normalization, storage, or the event model.

```go
// internal/scanner/scanner.go
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
// internal/scanner/grype.go
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
// internal/scanner/trivy.go
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
// internal/scanner/exec.go
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
// internal/converter/converter.go
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
// internal/sbom/subject.go
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
// internal/server/ingest.go
func (s *Server) handleSubmitSBOM(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenant := TenantFromContext(ctx) // set by auth middleware (assumed auth)

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

Cloud SQL PostgreSQL. Tenant isolation via Row-Level Security (matching the DevPulse/DevTrace pattern). `finding_events` is partitioned monthly from day one.

```sql
-- Tenants own SBOMs and receive alerts. Auth is assumed upstream; this is the
-- identity SBOMs and events hang off of.
CREATE TABLE tenants (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    alert_email TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One row per unique submitted SBOM. Content-addressed (id = sha256 of bytes),
-- digest-pinned, immutable. Bytes live in GCS; this is the index over them.
CREATE TABLE sboms (
    id                  TEXT PRIMARY KEY,              -- sha256 of raw bytes
    tenant_id           UUID NOT NULL REFERENCES tenants(id),
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
CREATE INDEX idx_sboms_tenant_active ON sboms(tenant_id) WHERE status = 'active';
CREATE INDEX idx_sboms_image_ref ON sboms(tenant_id, image_ref);

-- One row per SBOM per scanner per run. Proof-of-scan + DB-version attribution.
CREATE TABLE scan_runs (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sbom_id      TEXT NOT NULL REFERENCES sboms(id),
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
CREATE TABLE findings (
    sbom_id     TEXT NOT NULL REFERENCES sboms(id),
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
CREATE INDEX idx_findings_exposure ON findings(exposure);
CREATE INDEX idx_findings_severity ON findings(severity);

-- APPEND-ONLY change log. The delta history and the alert source.
-- A row exists ONLY when a finding changed. Partitioned monthly, retained forever.
CREATE TABLE finding_events (
    id           BIGINT GENERATED ALWAYS AS IDENTITY,
    tenant_id    UUID NOT NULL,                        -- denormalized for RLS + fast tenant queries
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
CREATE TABLE finding_events_2026_07 PARTITION OF finding_events
    FOR VALUES FROM ('2026-07-01') TO ('2026-08-01');
CREATE INDEX idx_fe_tenant_time ON finding_events(tenant_id, occurred_at DESC);
CREATE INDEX idx_fe_alerting ON finding_events(tenant_id, event_type, severity, occurred_at DESC);

-- Failure surface: per-SBOM/per-scanner errors, not swallowed. Drives ops alerting.
CREATE TABLE scan_failures (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    sbom_id     TEXT NOT NULL,
    scanner     TEXT,
    stage       TEXT NOT NULL,                         -- download|scan|parse|detect|convert|persist
    error       TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### Why the event log instead of the original `findings`-per-day table

The original design appended every finding on every scan — ~159M rows/year, of which ~99% are byte-identical to the prior day because a fixed SBOM's inventory doesn't change. The event model stores *current state* (bounded) plus *changes* (a handful of rows on a normal day). Same query power for "what did this image look like on date X" (replay events up to X, or read `scan_runs` + reconstruct), far less storage, and alerts are a trivial `SELECT` over `finding_events` instead of a nightly diff job.

### Retention & roll-up (forward-looking, additive)

`finding_events` is retained **forever** in v1. Because it is partitioned monthly by `occurred_at`, later policies are additive and require no migration:

- **Per-plan caps** — a retention job drops or archives partitions older than the tenant's plan allows.
- **Roll-ups** — a derived `finding_event_rollups` table (per `image_ref` × month × severity: counts, net delta) materialized from the event log gives long-range trend views while detailed CVE-level events are kept only for the last N days. The raw log stays the source of truth.

---

## Alerting

Triggered by the scan job (or a short poll over recent events). When an `added` event of severity `critical` or `high` lands for a tenant, notify that tenant (the submitter is always known — they own the SBOM).

```sql
-- New actionable events since the last alert watermark for a tenant.
SELECT exposure, package, severity, score, image_ref, e.occurred_at
FROM finding_events e
JOIN sboms s ON s.id = e.sbom_id
WHERE e.tenant_id = $1
  AND e.event_type = 'added'
  AND e.severity IN ('critical','high')
  AND e.occurred_at > $2            -- last alert watermark
ORDER BY e.occurred_at;
```

Alert routing needs no registry knowledge, no external identity resolution — the SBOM carries the tenant, the tenant carries the destination. This is a direct benefit of the submit-time ownership model.

---

## Deployment

All GCP, in the `thingzio` project. No VMs, no Cloud Tasks, no Secret Manager entries for registry credentials (there are none).

| Component | Technology | Notes |
|---|---|---|
| Ingest API | Cloud Run service | Scales to zero; authenticated (assumed upstream) |
| Daily scan | Cloud Run Job | ~2 vCPU; scanners + pinned DBs baked into the image |
| Job image | `ko` build (no Dockerfile) | Reproducible; scanner binaries + DB snapshot layered in |
| Scheduling | Cloud Scheduler | Triggers the scan job ~02:00 UTC |
| SBOM bytes | GCS | Content-addressed objects; lifecycle optional |
| Store | Cloud SQL PostgreSQL | `db-custom-1-3840` + 50 GB SSD to start |
| Secrets | Secret Manager | DB credentials + API-signing keys only |

**Scanner/DB versioning.** `.versions.yaml` is the single source of truth for pinned Grype/Trivy versions and their DB snapshot identifiers — the same file governs local dev and CI, so a scan reproduces identically anywhere. The job image is rebuilt (nightly) to refresh the baked DBs; `db_version` recorded on every `scan_run` ties each finding to the exact DB that produced it.

```yaml
# .versions.yaml  (single source of truth; consumed by build + CI)
scanners:
  grype: "0.85.0"
  trivy: "0.58.1"
tools:
  ko: "0.17.1"
  golangci-lint: "1.63.4"
```

---

## Component Layout (target)

```
cmd/
  ingest-api/      main.go        # Cloud Run service
  scan-job/        main.go        # Cloud Run Job (daily)
internal/
  server/                          # HTTP handlers, auth middleware, untrusted-input guards
  sbom/                            # format detect + subject/digest extraction
  scanner/                         # Scanner interface, exec backends (grype, trivy), registry
  converter/                       # Converter interface + grype/trivy normalizers (from vimp)
  store/                           # Postgres access: UpsertSBOM, ApplyScan, event/alert queries
  parser/                          # gabs helpers (from vimp)
pkg/
  data/            vuln.go         # normalized Vulnerability (from vimp)
sql/
  ddl.sql                          # idempotent schema
.versions.yaml                     # pinned scanner + tool versions
```

The `scanner` and `converter` packages are the reuse surface from vimp; `sbom`, `store` (event model), and `server` (ingest + untrusted input) are DevRadar-specific.
