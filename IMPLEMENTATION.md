# DevRadar — Implementation Reference

> High-level design: see [README.md](README.md)

## Overview

DevRadar tracks how the vulnerabilities in a container image change over time by rescanning its SBOM daily. It never pulls images. A tenant submits an SBOM (pinned to an image digest) through an authenticated API; a daily Cloud Run Job rescans every active SBOM with Grype and Trivy, normalizes the results into a scanner-agnostic schema, and records every change as an append-only event.

DevRadar is the third service on the shared Thingz platform and follows the conventions of its siblings DevPulse and DevTrace — same `pkg/` layout, `database/sql`+`lib/pq` store, embedded advisory-lock migrations, `ko`/GoReleaser build, and the shared `thingzio-pg` Postgres instance. Where the siblings diverge, DevRadar's choices and their rationale are in [Platform Alignment](#platform-alignment). The specifics of plugging into shared infra are in [Shared-Infrastructure Contract](#shared-infrastructure-contract).

The system's runtime pieces, all Cloud Run, no VMs, no queue, no registry access:

1. **Ingest API + minimal UI** — Cloud Run *service* (`devradar-saas-serve`). Accepts, validates, content-addresses, and stores SBOMs (API-token auth); serves a small GitHub-OAuth UI for minting/revoking API tokens (session auth).
2. **Daily Scan Job** — Cloud Run *job* (`devradar-saas-scan`). Rescans active SBOMs, writes current state + change events.
3. **Read API + UI** — tenants pull their current findings and change history (`/v1/images`, `/v1/sboms/{id}/findings`, `/v1/sboms/{id}/events`). v1 is pull-only; push alerting is post-MVP.
4. **Store** — shared Cloud SQL PostgreSQL (`thingz` database, `devradar_`-prefixed tables).

The scanner design (a `Scanner` interface to run the tool, a `Converter` interface to normalize its JSON, both behind a registry) is **informed by the patterns proven in** [vimp](https://github.com/mchmarny/vimp) — but reimplemented natively in this module. **DevRadar takes lessons from vimp, not code: there is no build or module dependency on vimp.** DevRadar changes the scanner *input* from an image reference to an SBOM file and adds the time-series event model.

---

## Design Principles

**Scan a frozen inventory.** The SBOM is immutable once submitted. Because the package inventory never changes, the only variable across daily scans is the scanner's vulnerability database. This makes every change unambiguous: a new finding on an unchanged SBOM is DB-driven; a new finding requires a new SBOM (new digest) to be image-driven.

**Store change, not snapshots.** Day-over-day findings on a fixed SBOM are ~99% identical. DevRadar keeps *current state* (`devradar_finding`, UPSERT) plus an append-only *change log* (`devradar_finding_event`). The change log is the delta history — there is no nightly diff job and no snapshot table.

**Trust on submission, but record provenance.** DevRadar cannot verify that an SBOM faithfully represents its claimed digest without pulling the image. It doesn't try. Every SBOM carries a `verification_status` (`unverified` in v1) so signed-attestation verification can be added later without migration.

**Normalize across scanners.** No single scanner's output shape defines the data. Both Grype and Trivy run from day one, normalized into one `Vulnerability` type. New scanners register as converters.

**Pin the tools, refresh the data, record every version axis.** A finding set is determined by four inputs — the SBOM inventory, the vuln DB, the scanner binary, and the canonicalizer — that change on different clocks. Scanner *binaries* and tool versions are pinned in `.settings.yaml` (the platform-wide single source of truth) and baked into the job image; the vulnerability *database* is refreshed lazily at job start (see [Vulnerability DB freshness](#vulnerability-db-freshness)) rather than baked, then frozen for the run. **All four axes are recorded per scan run.** This is what lets every change be attributed to exactly one cause (image / db / tooling) and every result be reproduced exactly. Reproducibility is the product; the recorded version is a first-class, auditable fact.

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
2. **Run Trivy as a deliberate cross-check.** Divergence between Grype and Trivy on the same SBOM surfaces cataloger disagreement — signal, not noise. The `devradar_finding_event`/`devradar_finding` model already keys by scanner, so per-scanner differences are first-class.
3. **Record generator provenance at ingest.** `devradar_sbom.tool` / `devradar_sbom.tool_version` (from CycloneDX `metadata.tools` or SPDX `creationInfo.creators`) make the cataloging boundary auditable — "this finding set reflects Syft 1.x cataloging" — and let a future check flag SBOMs from generators known to under-catalog. Best-effort: captured when present, never required.

---

## SBOM Ingestion Spike (findings)

Before building, a spike validated the two premises the pipeline rests on, using 12 real SBOMs — `{nginx, redis, prometheus} × {syft, trivy} × {CycloneDX, SPDX}` (retained as `pkg/sbom/testdata` fixtures). Results:

**1. Digest, timestamp, and generator extract reliably from all four format×tool combinations (12/12).** The paths differ per combination (tabulated in [Subject digest extraction](#subject-digest-extraction-spike-validated)) but are deterministic. **Consequence:** submission needs only the SBOM bytes — no required image URI. `pkg/sbom.Resolve` implements this with a fixture table test.

**2. Scanning is NOT format-neutral — and this is the load-bearing finding.** Grype reads everything. But **Trivy returns zero findings on Syft-generated SPDX**:

| Scanner ← SBOM | nginx findings |
|---|---|
| Grype ← Syft CDX / Syft SPDX | 369 / 369 |
| Trivy ← Syft **CDX** | 60 |
| Trivy ← Syft **SPDX** | **0** ← broken |
| Trivy ← Trivy's own SPDX | 374 |

Root cause: Trivy can't find OS/distro metadata in Syft's SPDX (`WARN Unsupported os family="none"`) and drops all OS packages. It is **not** a DevRadar bug and not fixable in our code.

**3. Converting SPDX → CycloneDX fully recovers it.** `syft convert spdx→cyclonedx` preserves the OS metadata (`debian 13`), all 3378 components, and the exact digest — and Trivy then finds the same 60 it finds on native CDX. This is the basis for canonicalizing on ingest-side storage but converting in the scan job (below).

---

## Canonicalize to CycloneDX

Because scanning is not format-neutral, every SBOM is converted to **CycloneDX** before it reaches the scanners, giving even coverage across scanners regardless of the submitted format. Design decisions, all driven by the spike:

- **Accept both formats at the API**; never reject SPDX. SPDX is the more common compliance format — rejecting it would undercut "you give us the SBOM you already generate." Restriction also wouldn't fully solve it (Trivy-native SPDX scans fine), so a blanket ban would over-reject.
- **Convert in the scan job, not at ingest.** Ingest stays thin and only *extracts* (digest/timestamp, proven to work on raw SPDX with no conversion). Conversion — potentially slow, and via a tool Syft flags experimental — runs in the retriable batch, where a failure is a recorded `devradar_scan_failure`, never a rejected submission.
- **Store original bytes + canonical form.** The tenant's original artifact is what's content-addressed and audited (`devradar_sbom.id = sha256(tenant_id + raw)`, per-tenant); the canonical CDX is a derived scanning input.
- **Record the converter version** (`Canonicalizer.Version()`) alongside `db_version` on each scan, for the same reproducibility reason.
- **Backend is a seam, not yet chosen.** `pkg/sbom.Canonicalizer` is an interface. Candidates: shell out to `syft convert` (spike-proven, but experimental) or the CycloneDX/SPDX Go libraries in-process (needs its own fidelity check). A `passthrough` implementation (CycloneDX-only) ships first so the pipeline runs end-to-end on CDX before the SPDX backend lands.

```go
// pkg/sbom/canonicalize.go
type Canonicalizer interface {
	// Canonicalize returns CycloneDX JSON for raw SBOM of the stated format
	// (pass-through when already CycloneDX). Runs in the scan job.
	Canonicalize(ctx context.Context, raw []byte, format Format) (cyclonedx []byte, err error)
	Version() string // converter identity, recorded per scan for reproducibility
}
```

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

	// Version is the scanner binary version (the matcher logic), recorded per
	// scan run so a change in findings can be attributed to a scanner upgrade
	// rather than the image or the vuln DB. Resolved from the binary, e.g.
	// `grype version -o json`.
	Version() string

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
	// Auto-update off: the DB was refreshed once at job start (EnsureDB) and is
	// frozen for the run, so every scan shares one db_version.
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
	// trivy scans an SBOM directly. --skip-db-update: the DB was refreshed once
	// at job start (EnsureDB) and is frozen for the run.
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

`runCmd` (following vimp's approach, reimplemented here) runs the command under the context, kills the process on cancellation, and validates that the output file exists and contains parseable JSON before returning success — so a scanner that dies on a malformed SBOM surfaces as a clean per-SBOM error rather than corrupt data.

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

## Normalized Data Model

DevRadar normalizes every scanner into one deliberately minimal, scanner-agnostic type — the lowest common denominator, so no scanner's idiosyncrasies leak into the schema. The shape follows the lesson from vimp's `data.Vulnerability` (reimplemented here, not imported):

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

The `Converter` interface and its registry follow vimp's structure (auto-detection via `CanHandle`, lookup by name), reimplemented in this module. Both converters parse with `gabs` rather than typed structs, which is what lets the score logic walk a **source-precedence list** instead of hardcoding one CVSS provider — the fix for the common "Trivy reports vendor CVSS, not NVD, so score is silently 0" bug.

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

The Grype and Trivy converters (`pkg/converter/grype`, `pkg/converter/trivy`) reimplement vimp's, preserving one key detail from vimp's Trivy converter — resolve CVSS across sources in priority order, taking V3 over V2:

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

Accepts an authenticated SBOM submission, treats the body as untrusted, extracts the subject digest, content-addresses the bytes **per tenant**, and stores. Idempotent by construction on two levels: the row's natural identity is `(tenant_id, digest, format)` — one SBOM per image digest+format per tenant (an image digest is an immutable inventory) — and the object id is `sha256(tenant_id + bytes)`. Re-submitting the same bytes, or a *different* SBOM for the same digest+format (e.g. by-tag vs by-digest generation, or a newer generator), both resolve to the canonical first row and return `existing: true`; two tenants submitting the same public SBOM get distinct rows. Ingest is deliberately **thin** — it does **not** scan and does **not** convert formats; all heavy/fallible work is deferred to the scan job (see [Ingest vs. scan-job split](#ingest-vs-scan-job-split)).

**Digest resolution.** The digest is extracted from the SBOM (`sbom.Resolve`). SBOMs generated *by tag* often omit the image manifest digest (generators record only the tag and layer digests), so the request may supply an `image_ref` with an `@sha256:` digest as a fallback (`sbom.ResolveWithRef`). Ingest fails closed only when no digest can be found in either place — the README instructs generating SBOMs by digest to avoid needing the override.

### Request contract

The SBOM is self-contained — the spike ([SBOM Ingestion Spike](#sbom-ingestion-spike-findings)) confirmed that digest, generation timestamp, and generator tool/version all extract reliably from CycloneDX **and** SPDX as produced by both Syft and Trivy. So submission requires only the artifact; everything else is an optional override for when the SBOM's self-reporting is weak.

`POST /v1/sboms`, `Authorization: Bearer dr_...`, JSON body:

| Field | Req? | Purpose |
|---|---|---|
| `sbom` | **yes** | Base64-encoded SBOM bytes (CycloneDX or SPDX; gzip allowed within the size cap). |
| `image_ref` | no | Override the image reference. The SBOM's digest is always trusted; this only *labels* it — Syft SPDX reports just `nginx`, Trivy embeds the full registry path, and a tenant may want their canonical name (`registry.internal/team/api:1.4.2`). |
| `format_hint` | no | `cyclonedx`\|`spdx`. Auto-detection is reliable; this is only a fast-fail assist. |
| `generated_at` | no | Override the SBOM's timestamp, for the rare generator that omits it. |
| `labels` | no | Free-form tenant tags (`env=prod`) for the tenant's own filtering. |

Read endpoints (session or token auth):

| Method | Path | Purpose |
|---|---|---|
| `GET`  | `/v1/images` | List the tenant's tracked images (latest state per digest). |
| `GET`  | `/v1/images/{ref}/timeline` | Event history for an image ref across digests. |
| `GET`  | `/v1/sboms/{id}/findings` | Current findings for one SBOM. |
| `GET`  | `/v1/sboms/{id}/events` | Change events for one SBOM. |

### Untrusted-input handling

The SBOM is attacker-controllable. The handler enforces, before any parsing:

- **Size cap** on the request body (e.g. 20 MB) via `http.MaxBytesReader`.
- **Decompression cap** if the body is gzipped — bounded reader on the decompressed stream to prevent decompression bombs.
- **Format detection** — must be recognizable CycloneDX or SPDX; reject otherwise (`ErrUnknownFormat`).
- **Subject resolution** — the digest must be extractable from the SBOM *or* supplied via `image_ref`; fail closed otherwise (`ErrNoDigest`). DevRadar refuses to store an SBOM it can't pin to a digest.

### Subject digest extraction (spike-validated)

The digest, timestamp, and generator live in different places across formats and generators — the fiddliest part of ingest, so it gets its own package (`pkg/sbom`) and a fixture-based table test over 12 real SBOMs. The empirically-confirmed extraction paths:

| Format + tool | Digest path | Timestamp path |
|---|---|---|
| CycloneDX + Syft | `metadata.component.version` | `metadata.timestamp` |
| CycloneDX + Trivy | property `aquasecurity:trivy:RepoDigest` (strip `repo@`) | `metadata.timestamp` |
| SPDX + Syft | package `SPDXID ~ DocumentRoot-Image` → `.versionInfo` | `creationInfo.created` |
| SPDX + Trivy | document `.name` (`repo@digest`) | `creationInfo.created` |

Rather than branch on the generator, `Resolve` tries the known locations for the detected format in priority order and takes the first `sha256:` digest. Generator tool/version come from `metadata.tools` (CycloneDX) / `creationInfo.creators` (SPDX). All of this is best-effort *except* the digest, whose absence is `ErrNoDigest`.

```go
// pkg/sbom/sbom.go
package sbom

// Subject is what an SBOM describes plus the provenance needed to reason about
// its freshness. All fields except Digest are best-effort.
type Subject struct {
	ImageRef    string    // may be weak/absent; caller override wins
	Digest      string    // sha256:...  (required; absence is ErrNoDigest)
	Format      Format    // cyclonedx | spdx
	SpecVersion string    // e.g. "1.7" | "SPDX-2.3"
	Tool        string    // generator, e.g. "syft" | "trivy"
	ToolVersion string    // bounds cataloging freshness
	GeneratedAt time.Time // zero → caller falls back to ingest-receive time
}

// Resolve detects the format and extracts the Subject from raw bytes. It never
// converts; it reads what the document states. (pkg/sbom/extract.go)
func Resolve(raw []byte) (*Subject, error)
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

	// Per-tenant content address: sha256(tenant_id + bytes). A global content
	// hash would collide across tenants submitting the same public SBOM (PK is
	// id), so the second submitter could never see their own row. Scoping by
	// tenant keeps per-tenant idempotency/dedup and preserves isolation.
	id := tenantContentID(tenant.ID, raw)

	if err := s.gcs.PutIfAbsent(ctx, sbomObjectPath(tenant.ID, id), raw); err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}

	// Idempotent on (tenant_id, digest, format): returns the canonical row's id
	// and inserted=false on conflict. Bytes are written only when inserted.
	if err := s.store.UpsertSBOM(ctx, &store.SBOM{
		ID: id, TenantID: tenant.ID,
		ImageRef: subj.ImageRef, Digest: subj.Digest,
		Format: string(subj.Format), SpecVersion: subj.SpecVersion,
		Tool: subj.Tool, ToolVersion: subj.ToolVersion, // cataloging-freshness provenance
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

Runs once daily. For each active SBOM: **canonicalize to CycloneDX**, run every available scanner on the canonical form, normalize, and write current state + change events in one transaction per (sbom, scanner). Pure CPU — the only external I/O is reading the SBOM from GCS and writing to Postgres.

Canonicalization is the fix the spike surfaced ([Canonicalize to CycloneDX](#canonicalize-to-cyclonedx)): scanning is **not** format-neutral, so every SBOM is converted to CycloneDX here — in the job, never at ingest — before it reaches the scanners.

```go
// cmd/devradar-scan/main.go  (sketch)
func run(ctx context.Context, st *store.Store, gcs *gcsClient,
	canon sbom.Canonicalizer, scanners []scanner.Scanner, convs *converter.Registry) error {

	sboms, err := st.ListActiveSBOMs(ctx) // streamed / paged in practice
	if err != nil {
		return err
	}

	for _, sb := range sboms {
		raw, err := gcs.Download(ctx, sb.ObjectPath)
		if err != nil {
			st.RecordScanFailure(ctx, sb.ID, "", "download", err) // failure surface, not swallowed
			continue
		}

		// Canonicalize SPDX → CycloneDX (pass-through if already CDX). A convert
		// failure is a per-SBOM failure, never a lost SBOM.
		cdx, err := canon.Canonicalize(ctx, raw, sbom.Format(sb.Format))
		if err != nil {
			st.RecordScanFailure(ctx, sb.ID, "", "canonicalize", err)
			continue
		}
		local := writeTemp(cdx)

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

			// Tripwire: a scanner returning zero findings on a non-trivial SBOM
			// signals a conversion/compat regression (e.g. the Trivy↔Syft-SPDX
			// gap), not a clean image. Record it; don't write a misleading empty
			// scan that would fire "all resolved" events.
			if len(vulns) == 0 && sb.PackageCount > zeroFindingFloor {
				st.RecordScanFailure(ctx, sb.ID, sc.Name(), "zero-findings", errZeroOnNonEmpty)
				continue
			}

			// One transaction: summary row + current-state upsert + change events.
			// All four version axes travel with the scan so the delta engine can
			// classify each event's cause (image | db | tooling).
			ver := scan.Versions{
				DBVersion:            scannerDBVersion(sc),
				ScannerVersion:       sc.Version(),
				CanonicalizerVersion: canon.Version(),
			}
			if err := st.ApplyScan(ctx, sb, sc.Name(), ver, vulns); err != nil {
				st.RecordScanFailure(ctx, sb.ID, sc.Name(), "persist", err)
			}
		}
	}
	return nil
}
```

### `ApplyScan` — the delta engine

This is where current state and the event log are written. The logic, per `(sbom, scanner)`:

1. Load the previous current-state set for this `(sbom_id, scanner)`, and the previous `scan_run`'s version axes.
2. Compute the incoming set from `vulns`, keyed by `GetID()`.
3. **Classify the cause** for this run's deltas by comparing what changed since the prior run (see below).
4. **Added** — in incoming, not in previous → insert into `devradar_finding`, append `devradar_finding_event(type='added', cause=…)`.
5. **Resolved** — in previous, not in incoming → delete from `devradar_finding`, append `devradar_finding_event(type='resolved', cause=…)`.
6. **Changed** — in both but severity/score/fixed differs → update `devradar_finding`, append `devradar_finding_event(type='rerated' | 'fixed', cause=…)`.
7. **Unchanged** — in both, identical → **no write**. This is the common case and the reason the event log stays small.
8. Always insert one `devradar_scan_run` summary row (counts + all three version axes), so every scan is provable even on a zero-event day.

#### Cause classification — the four version axes

A finding set is fully determined by four inputs, which change on different clocks. Every event records **which one changed** so the change is attributable — and so alerting can ignore changes the tenant didn't cause:

| Axis | Source | Changes when | `cause` when it's what moved |
|---|---|---|---|
| SBOM inventory | `devradar_sbom.id` / `digest` | new image digest | `image` |
| Vulnerability DB | `db_version` | ~daily | `db` |
| Scanner binary (matcher logic) | `scanner_version` | our upgrade | `tooling` |
| Canonicalizer | `canonicalizer_version` | our upgrade | `tooling` |

The rule, in priority order, for a given `(sbom, scanner)` versus its prior run:
- The SBOM is immutable and keyed per digest, so a *new* SBOM is a different `sbom_id` — deltas on a new digest are **`image`**.
- Same `sbom_id`, changed `db_version` → **`db`** (a real new disclosure or re-rating; the image is frozen).
- Same `sbom_id`, same `db_version`, changed `scanner_version` or `canonicalizer_version` → **`tooling`** (our matcher/converter changed the answer, not the world).

This matters because a scanner upgrade can add or drop findings on an identical SBOM + identical DB — grype/trivy matching logic evolves independently of the DB. Without this, upgrading grype would emit a wave of `added` events and **page every tenant** for a change that is neither their image nor the CVE data. `tooling`-caused events are still recorded (full audit trail, reproducibility preserved) but are excluded from alerting by the `cause IN ('image','db')` filter. Expect a one-time, non-alerting wave of `tooling` deltas across the corpus on each deliberate scanner upgrade — explainable precisely because it's tagged.

Because the SBOM is frozen, this classification is unambiguous: only one axis can be "the newest thing that changed" for any given run.

Idempotency: the whole method is safe to re-run (Cloud Run Job retries). Re-running the same `(sbom, scanner, db_version, scanner_version)` recomputes the identical incoming set → produces zero new events. Current-state writes are UPSERTs; event inserts are guarded by a natural key (the `UNIQUE` above).

Reproducibility: `(sbom.id, db_version, scanner_version, canonicalizer_version)` fully determines a finding set — "show me this image as of DB X, grype Y" is answerable forever from `devradar_scan_run`.

---

## PostgreSQL Schema

DevRadar shares one Postgres database (`thingz` on `thingzio-pg`) with DevPulse and DevTrace. Isolation follows the platform contract, and this is a **hard invariant**: **every DB object DevRadar creates — tables, indexes, sequences, views, materialized views, functions, types — is prefixed `devradar_`** (indexes as `idx_devradar_*`), so nothing can collide with `devpulse_*` or `devtrace_*` in the shared database. DevRadar also connects as its own DB user (`devradar`). See [Shared-Infrastructure Contract](#shared-infrastructure-contract) for the instance-level detail.

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
    min_severity  TEXT NOT NULL DEFAULT 'medium',      -- read-API default severity filter
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
-- One row per SBOM per scanner per run. Records ALL FOUR version axes that
-- determine a finding set, so every result is fully reproducible and every
-- change is attributable to exactly one cause (see ApplyScan).
CREATE TABLE devradar_scan_run (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sbom_id              TEXT NOT NULL REFERENCES devradar_sbom(id) ON DELETE CASCADE,
    scanner              TEXT NOT NULL,                 -- grype | trivy
    db_version           TEXT NOT NULL,                 -- vuln DB snapshot (changes ~daily)
    scanner_version      TEXT NOT NULL,                 -- scanner binary — the MATCHER logic (changes on upgrade)
    canonicalizer_version TEXT NOT NULL,                -- SPDX->CDX converter identity
    scanned_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    finding_count  INT NOT NULL,
    critical_count INT NOT NULL,
    high_count     INT NOT NULL,
    medium_count   INT NOT NULL,
    low_count      INT NOT NULL,
    -- (sbom_id, digest via sbom) + these three versions fully determine the result.
    UNIQUE (sbom_id, scanner, db_version, scanner_version, scanned_at)
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
    cause        TEXT NOT NULL,                         -- image | db | tooling  (what changed to cause this)
    db_version   TEXT NOT NULL,                         -- vuln DB that produced the change
    scanner_version TEXT NOT NULL,                      -- scanner binary that produced the change
    scan_run_id  UUID NOT NULL,
    occurred_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Idempotency: a given change is recorded once per (db, scanner) version pair.
    UNIQUE (sbom_id, scanner, finding_id, event_type, db_version, scanner_version, occurred_at)
) PARTITION BY RANGE (occurred_at);

-- Monthly partitions (create ahead via pg_partman or a scheduled job).
CREATE TABLE devradar_finding_event_2026_07 PARTITION OF devradar_finding_event
    FOR VALUES FROM ('2026-07-01') TO ('2026-08-01');
CREATE INDEX idx_devradar_fe_tenant_time ON devradar_finding_event(tenant_id, occurred_at DESC);
-- Alerting reads only tenant-facing causes (image|db), never tooling-driven noise.
CREATE INDEX idx_devradar_fe_alerting ON devradar_finding_event(tenant_id, event_type, severity, occurred_at DESC)
    WHERE cause IN ('image','db');

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

The original design appended every finding on every scan — ~159M rows/year, of which ~99% are byte-identical to the prior day because a fixed SBOM's inventory doesn't change. The event model stores *current state* (bounded) plus *changes* (a handful of rows on a normal day). Same query power for "what did this image look like on date X" (replay events up to X, or read `devradar_scan_run` + reconstruct), far less storage, and the "what changed" read API (and future alerts) is a trivial `SELECT` over `devradar_finding_event` instead of a nightly diff job.

### Retention & roll-up (forward-looking, additive)

`devradar_finding_event` is retained **forever** in v1. Because it is partitioned monthly by `occurred_at`, later policies are additive and require no migration:

- **Per-plan caps** — a retention job drops or archives partitions older than the tenant's plan allows.
- **Roll-ups** — a derived `devradar_finding_event_rollup` table (per `image_ref` × month × severity: counts, net delta) materialized from the event log gives long-range trend views while detailed CVE-level events are kept only for the last N days. The raw log stays the source of truth.

---

## Reading Findings & Deltas (v1 — pull)

**v1 is pull, not push.** There is no email/notification delivery in the MVP; tenants retrieve their current findings and change history over the read API (and the UI renders the same data). The event log and cause classification already produced by the scan job are exactly what these endpoints serve — delivery is the only thing deferred.

The read endpoints (tenant-scoped, `WHERE tenant_id = $1`):

| Method | Path | Returns |
|---|---|---|
| `GET` | `/v1/images` | tracked images (latest state per digest) |
| `GET` | `/v1/images/{ref}/timeline` | change events for an image ref across digests |
| `GET` | `/v1/sboms/{id}/findings` | current findings for one SBOM |
| `GET` | `/v1/sboms/{id}/events` | change events for one SBOM |

**Severity threshold (a view/policy knob, not a write filter).** Findings are always *stored* at every severity; which ones a read *returns* is a tenant policy. Each tenant has a `min_severity` (default `medium`, in `devradar_tenant`). Every read endpoint filters at or above it, and accepts an independent `?min_severity=` per-request override — so `/findings` and `/events` can use different thresholds in the same session. `/v1/images` always returns the **full** per-severity breakdown (critical…negligible + unknown + total) plus a `relevant` count at the threshold, so the UI can render everything without re-querying. **`unknown` is always included**, at any threshold — an unrated CVE could be anything, so it is never hidden. The ordering lives in one place (`data.SeverityRank` / `AllowedSeverities` / `MeetsThreshold`) so the SQL filter and the `relevant` count can't drift. `unknown` is not a valid *threshold* value (it's a floor of "everything ranked", not a rank).

The core query — recent actionable changes for a tenant — is the same one a future alerter will use; in v1 it backs the "what changed" view. `cause IN ('image','db')` filters out tooling-driven deltas so a grype/trivy upgrade never shows up as a real change (and, later, never pages anyone):

```sql
-- Actionable changes for a tenant since a caller-supplied cursor.
SELECT e.exposure, e.package, e.severity, e.score, s.image_ref, e.cause, e.occurred_at
FROM devradar_finding_event e
JOIN devradar_sbom s ON s.id = e.sbom_id
WHERE e.tenant_id = $1
  AND e.event_type = 'added'
  AND e.severity IN ('critical','high')
  AND e.cause IN ('image','db')     -- exclude tooling-driven changes
  AND e.occurred_at > $2            -- cursor / since
ORDER BY e.occurred_at;
```

### Alerting & narratives (post-MVP)

Push delivery is deferred, but the design is unchanged and the data is ready:

- **Email/webhook alerts** — the SBOM carries the tenant and the tenant carries the destination (`devradar_tenant.email`), so routing needs no registry knowledge or external identity resolution. An alerter is a thin consumer of the query above plus a per-tenant watermark.
- **Delta narratives (Claude)** — turn a day's change set into a one-line human summary (e.g. *"Criticals rose by 3: new CVEs in openssl and glibc from a DB update; the image did not change"*), using the **Haiku** model, nil-safe (absent key ⇒ raw events, never a hard dependency). See [Platform Alignment → Claude](#claude-optional-delta-narratives).

Both are strictly additive: they consume the event log v1 already produces, so shipping pull-first costs nothing later.

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
| Daily scan | Cloud Run Job `devradar-saas-scan` | ~2 vCPU; pinned scanner binaries baked in, vuln DB refreshed lazily at job start; triggered by Cloud Scheduler |
| Images | `ko` via GoReleaser (no Dockerfile) | Pushed to Artifact Registry `us-west1-docker.pkg.dev/thingzio/devradar-saas-images/<name>` |
| Scheduling | Cloud Scheduler | Triggers the scan job ~02:00 UTC |
| SBOM bytes | GCS bucket `devradar-saas-sboms` (DevRadar-owned) | Content-addressed objects; the shared infra's DB-backup bucket is not for app data |
| Store | Shared Cloud SQL `thingzio-pg`, database `thingz`, user `devradar` | `db-custom-1-3840` — DevRadar does **not** provision the instance |
| Secrets | Secret Manager | `devradar-saas-database-url`, `devradar-saas-oauth-client-secret`, `devradar-saas-anthropic-api-key` |

This is the **two-deployable-unit** shape (DevPulse's model: a service + a scheduled Job), chosen over DevTrace's single-binary-with-background-goroutines because DevRadar's daily scan is a long batch over *all* tenants — a Cloud Run Job is independently retriable and scaled, and lets the API service scale to zero between requests.

**Scanner/DB versioning.** Two version concerns, two files:

- **`.settings.yaml`** — the platform single-source-of-truth (Go version, `ko`/`goreleaser`/`golangci-lint`/`tfsec` versions, coverage threshold), consumed by the Makefile and CI via `yq`, identical to both siblings.
- **Pinned scanner versions** live alongside it and are baked into the scan-job image; `db_version` recorded on every `devradar_scan_run` ties each finding to the exact DB that produced it.

#### Vulnerability DB freshness

The scanner *binaries* are pinned and baked (a fixed matcher version is what makes findings reproducible). The vulnerability *database* is **not** baked — it is refreshed lazily:

- At **job start**, `Scanner.EnsureDB(ctx, maxAge)` updates each scanner's DB if it is missing or older than `maxAge` (default 24h): `grype db update` when `grype db status` reports stale/invalid; `trivy image --download-db-only` when its `UpdatedAt` is beyond `maxAge`.
- For the **rest of the run** the DB is frozen — every per-SBOM scan runs with auto-update off (`GRYPE_DB_AUTO_UPDATE=false` / `--skip-db-update`). This is the important invariant: **one job run uses exactly one DB version**, so a DB refresh can never fire mid-run and split otherwise-identical SBOMs across two `db_version`s (which would corrupt cause attribution).

This replaces the original "bake the DB into a nightly-rebuilt image" plan, which was a holdover from the discarded VM-fleet design. For a single daily Cloud Run Job the one-time refresh at start amortizes to nothing, needs no image-rebuild pipeline, and is always current. Baking would only win for air-gapped or high-frequency cold-start topologies — neither applies here.

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
  converter/                       # Converter interface + grype/trivy normalizers (vimp pattern, native impl)
  parser/                          # gabs helpers (vimp pattern, native impl)
  claude/          client.go       # nil-safe Anthropic Messages client (delta narratives)
  data/
    vuln.go                        # normalized Vulnerability (vimp pattern, native impl)
    postgres/                      # Store, PoolConfig, advisory-lock migrate, per-domain query files
      sql/migrations/*.sql         # NNN_name.sql; 001 squashed idempotent schema (devradar_ tables)
  logging/         cli.go          # slog JSON to stderr, version/source tagged
  health/
infra/saas/                        # Terraform: references shared thingzio-pg + VPC, creates DevRadar resources
.settings.yaml                     # platform SoT: Go + tool versions, coverage threshold (yq-consumed)
.goreleaser.yaml  Makefile         # ko build + self-documenting targets
```

**Pattern sources (lessons, not dependencies — DevRadar imports neither project):**
- From **vimp**: the shape of `scanner`, `converter`, `parser`, and `data/vuln.go` (multi-scanner registry + normalized finding). Reimplemented natively; no `github.com/mchmarny/vimp` import.
- From **devtrace/devpulse**: the shape of `config`, `data/postgres` (Store + migrate runner), `tenant`, `middleware`, `server`, `logging`, `claude`, and the Makefile/CI/Terraform skeleton. Copied/adapted into this module, not imported.

DevRadar-specific and original: `sbom` (subject extraction + canonicalization), the event-model store queries, and the SBOM-scanning scan job.
