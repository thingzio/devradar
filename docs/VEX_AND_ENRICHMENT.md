# DevRadar: Risk Enrichment, VEX Ingestion & Advanced Views

_Design doc. Draft 2026-07-06._

This covers three related enhancements that together move DevRadar from
*change-detection* to *triage*:

1. **Risk enrichment** — EPSS + CISA KEV, so "severity" becomes "risk". (Building first.)
2. **VEX ingestion** — tenants post OpenVEX to contextualize/suppress findings.
3. **Advanced views** — cross-image CVE (blast radius), per-version time-series, per-package distribution.

## Governing principle: enrichment and context are *overlays*, never mutations

DevRadar's core guarantee is determinism: same SBOM + same scanner DB → same
findings. Everything below must preserve that. So **`devradar_finding` is never
mutated by any of these features.** EPSS/KEV live in a CVE-keyed reference table;
VEX lives in its own tables; both are `LEFT JOIN`ed at read time. This is the
exact discipline the `min_severity` threshold already follows — a view/policy
layer on top of immutable facts.

Trust ledger, made explicit per source:
- **SBOM** — `unverified` (tenant-submitted).
- **VEX** — tenant-asserted (`unverified`); DevRadar records it, never blesses it.
- **EPSS / KEV** — authoritative external feeds (FIRST.org, CISA).

---

## 1. Risk Enrichment (EPSS + KEV) — building first

### Why first
Prioritization today is **CVSS-only**, which is a static label, not a risk
signal. Real triage needs:
- **EPSS** (Exploit Prediction Scoring System, FIRST.org) — probability [0,1]
  that a CVE is exploited in the next 30 days. Refreshed daily.
- **CISA KEV** (Known Exploited Vulnerabilities) — CVEs with confirmed
  in-the-wild exploitation. A KEV hit is the strongest "patch now" signal there is.

Both are free, public, CVE-keyed, and refresh daily — the same cadence as the
vuln DB. This makes *every* view and the dashboard risk-ranking dramatically more
actionable for low effort.

### Data model — `devradar_cve_enrichment` (migration 005)
```sql
CREATE TABLE devradar_cve_enrichment (
    cve             TEXT PRIMARY KEY,          -- e.g. CVE-2025-68121
    epss_score      REAL,                      -- [0,1] probability, nullable
    epss_percentile REAL,                      -- [0,1] percentile, nullable
    kev             BOOLEAN NOT NULL DEFAULT false,
    kev_added       DATE,                      -- CISA date_added, nullable
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```
CVE-keyed (not per-finding): one row per CVE, shared across every finding/SBOM
that references it. No duplication, no re-write on scan.

### Refresh pipeline — `pkg/enrich`
Runs in the **daily scan job** (it already has internet egress for the scanner
DBs, and daily is the right cadence). Order in `Runner.Execute`: refresh
enrichment once up front, then the scan loop (unchanged).

- **KEV**: one HTTPS GET of CISA's `known_exploited_vulnerabilities.json`
  (~1300 entries). Parse → set of CVEs + `date_added`. Small, complete.
- **EPSS**: query `api.first.org/data/v1/epss` in batches for the **distinct CVEs
  currently in `devradar_finding`** (targeted, not the full ~300k corpus). Bulk
  CSV is the fallback if batch volume grows.
- **Upsert** all into `devradar_cve_enrichment`. Failures are logged + recorded
  but never abort the scan (enrichment is additive; a stale EPSS is acceptable,
  a missed scan is not).

### Read-path integration
`Finding` gains `EPSS float32`, `EPSSPercentile float32`, `KEV bool`. Every
finding read `LEFT JOIN devradar_cve_enrichment e ON e.cve = f.exposure`.
Dashboard/fleet stats gain a `kev_count`. Nothing about the write path changes.

### Risk ranking (the payoff)
The dashboard's SQL risk score evolves from `crit*1e9 + high*1e5 + total` to
incorporate KEV and EPSS, e.g.: **KEV present** dominates, then CVSS tier, then
EPSS as the tiebreaker within a tier. This is what makes "actionable vs. noise"
real. (Kept as a documented, tunable expression in one place.)

### UI
- Findings table: a **KEV badge** (red, unmissable) and an **EPSS %** column.
- Dashboard: a "KEV" headline stat and a per-image KEV flag.
- Sort/filter: "KEV only" and "EPSS > x" toggles alongside "fixable only".

### Effort: **Low–Medium.** 1 table + 1 migration + `pkg/enrich` (2 HTTP
parsers, fixture-tested) + read-path joins + UI badges. No scan-path disruption.

---

## 2. VEX Ingestion (OpenVEX)

### Why it makes sense
DevRadar's findings provoke exactly one question — *"it's present, but does it
affect me?"* — that nothing else answers. VEX is the standards-based, portable
answer, and it's the biggest false-positive-reduction lever available. A tenant
staring at 256 findings needs to say "we don't ship that code path — suppress it"
in a way that travels to other consumers too.

### Why it's tractable here
The hard part — a **stable finding identity** — already exists:
`finding_id = sha256(exposure/package/version)`, pinned to an immutable digest.
OpenVEX's correlation triple maps directly:

| OpenVEX | DevRadar | Match |
|---|---|---|
| `statements[].vulnerability.name` | `finding.exposure` | exact (CVE) |
| `statements[].products[].@id` (digest) | `sbom.digest` | exact |
| `statements[].products[].subcomponents[]` (purl) | `package`+`version` | good |
| `statements[].status` / `justification` | *(new tables)* | — |

### Data model
```sql
CREATE TABLE devradar_vex_document (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL,
    author      TEXT,
    document    JSONB NOT NULL,               -- raw OpenVEX, for round-trip
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE devradar_vex_statement (
    id               BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id        UUID NOT NULL,
    document_id      UUID NOT NULL REFERENCES devradar_vex_document(id) ON DELETE CASCADE,
    product_digest   TEXT NOT NULL,           -- scopes to a specific image version
    vulnerability    TEXT NOT NULL,           -- CVE
    subcomponent     TEXT,                    -- purl; NULL = whole product
    status           TEXT NOT NULL,           -- not_affected|affected|fixed|under_investigation
    justification    TEXT,                    -- required when not_affected
    impact_statement TEXT,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### Endpoint
`POST /v1/vex` (tenant-scoped, API-token). Parse + spec-validate OpenVEX JSON,
persist the document, explode statements, resolve each to matching findings by
`(product_digest, vulnerability[, subcomponent])`.

### Read-path integration (the real work)
Every finding/count path `LEFT JOIN`s the latest VEX statement per
`(digest, cve, subcomponent)`. `not_affected` / `fixed` are **suppressed by
default** with a "show suppressed" toggle. This is architecturally identical to
how `min_severity` threads through every read — the pattern exists.

### Guardrails (hard-won)
- **Suppression is reversible + visible, never destructive.** A VEX'd finding is
  hidden-by-default, one click from visible; the change-event log still records it.
  The CVE data underneath keeps updating — that's the point.
- **Digest-scoped VEX does NOT carry to a new digest.** A new image is a new
  product; previously-suppressed findings need re-triage. Surface "N suppressed
  findings need re-triage on this new version."
- **Validate the justification enum, not the claim.** Enforce a spec justification
  on `not_affected`; you can't verify it's true. Surface, don't bless.
- **Trust boundary:** VEX is the tenant's assertion (`unverified`), like the SBOM.

### Synergy with the (already-designed) Claude VEX *generation*
`POST /v1/sboms/{id}/vex` (Claude drafts `under_investigation` stubs) and this
`POST /v1/vex` (tenant posts a completed doc) are the two ends of one round-trip:
draft → edit/review → post back → findings contextualized. Share the
`devradar_vex_document` table.

### Effort: **Medium.** 2 tables + 1 endpoint + read-path overlay (the bulk) + UI.
Comparable to the CUJ-endpoints phase. ~2–3 sessions.

---

## 3. Advanced Views

### 3a. Cross-image CVE — "blast radius" (High value, Low effort)
*"CVE-X affects 6 of your 13 images."* Turns per-image noise into one fleet
action. One query, one page (`/cve/{id}` + a fleet CVE list), keyset-paginated.
Most valuable *with* VEX (suppress a CVE across the whole fleet at once) and *with*
enrichment (rank the fleet CVE list by KEV/EPSS).
```sql
SELECT exposure, MAX(severity) worst, COUNT(DISTINCT sb.repository) images
FROM devradar_finding f JOIN devradar_sbom sb ON sb.id = f.sbom_id
WHERE sb.tenant_id = $1 AND sb.status = 'active'
GROUP BY exposure ORDER BY images DESC, worst;
```

### 3b. Per-version time-series composition (High value, Medium effort)
Stacked-area chart: X = scan date/version, Y = finding count, bands = severity —
an image's risk trajectory. **`devradar_scan_run` already stores per-scan
`finding_count` + `critical/high/medium/low_count`**, so the time-series data
largely exists; the read is a per-repo aggregation of scan_run rows over time.
Render with Chart.js (siblings already vendor it). Minor gap: confirm scan_run
counts are populated on every run.

### 3c. Per-package distribution (Medium value, Medium effort)
Cheap version (ship now): horizontal bar chart on the SBOM page's existing
`PackageRollup` — packages by vuln count, colored by worst severity. True scatter
(vuln count vs. package *size*) needs a size axis captured at ingest from syft
component metadata — defer; more novelty than triage signal.

---

## Recommended sequence

1. **EPSS + KEV enrichment** (this doc's build) — force-multiplier for everything.
2. **Cross-image CVE view** — highest-value view, lowest effort, ranks by #1.
3. **VEX ingestion** — closes the false-positive loop.
4. **Time-series composition** (scan_run aggregation) + **package bar chart**.
5. **SBOM tagging / image groups** (separately planned) — pairs with fleet-CVE + VEX.
