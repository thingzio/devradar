# DevRadar UI Plan — data-driven layout

_Draft 2026-07-06. Grounded in the 13 images / 15 SBOMs currently ingested in the
prod test tenant, scanned by Grype + Trivy._

## Where the UI is today

Two authenticated pages only: `landing.html` (magic-link sign-in) and
`tokens.html` (API tokens + severity threshold). **There is no data view** — a
signed-in tenant can mint a token but cannot see a single finding in the browser.
Everything below is net-new, built on the read API that now backs the three CUJs.

## What the data actually looks like (measured, not assumed)

Risk-sorted inventory after a scan of all 13 images:

| repo | crit | high | med | low | total | fixable | scanners |
|---|---|---|---|---|---|---|---|
| crd-upgrader | 11 | 98 | 125 | 21 | 256 | ~48% | grype 222 / trivy 34 |
| prometheus-adapter | 11 | 70 | 88 | 6 | 176 | — | both |
| node-feature-discovery | 7 | 59 | 49 | 4 | 124 | — | both |
| debian | 7 | 27 | 93 | 23 | 168 | — | both |
| alpine | 4 | 36 | 40 | 17 | 97 | — | grype only (1 trivy failure) |
| … 8 more, tapering to operator (12 total) | | | | | | | |

Key facts that should drive the layout:

1. **Severity spread is the primary signal.** Every image has a critical/high
   count; the interesting question is *which images* concentrate risk. crd-upgrader
   and prometheus-adapter (11 criticals each) dominate — the UI must make the worst
   offenders obvious at a glance.
2. **~48% of findings are fixable** (`is_fixed=true`). This is the single most
   actionable dimension and is currently invisible. "Fixable now" vs "no fix
   available" is the difference between a work item and noise.
3. **Findings cluster on a few packages.** crd-upgrader's 256 findings trace to
   `stdlib` (48 — Go binary CVEs), `openssl-libs` (24), `curl-minimal`/`libcurl`
   (19 each). A per-image package rollup turns 256 rows into ~5 real problems.
4. **Scanner divergence is real and worth showing.** grype 222 vs trivy 34 on the
   same SBOM; alpine has a recorded trivy `zero-findings` failure. The `failures`
   count per image is a data-quality badge, not an error to hide.
5. **Time-series is shallow *today*** — nearly all events are `cause:image` from
   the first scan, ~1 day of history. The change-over-time views must be built
   now (they're the product thesis) but designed to look sensible with one day of
   data and get richer automatically as daily scans accrue.

## Information architecture

Four authenticated pages, mapping 1:1 to the CUJs plus a fleet overview. All
server-rendered `html/template` (matches existing stack; no SPA), reusing
`app.css`. Data comes from the existing read API — no new endpoints required.

```
/                    landing (unchanged)
/tokens              tokens + settings (unchanged)
/dashboard   [NEW]   fleet overview  — CUJ-1, the "what should I worry about" page
/images/{repo}[NEW]  one image       — CUJ-2 (its SBOMs/versions) + CUJ-3 (timeline)
/sboms/{id}  [NEW]   one SBOM         — findings table + failures + events
```

(Repository has slashes → route as `/images?repo=<repository>` query param, same
as the API, to avoid path-wildcard trouble.)

### Page 1 — Dashboard (fleet overview) · CUJ-1

The landing spot after sign-in. Answers "across everything I track, what's worst?"

- **Top strip: 4 headline stats** — Images tracked · Total findings · Critical
  (fleet-wide) · Fixable now (%). One number each, big. Fixable% is the hook.
- **Risk-ranked image table** — one row per repository, sorted by a risk score
  (crit×1000 + high×10 + total), columns: image · a **stacked severity bar**
  (crit/high/med/low as colored segments, width = count) · total · fixable badge ·
  a data-quality dot if `failures>0`. Row links to the image page.
- The stacked bar is the workhorse: it encodes the full breakdown in one glance
  and makes crd-upgrader/prometheus-adapter visually pop without reading numbers.
- Severity threshold selector (reuses the existing tenant setting) filters what
  counts, consistent with the API's `min_severity`.

### Page 2 — Image detail · CUJ-2 + CUJ-3

"Show me this image over its versions and over time."

- **Header**: repository, current version(s)/tag, digest count, latest scan date.
- **Trend chart (CUJ-3)**: findings-over-time line from the timeline endpoint,
  one point per scan, split by severity. With one day of data it's a single
  marker + an honest "history builds daily" note; it fills in automatically. This
  is the product's signature view — build it now even though it's sparse.
- **Change log (CUJ-3)**: the event feed — added / fixed / rerated / resolved,
  each tagged with **cause** (`image` = new digest, `db` = new CVE data,
  `tooling` = scanner change). Cause is the "clean causality" payoff; color/icon
  it. Paginated via `next_cursor`.
- **Versions/SBOMs list (CUJ-2)**: each submitted SBOM for this image, newest
  generation first — version, digest (short), generated-at, package count, its
  finding total. Rows link to the SBOM page.

### Page 3 — SBOM detail

The drill-down for one frozen inventory.

- **Findings table** — the core. Columns: severity (colored) · CVE (link to
  NVD) · package · version · CVSS score · **Fix available** (the fixable flag) ·
  scanner. Sortable by severity/score; filterable by "fixable only". Paginated.
- **Package rollup** (collapsible) — findings grouped by package, worst-first, so
  "openssl-libs: 24 findings" reads as one upgrade decision, not 24 rows.
- **Scan health** — the `failures` for this SBOM (e.g. the alpine trivy
  `zero-findings`), shown as an informational panel so a partial scan is explicit,
  not a silent gap. Also surface which scanners contributed and their `db_version`.
- **Events for this SBOM** — the per-SBOM change log (paginated).

## Cross-cutting design decisions

- **Fixable is a first-class dimension everywhere** — a badge on the dashboard, a
  column + filter on findings. It's the most actionable fact in the data and is
  currently unsurfaced.
- **Severity color scale** — one palette (critical→low + a distinct `unknown`),
  defined once in `app.css`, used by every bar/badge/row.
- **Honor the tenant `min_severity`** on every view, with a per-page override,
  mirroring the API so the UI and API never disagree.
- **Stacked severity bar** as the recurring visual primitive (dashboard rows,
  image header) — pure CSS flexbox, no chart library.
- **Charts**: the only thing needing more than CSS is the trend line. Prefer a
  tiny inline SVG sparkline generated server-side (no JS dependency, matches the
  "boring, self-contained" stance) over pulling in a charting library.
- **Pagination**: reuse `next_cursor`; "Load more" links, not page numbers.

## Honest constraints

- **Time-series views are sparse until daily scans accrue.** They must be built
  now (they're the thesis) but shouldn't look broken with one data point — hence
  the "history builds daily" affordance.
- **No cross-image CVE aggregation endpoint yet.** "CVE-X affects 6 of your
  images" is a compelling fleet insight but needs a new query (group findings by
  exposure across a tenant's SBOMs). Flagged as a fast-follow, not v1 of the UI.
- **Read API is per-repo / per-SBOM.** The dashboard's fleet rollup is already
  served by `/v1/images` (grouped). No new endpoints needed for pages 1–3; the
  cross-image CVE view is the one future addition.

## Suggested build order

1. Dashboard (`/dashboard`) — highest value, reuses `/v1/images`, no new API. ✅ shipped v0.1.7
2. Image detail (`/images?repo=`) — versions list + change log + trend affordance. ✅ shipped v0.1.8
3. SBOM detail (`/sboms/{id}`) — findings table + fixable filter + package rollup. ✅ shipped (Page 3)
   - All list views keyset-paginated (v0.1.9): image list, SBOMs, change log, findings.
4. Fast-follow: cross-image CVE aggregation ("which images share this CVE").
5. Fast-follow: SBOM tagging → image groups (see below).

## Future — SBOM tagging & image groups

_Requested 2026-07-06. Lets tenants label SBOMs (e.g. `team-x`, `prod`, `edge`)
and filter the dashboard to a group. The unique tag set shows atop the dashboard;
selecting a tag lists only images with that tag._

The design composes cleanly onto what's already built:

- **Data**: a `devradar_sbom_tag` table (tenant-scoped, `(sbom_id, tag)`), or a
  `tags text[]` column on `devradar_sbom`. Tags are per-SBOM but roll up to the
  repository/image for grouping — the same relationship `version` already has.
- **Ingest**: `POST /v1/sboms` accepts an optional `tags: ["team-x","prod"]`
  field; `tools/sbom-submit` gains a repeatable `--tag` flag so CI labels at
  push. In-UI tag editing is a nice-to-have on top of the push path.
- **API**: a `?tag=` filter on `/v1/images` and the grouped views. It's just
  another `WHERE` predicate, so it composes with the existing `min_severity`
  filter and keyset pagination without new machinery.
- **UI**: a tag filter bar across the top of the dashboard (the tenant's unique
  tag set); selecting one narrows the risk-ranked image list to that group.

Effort is modest because the grouping, filtering, and pagination substrate all
exist — this adds a dimension, not a new subsystem.
