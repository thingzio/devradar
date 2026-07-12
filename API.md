# DevRadar API — CLI-Driven Work Items

Backlog of server-side API enhancements surfaced while building the `devradarctl`
CLI against the current contract (`/openapi.yaml`, v0.13.0). Each item is
something the CLI **cannot** deliver well today because the API does not expose
it. Ordered by leverage (impact × how many CLI/CI workflows it unblocks).

Legend: **Priority** P0 (highest) → P2. **Effort** S/M/L (rough).

---

## P0 — Highest leverage

### 1. Batch / fleet-wide SBOM listing
- **Priority:** P0 · **Effort:** M
- **Gap:** There is no `GET /v1/sboms` (list all) and no batch submit. Every
  fleet-wide CLI operation (e.g. "gate the whole fleet") is an N+1 walk:
  `GET /v1/images` → per-repo `GET /v1/images/sboms` → per-SBOM
  `GET /v1/sboms/{id}/findings`.
- **Proposal:**
  - `GET /v1/sboms` — tenant-wide SBOM list, keyset-paginated, filterable by
    `status`, `label`, `min_severity`, `repo`; same envelope as existing lists.
  - `POST /v1/sboms:batch` — accept an array of submit requests (bounded), return
    per-item results. Cuts round-trips for CI that pushes many images.
- **CLI unlock:** `devradarctl sbom list`, fleet-wide `--exit-code` gating in one
  call, bulk `submit`.

### 2. Scan-status resource (deterministic `submit --wait`)
- **Priority:** P0 · **Effort:** M
- **Gap:** Rescans run "on a schedule"; a submission returns `202` with no
  handle to poll. `submit --wait` (deferred in the CLI for exactly this reason)
  can only heuristically poll `GET /v1/sboms/{id}` for non-empty counts —
  racy and imprecise.
- **Proposal:** either
  - `GET /v1/sboms/{id}/scan-status` → `{ state: pending|scanning|complete|failed,
    last_scanned_at, scanners[] }`; or
  - have `202` return a `Location`/`job_id` addressable at `GET /v1/jobs/{id}`.
- **CLI unlock:** a correct, non-heuristic `submit --wait` that blocks until the
  first scan lands, then prints findings.

### 3. Token introspection (`whoami`)
- **Priority:** P0 · **Effort:** S
- **Gap:** No endpoint validates a token or reveals its tenant/scope. A CLI
  `auth status`/`login` can only infer validity by making a real request and
  watching for `401`.
- **Proposal:** `GET /v1/whoami` → `{ tenant, token_id, created_at,
  scopes[] }` (scopes future-proofs today's read/write-only tokens).
- **CLI unlock:** `devradarctl auth status`, friendlier startup errors,
  pre-flight validation before a long operation.

---

## P1 — Strong value

### 4. Findings export in report formats (SARIF)
- **Priority:** P1 · **Effort:** M
- **Gap:** `GET /v1/sboms/{id}/findings` returns paginated JSON only. CI systems
  (GitHub code-scanning, etc.) consume **SARIF**; the CLI would have to hand-roll
  the conversion (and keep it correct).
- **Proposal:** content negotiation or `?format=sarif` on the findings endpoint
  (and/or a `.../findings.sarif` sibling). Optionally CSV for spreadsheets.
- **CLI unlock:** `devradarctl sbom findings <id> --output sarif` feeding
  `github/codeql-action/upload-sarif` directly.

### 5. Server-side image diff
- **Priority:** P1 · **Effort:** M
- **Gap:** No authoritative "what changed between digest A and B." The CLI can
  approximate by diffing two `/findings` pulls, but that is client-side,
  expensive, and non-canonical.
- **Proposal:** `GET /v1/images/diff?repo=&from=&to=` (or
  `.../{repo}/diff`) → `{ added[], resolved[], rerated[] }` of findings between
  two digests/versions.
- **CLI unlock:** `devradarctl images diff --repo r --from vX --to vY` — "did
  this release add CVEs?" as a first-class, cheap query.

### 6. Richer VEX read model + lifecycle
- **Priority:** P1 · **Effort:** M
- **Gap:** `GET /v1/vex` is metadata-only (free-form objects); there is no
  per-statement match detail and no way to delete/supersede a document. The CLI
  cannot show *why* a finding is suppressed or manage assertions.
- **Proposal:**
  - `GET /v1/vex/{id}` → statements with `{ vuln, status, justification,
    matched_digest, matched: bool }`.
  - `DELETE /v1/vex/{id}` (or a supersede semantics) for lifecycle.
  - On `Finding`, the existing `vex_status` is good; add `vex_document_id` so the
    CLI can link a suppression back to its source.
- **CLI unlock:** `devradarctl vex show <id>`, `vex rm <id>`, and a
  `findings --suppressed` view that explains each suppression.

### 7. Tenant settings / effective policy
- **Priority:** P1 · **Effort:** S
- **Gap:** No endpoint exposes the tenant's default `min_severity`, license
  policy, or trust policy. The CLI cannot tell a user what `--exit-code` will
  actually enforce without guessing.
- **Proposal:** `GET /v1/settings` → `{ default_min_severity, license_policy{…},
  trust_policy{…} }` (read-only is fine).
- **CLI unlock:** `devradarctl gate --explain` / clearer defaults; the gate can
  report the effective threshold it is applying.

---

## P2 — Nice to have

### 8. Webhooks / event stream (push instead of poll)
- **Priority:** P2 · **Effort:** L
- **Gap:** `devradarctl watch` is poll-only because there is no push channel.
  Polling is fine for a human at a terminal but wasteful for automation.
- **Proposal:** either tenant webhooks (`POST` config: URL + event filter, HMAC
  signed) or a server-sent-events stream `GET /v1/events/stream`.
- **CLI unlock:** real-time `watch` and event-driven CI notification without a
  poll loop.

### 9. Cursor stability / total counts on list envelopes
- **Priority:** P2 · **Effort:** S
- **Gap:** List envelopes carry `next_cursor` but no total/count, so the CLI's
  "more available" hint can't say *how many* more, and progress for `--all`
  cannot be shown.
- **Proposal:** add an optional `total` (or `estimated_total`) to the `Page`
  envelope where cheap to compute.
- **CLI unlock:** better paging UX (`showing 100 of 4,213`).

---

## Notes for the API team

- Items **2** and **7** together make CI gating first-class: wait for a real
  scan, then gate against the tenant's declared policy — no client-side
  heuristics.
- Item **1** is the single biggest multiplier: nearly every "operate on the whole
  fleet" CLI feature is blocked on N+1 walks today.
- The CLI already validates responses against the vendored `openapi.yaml`
  (`internal/client/contract_test.go`); please keep `/openapi.yaml` authoritative
  and bump it in the same PR as any of the above so the CLI's drift test catches
  the change.
