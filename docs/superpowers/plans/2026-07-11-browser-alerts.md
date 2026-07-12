# Browser Alerts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Let a tenant opt into alert generation, review unread alerts from Overview, browse alert history, and open a canonical alert detail page.

**Architecture:** Extend the Postgres store with strictly tenant-scoped policy and alert reads/mutations. Add session-authenticated, CSRF-protected settings and read-state routes. Render server-side pages that reuse the existing DevRadar design system; the alert kind/cause rail is the single new visual signature.

**Tech Stack:** Go 1.26, `database/sql`, PostgreSQL, stdlib `net/http`, `html/template`, embedded CSS, existing session/CSRF middleware.

## Global Constraints

- Browser is the only delivery channel.
- Policy and read state are tenant-scoped; multi-user behavior is deferred.
- Policy changes are prospective and never rewrite existing alerts.
- Every store method takes `tenantID` first and filters by it.
- All POST routes require session authentication and CSRF validation.
- Existing alert generation, scan persistence, API behavior, and navigation remain functional.
- No deployment or release.

---

### Task 1: Tenant-scoped policy and alert store API

**Files:**
- Modify: `pkg/data/postgres/models.go`
- Modify: `pkg/data/postgres/alert.go`
- Modify: `pkg/data/postgres/alert_test.go`

**Interfaces:**
- Produces: `UpdateAlertPolicy(ctx, tenantID string, policy AlertPolicy) error`.
- Produces: `ListAlerts(ctx, tenantID, cursor string, limit int) ([]Alert, string, error)`.
- Produces: `UnreadAlerts(ctx, tenantID string, limit int) ([]Alert, error)`.
- Produces: `GetAlert(ctx, tenantID, alertID string) (*Alert, error)`.
- Produces: `MarkAlertRead(ctx, tenantID, alertID string) error`.

- [x] **Step 1: Write failing integration tests**

Use two seeded tenants and direct alert fixtures. Assert policy updates persist only for the owner; list order is `(created_at,id) DESC`; unread filtering excludes `read_at`; `GetAlert` and `MarkAlertRead` return `ErrNotFound` for a different tenant; retrying mark-read is harmless; and pagination returns a cursor without duplicates.

- [x] **Step 2: Verify RED**

Run: `DATABASE_URL=postgres://devradar:devradar@localhost:5432/devradar?sslmode=disable go test ./pkg/data/postgres -run TestAlertTenantStore -count=1`

Expected: FAIL because the store methods do not exist.

- [x] **Step 3: Implement policy update**

Validate `MinSeverity` with `data.ValidMinSeverity`; normalize labels to a non-nil slice; update by `tenant_id`; return `ErrNotFound` when no row is affected. Do not permit callers to change policy ID or tenant ID.

- [x] **Step 4: Implement alert reads and read state**

Select alert facts plus current KEV/EPSS enrichment. Use existing keyset cursor helpers for `(created_at,id)`. `GetAlert` and `MarkAlertRead` include `tenant_id=$1`; map `sql.ErrNoRows` or zero affected rows to `ErrNotFound`.

- [x] **Step 5: Verify GREEN and commit**

Run: `go test -race ./pkg/data/postgres -count=1`

Expected: PASS.

```bash
git add pkg/data/postgres
git commit -S -m "feat(alerts): add tenant alert reads and settings"
```

### Task 2: Alert settings on the existing Settings page

**Files:**
- Modify: `pkg/server/ui.go`
- Modify: `pkg/server/templates/tokens.html`
- Modify: `pkg/server/csrf_tenant_test.go`
- Create: `pkg/server/alerts_test.go`

**Interfaces:**
- Adds: `POST /settings/alerts`.
- Extends the `/tokens` view with `AlertPolicy` and `Labels`.

- [x] **Step 1: Write failing route tests**

Assert `/tokens` renders disabled policy defaults, valid CSRF submission enables the policy and selected causes, invalid severity returns 400, submitted labels are restricted to the tenant's known labels, and another tenant's labels cannot be stored.

- [x] **Step 2: Verify RED**

Run: `go test ./pkg/server -run 'TestAlertSettings|TestTenantMutationsRequireCSRF' -count=1`

Expected: FAIL because the settings route/form are absent.

- [x] **Step 3: Register and implement settings handler**

Register `POST /settings/alerts` under `authed(csrf(...))`. Parse checkboxes by exact value `on`, validate severity, intersect submitted labels with `TenantLabels(ctx, tenantID)`, and call `UpdateAlertPolicy`. Redirect to `/tokens?alerts=saved` on success.

- [x] **Step 4: Render the settings card**

Extend `handleTokensPage` to call `EnsureAlertPolicy` and `TenantLabels`. Add a “Browser alerts” card before API tokens with a clear opt-in switch, severity selector, KEV/fix/cause checkboxes, optional known-label filters, and copy stating that email/webhooks come later. Button text: “Save alert settings.”

- [x] **Step 5: Verify GREEN and commit**

Run: `go test -race ./pkg/server -run 'TestAlertSettings|TestTenantMutationsRequireCSRF' -count=1`

Expected: PASS.

```bash
git add pkg/server
git commit -S -m "feat(alerts): add tenant browser alert settings"
```

### Task 3: Alert history and canonical detail page

**Files:**
- Create: `pkg/server/ui_alerts.go`
- Create: `pkg/server/templates/alerts.html`
- Create: `pkg/server/templates/alert.html`
- Modify: `pkg/server/ui.go`
- Modify: `pkg/server/templates/_chrome.html`
- Modify: `pkg/server/alerts_test.go`

**Interfaces:**
- Adds: `GET /alerts`.
- Adds: `GET /alerts/{id}`.
- Adds: `POST /alerts/{id}/read`.

- [x] **Step 1: Write failing route/isolation tests**

Seed one alert per tenant. Assert unauthenticated requests redirect, the owner sees list/detail content, a different tenant receives 404, marking read requires CSRF, retrying mark-read redirects successfully, and pagination preserves the cursor.

- [x] **Step 2: Verify RED**

Run: `go test ./pkg/server -run TestAlertPages -count=1`

Expected: FAIL because alert routes/templates are absent.

- [x] **Step 3: Implement handlers and view models**

Map kinds to plain-language titles: “Known exploited vulnerability”, “New vulnerability”, “Fix now available”, and “Posture regression”. Detail copy must say “scanner now reports a fix” for fix alerts. Link to `/cves/{exposure}`, `/sboms/{sbom_id}`, and `/images?repo={repository}`. Return 404 for `postgres.ErrNotFound` and 500 for other errors.

- [x] **Step 4: Render list/detail and navigation**

Add an Alerts nav tab. The list shows unread state, kind, CVE, repository, severity, cause, and time. The detail page is the canonical destination for later email/webhook links and contains an explicit “Mark as read” POST when unread.

- [x] **Step 5: Verify GREEN and commit**

Run: `go test -race ./pkg/server -run TestAlertPages -count=1`

Expected: PASS.

```bash
git add pkg/server
git commit -S -m "feat(alerts): add browser alert pages"
```

### Task 4: Overview unread-alert entry point and visual polish

**Files:**
- Modify: `pkg/server/ui_overview.go`
- Modify: `pkg/server/templates/overview.html`
- Modify: `pkg/server/static/css/app.css`
- Modify: `pkg/server/alerts_test.go`

**Interfaces:**
- Overview displays at most five unread alerts and an “All alerts” link.
- Alert pages use a kind/cause rail derived from existing severity/accent tokens.

- [x] **Step 1: Write failing overview test**

Seed six unread alerts and assert Overview renders five, links to `/alerts`, identifies unread items, and contains no alert belonging to another tenant.

- [x] **Step 2: Verify RED**

Run: `go test ./pkg/server -run TestOverviewUnreadAlerts -count=1`

Expected: FAIL because Overview does not load alerts.

- [x] **Step 3: Add the bounded Overview query and template card**

Call `UnreadAlerts(ctx, tenantID, 5)` after core fleet queries. If it fails, log a warning and render the rest of Overview with an “Alerts unavailable” message. Render the alert card before highest-risk images.

- [x] **Step 4: Add focused CSS**

Reuse the current GitHub-derived palette and typography. Add only alert-list layout, unread dot, and a 3px causality rail: red for KEV/regression, green for fix available, accent blue for new findings. Include visible focus styles and a single-column mobile layout. Do not introduce new fonts, gradients, animation, or unrelated restyling.

- [x] **Step 5: Run browser-slice verification and commit**

Run: `go test -race ./pkg/server ./pkg/data/postgres -count=1 && go vet ./pkg/server ./pkg/data/postgres`

Expected: PASS.

```bash
git add pkg/server
git commit -S -m "feat(alerts): surface unread alerts on overview"
```

## Completion Boundary

This plan exposes the already-shadowed alerts in the browser after explicit tenant opt-in. It does not add work-queue or comparison links that do not exist yet; those are attached in their own slices before the combined release.

## Unresolved Questions

None. Settings location, tenant scope, browser-only delivery, explicit opt-in, and canonical detail-page behavior are approved.
