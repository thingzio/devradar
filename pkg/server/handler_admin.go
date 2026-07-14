package server

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"maps"
	"net/http"
	"strconv"
	"time"

	"github.com/thingzio/devradar/pkg/account"
	"github.com/thingzio/devradar/pkg/authn"
	"github.com/thingzio/devradar/pkg/config"
	"github.com/thingzio/devradar/pkg/data"
	"github.com/thingzio/devradar/pkg/data/postgres"
	"github.com/thingzio/devradar/pkg/middleware"
	"github.com/thingzio/devradar/pkg/scanner"
	"github.com/thingzio/devradar/pkg/tenant"
)

// This file implements the operator admin console (/admin/*). Access is gated by
// middleware.RequirePlatformAdmin (email allowlist, 404-on-deny); mutating routes are
// additionally wrapped in middleware.ValidateCSRF. Every action is audited to the
// log (auditLog) — there is no audit table by design. Mutations follow
// POST-redirect-GET with a ?msg= flash. The console is unlinked from the tenant
// nav and stays hidden.

const (
	adminPageSize    = 10
	adminScanRunsMax = 50
	adminFailuresMax = 50
	adminHistoryMax  = 720 // 30 days of hourly buckets
)

type adminProductHealthReader interface {
	AdminProductHealth(context.Context) (*postgres.AdminProductHealth, error)
}

func loadAdminProductHealth(ctx context.Context, reader adminProductHealthReader) (*postgres.AdminProductHealth, error) {
	return reader.AdminProductHealth(ctx)
}

func adminDashboardData(
	counts *postgres.PlatformCounts,
	rows []trendRow,
	productHealth *postgres.AdminProductHealth,
	productHealthErr error,
	now time.Time,
) map[string]any {
	oldestPendingAge := ""
	if productHealth != nil && productHealth.EvaluatorBacklog > 0 && !productHealth.OldestPendingAt.IsZero() {
		oldestPendingAge = humanizeSince(now.Sub(productHealth.OldestPendingAt))
	}
	return map[string]any{
		"Title":                         "Admin — Dashboard",
		"Counts":                        counts,
		"TrendRows":                     rows,
		"ProductHealth":                 productHealth,
		"ProductHealthUnavailable":      productHealthErr != nil,
		"ProductHealthOldestPendingAge": oldestPendingAge,
		"ProductHealthUTCDate":          now.UTC().Format("2006-01-02"),
	}
}

// auditLog records an operator action. Log-only (slog.Warn), matching the
// sibling services — no persisted audit table in v1.
func auditLog(action string, user *account.User, path, remote, detail string) {
	email := "<anonymous>"
	if user != nil {
		email = user.Email
	}
	slog.Warn("admin action",
		"action", action, "admin", email, "path", path, "remote", remote, "detail", detail)
}

// issueCSRF mints a CSRF token, sets the double-submit cookie, and returns the
// token for embedding as a hidden form field. Called by every GET page (admin
// and tenant) that renders a mutating form.
func issueCSRF(w http.ResponseWriter) string {
	token, err := middleware.GenerateCSRFToken()
	if err != nil {
		slog.Error("csrf token", "error", err)
		return ""
	}
	middleware.SetCSRFCookie(w, token)
	return token
}

// handleAdminDashboard renders the live platform snapshot.
func (s *Server) handleAdminDashboard(w http.ResponseWriter, r *http.Request) {
	user := middleware.UserFromContext(r.Context())
	auditLog("view_dashboard", user, r.URL.Path, r.RemoteAddr, "")

	counts, err := s.store.AdminPlatformCounts(r.Context())
	if err != nil {
		slog.Error("admin dashboard counts", "error", err)
		http.Error(w, "failed to load dashboard", http.StatusInternalServerError)
		return
	}

	// Record today's snapshot (last write of the day wins), then read deltas.
	// Best-effort: a snapshot/delta failure must not break the dashboard.
	if _, err := s.store.SnapshotPlatformStats(r.Context()); err != nil {
		slog.Warn("admin snapshot platform stats", "error", err)
	}
	deltas, err := s.store.PlatformDeltas(r.Context(), []int{1, 7, 30})
	if err != nil {
		slog.Warn("admin platform deltas", "error", err)
		deltas = nil
	}
	productHealth, productHealthErr := loadAdminProductHealth(r.Context(), s.store)
	if productHealthErr != nil {
		slog.Warn("admin product health unavailable", "error", productHealthErr)
	}

	render(w, "admin_dashboard.html", s.adminBase(user, "dashboard",
		adminDashboardData(counts, trendRows(deltas), productHealth, productHealthErr, time.Now())))
}

// trendCell is one Day/Week/Month delta cell.
type trendCell struct {
	Has   bool
	Delta int
}

// trendRow is one metric's row across the three horizons.
type trendRow struct {
	Label string
	Cells []trendCell
}

// trendRows flattens the deltas map into ordered, render-ready rows (nil when no
// snapshots exist yet, so the template omits the whole section).
func trendRows(deltas map[int]map[string]postgres.PlatformDelta) []trendRow {
	if len(deltas) == 0 {
		return nil
	}
	metrics := []struct{ key, label string }{
		{"tenants", "Tenants"},
		{"sboms_active", "Active SBOMs"},
		{"open_findings", "Open findings"},
		{"critical_open", "Critical open"},
		{"high_open", "High open"},
		{"vex_statements", "VEX statements"},
	}
	horizons := []int{1, 7, 30}
	rows := make([]trendRow, 0, len(metrics))
	for _, m := range metrics {
		row := trendRow{Label: m.label}
		for _, h := range horizons {
			if window, ok := deltas[h]; ok {
				d := window[m.key]
				row.Cells = append(row.Cells, trendCell{Has: d.Has, Delta: d.Delta})
			} else {
				row.Cells = append(row.Cells, trendCell{})
			}
		}
		rows = append(rows, row)
	}
	return rows
}

// handleAdminScans renders scan-job health.
func (s *Server) handleAdminScans(w http.ResponseWriter, r *http.Request) {
	user := middleware.UserFromContext(r.Context())
	auditLog("view_scans", user, r.URL.Path, r.RemoteAddr, "")
	ctx := r.Context()

	runs, err := s.store.AdminRecentScanRuns(ctx, adminScanRunsMax)
	if err != nil {
		slog.Error("admin scan runs", "error", err)
		http.Error(w, "failed to load scans", http.StatusInternalServerError)
		return
	}
	freshness, err := s.store.AdminScannerDBFreshness(ctx)
	if err != nil {
		slog.Error("admin scanner freshness", "error", err)
		http.Error(w, "failed to load scans", http.StatusInternalServerError)
		return
	}
	backlog, err := s.store.AdminScanBacklog(ctx, config.ScanMaxAge(), scanner.DefaultRegistry().Names())
	if err != nil {
		slog.Error("admin scan backlog", "error", err)
		http.Error(w, "failed to load scans", http.StatusInternalServerError)
		return
	}
	rows, err := s.store.AdminRecentFailures(ctx, r.URL.Query().Get("scanner"), adminFailuresMax)
	if err != nil {
		slog.Error("admin failures", "error", err)
		http.Error(w, "failed to load scans", http.StatusInternalServerError)
		return
	}
	// Split real errors from the informational zero-findings tripwire so the page
	// can present them differently (red failures vs a calmer warnings section).
	var failures, warnings []postgres.AdminFailure
	for _, f := range rows {
		if f.IsWarning() {
			warnings = append(warnings, f)
		} else {
			failures = append(failures, f)
		}
	}

	render(w, "admin_scans.html", s.adminBase(user, "scans", map[string]any{
		"Title":     "Admin — Scans",
		"CSRFToken": issueCSRF(w),
		"Runs":      runs,
		"Freshness": freshness,
		"Backlog":   backlog,
		"Failures":  failures,
		"Warnings":  warnings,
		"Msg":       r.URL.Query().Get("msg"),
	}))
}

// handleAdminScanHistory returns hourly scan/finding buckets as JSON.
func (s *Server) handleAdminScanHistory(w http.ResponseWriter, r *http.Request) {
	hours := clampInt(r.URL.Query().Get("hours"), 24, adminHistoryMax)
	points, err := s.store.AdminScanHistory(r.Context(), hours)
	if err != nil {
		slog.Error("admin scan history", "error", err)
		http.Error(w, "failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, points)
}

// handleAdminTenants renders the searchable, paginated tenant list.
func (s *Server) handleAdminTenants(w http.ResponseWriter, r *http.Request) {
	user := middleware.UserFromContext(r.Context())
	auditLog("view_tenants", user, r.URL.Path, r.RemoteAddr, "")

	query := r.URL.Query().Get("q")
	page := clampInt(r.URL.Query().Get("page"), 1, 1<<20)
	offset := (page - 1) * adminPageSize

	tenants, total, err := tenant.AdminListTenantsWithStats(r.Context(), s.store.DB(), query, adminPageSize, offset)
	if err != nil {
		slog.Error("admin list tenants", "error", err)
		http.Error(w, "failed to list tenants", http.StatusInternalServerError)
		return
	}
	totalPages := (total + adminPageSize - 1) / adminPageSize

	render(w, "admin_tenants.html", s.adminBase(user, "tenants", map[string]any{
		"Title":      "Admin — Tenants",
		"CSRFToken":  issueCSRF(w),
		"Tenants":    tenants,
		"Query":      query,
		"Page":       page,
		"TotalPages": totalPages,
		"Total":      total,
		"HasPrev":    page > 1,
		"HasNext":    page < totalPages,
		"PrevPage":   page - 1,
		"NextPage":   page + 1,
		"Plans":      tenant.Plans,
		"Msg":        r.URL.Query().Get("msg"),
	}))
}

// handleAdminTenantDetail renders one tenant with its activity rollup, tokens,
// and management forms.
func (s *Server) handleAdminTenantDetail(w http.ResponseWriter, r *http.Request) {
	user := middleware.UserFromContext(r.Context())
	id := r.PathValue("id")
	auditLog("view_tenant", user, r.URL.Path, r.RemoteAddr, "account_id="+id)

	target, err := tenant.GetTenant(r.Context(), s.store.DB(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	summary, err := s.store.AdminTenantSBOMSummary(r.Context(), id)
	if err != nil {
		slog.Error("admin tenant summary", "error", err)
		http.Error(w, "failed to load tenant", http.StatusInternalServerError)
		return
	}
	tokens, err := tenant.ListAPITokens(r.Context(), s.store.DB(), id)
	if err != nil {
		slog.Error("admin tenant tokens", "error", err)
		http.Error(w, "failed to load tenant", http.StatusInternalServerError)
		return
	}

	render(w, "admin_tenant.html", s.adminBase(user, "tenants", map[string]any{
		"Title":      "Admin — " + target.Email,
		"CSRFToken":  issueCSRF(w),
		"T":          target,
		"Summary":    summary,
		"Tokens":     tokens,
		"Plans":      tenant.Plans,
		"Statuses":   []string{tenant.StatusActive, tenant.StatusSuspended},
		"Severities": []string{"critical", "high", "medium", "low", "negligible"},
		"Msg":        r.URL.Query().Get("msg"),
	}))
}

// ── Mutations (CSRF-wrapped at the route; each audited + POST-redirect-GET) ─────

func (s *Server) handleAdminSetPlan(w http.ResponseWriter, r *http.Request) {
	user := middleware.UserFromContext(r.Context())
	id := r.PathValue("id")
	plan := r.FormValue("plan")
	dest := "/admin/tenant/" + id
	if !tenant.ValidPlan(plan) {
		http.Redirect(w, r, dest+"?msg=invalid_plan", http.StatusSeeOther)
		return
	}
	if err := tenant.SetPlan(r.Context(), s.store.DB(), id, plan); err != nil {
		slog.Error("admin set plan", "account_id", id, "error", err)
		http.Redirect(w, r, dest+"?msg=error", http.StatusSeeOther)
		return
	}
	auditLog("set_plan", user, r.URL.Path, r.RemoteAddr, "account_id="+id+" plan="+plan)
	http.Redirect(w, r, dest+"?msg=plan_updated", http.StatusSeeOther)
}

func (s *Server) handleAdminSetStatus(w http.ResponseWriter, r *http.Request) {
	user := middleware.UserFromContext(r.Context())
	id := r.PathValue("id")
	status := r.FormValue("status")
	dest := "/admin/tenant/" + id
	if status != tenant.StatusActive && status != tenant.StatusSuspended {
		http.Redirect(w, r, dest+"?msg=invalid_status", http.StatusSeeOther)
		return
	}
	if err := tenant.SetStatus(r.Context(), s.store.DB(), id, status); err != nil {
		slog.Error("admin set status", "account_id", id, "error", err)
		http.Redirect(w, r, dest+"?msg=error", http.StatusSeeOther)
		return
	}
	auditLog("set_status", user, r.URL.Path, r.RemoteAddr, "account_id="+id+" status="+status)
	http.Redirect(w, r, dest+"?msg=status_updated", http.StatusSeeOther)
}

func (s *Server) handleAdminSetMinSeverity(w http.ResponseWriter, r *http.Request) {
	user := middleware.UserFromContext(r.Context())
	id := r.PathValue("id")
	sev := r.FormValue("min_severity")
	dest := "/admin/tenant/" + id
	if !data.ValidMinSeverity(sev) {
		logMutationDenied(r, "account.min_severity.update", "invalid severity")
		http.Redirect(w, r, dest+"?msg=invalid_severity", http.StatusSeeOther)
		return
	}
	if err := s.store.SetMinSeverityAudited(r.Context(), id, sev,
		middleware.ActorFromContext(r.Context()), middleware.RequestIDFromContext(r.Context())); err != nil {
		logMutationFailure(r, "account.min_severity.update", id, id, err)
		slog.Error("admin set min_severity", "account_id", id, "error", err)
		http.Redirect(w, r, dest+"?msg=error", http.StatusSeeOther)
		return
	}
	auditLog("set_min_severity", user, r.URL.Path, r.RemoteAddr, "account_id="+id+" min_severity="+sev)
	http.Redirect(w, r, dest+"?msg=severity_updated", http.StatusSeeOther)
}

func (s *Server) handleAdminDeleteTenant(w http.ResponseWriter, r *http.Request) {
	user := middleware.UserFromContext(r.Context())
	id := r.PathValue("id")
	if err := tenant.DeleteTenant(r.Context(), s.store.DB(), id); err != nil {
		slog.Error("admin delete tenant", "account_id", id, "error", err)
		http.Redirect(w, r, "/admin/tenant/"+id+"?msg=error", http.StatusSeeOther)
		return
	}
	auditLog("delete_tenant", user, r.URL.Path, r.RemoteAddr, "account_id="+id)
	http.Redirect(w, r, "/admin/tenants?msg=tenant_deleted", http.StatusSeeOther)
}

func (s *Server) handleAdminRevokeToken(w http.ResponseWriter, r *http.Request) {
	user := middleware.UserFromContext(r.Context())
	id := r.PathValue("id")
	tid := r.PathValue("tid")
	dest := "/admin/tenant/" + id
	if err := s.store.RevokeAPITokenAudited(r.Context(), id, tid,
		middleware.ActorFromContext(r.Context()), middleware.RequestIDFromContext(r.Context())); err != nil {
		logMutationFailure(r, "api_token.revoke", id, tid, err)
		slog.Error("admin revoke token", "token", tid, "error", err)
		http.Redirect(w, r, dest+"?msg=error", http.StatusSeeOther)
		return
	}
	auditLog("revoke_token", user, r.URL.Path, r.RemoteAddr, "account_id="+id+" token="+tid)
	http.Redirect(w, r, dest+"?msg=token_revoked", http.StatusSeeOther)
}

func (s *Server) handleAdminInvite(w http.ResponseWriter, r *http.Request) {
	user := middleware.UserFromContext(r.Context())
	email := authn.NormalizeEmail(r.FormValue("email"))
	if !looksLikeEmail(email) {
		http.Redirect(w, r, "/admin/tenants?msg=invalid_email", http.StatusSeeOther)
		return
	}
	if _, err := tenant.UpsertTenantByEmail(r.Context(), s.store.DB(), email); err != nil {
		slog.Error("admin invite", "email", email, "error", err)
		http.Redirect(w, r, "/admin/tenants?msg=error", http.StatusSeeOther)
		return
	}
	auditLog("invite_tenant", user, r.URL.Path, r.RemoteAddr, "email="+email)
	http.Redirect(w, r, "/admin/tenants?msg=tenant_invited", http.StatusSeeOther)
}

func (s *Server) handleAdminResetFailure(w http.ResponseWriter, r *http.Request) {
	user := middleware.UserFromContext(r.Context())
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Redirect(w, r, "/admin/scans?msg=error", http.StatusSeeOther)
		return
	}
	if err := s.store.AdminResetFailure(r.Context(), id); err != nil && !errors.Is(err, sql.ErrNoRows) {
		slog.Error("admin reset failure", "id", id, "error", err)
		http.Redirect(w, r, "/admin/scans?msg=error", http.StatusSeeOther)
		return
	}
	auditLog("reset_failure", user, r.URL.Path, r.RemoteAddr, "id="+idStr)
	http.Redirect(w, r, "/admin/scans?msg=failure_reset", http.StatusSeeOther)
}

func (s *Server) handleAdminRescan(w http.ResponseWriter, r *http.Request) {
	user := middleware.UserFromContext(r.Context())
	sbomID := r.PathValue("sbomID")
	if err := s.store.AdminRequestRescan(r.Context(), sbomID); err != nil {
		slog.Error("admin request rescan", "sbom", sbomID, "error", err)
		http.Redirect(w, r, "/admin/scans?msg=error", http.StatusSeeOther)
		return
	}
	auditLog("request_rescan", user, r.URL.Path, r.RemoteAddr, "sbom="+sbomID)
	http.Redirect(w, r, "/admin/scans?msg=rescan_requested", http.StatusSeeOther)
}

// ── helpers ─────────────────────────────────────────────────────────────────

// adminBase seeds the template data map with the fields the admin chrome and
// sub-nav need, then merges the page-specific fields.
func (s *Server) adminBase(user *account.User, active string, extra map[string]any) map[string]any {
	d := map[string]any{
		"SignedIn": true,
		"AdminTab": active,
		"Version":  s.opts.Version,
	}
	if user != nil {
		d["Email"] = user.Email
		d["AvatarURL"] = user.AvatarURL
	}
	maps.Copy(d, extra)
	return d
}

// clampInt parses s as an int and clamps it to [1, maxV], falling back to def.
// The lower bound is always 1 (every caller is a 1-based page/window count), so
// it isn't a parameter.
func clampInt(s string, def, maxV int) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	if n < 1 {
		return 1
	}
	if n > maxV {
		return maxV
	}
	return n
}
