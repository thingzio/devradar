// Copyright 2026 Thingz LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/thingzio/devradar/pkg/account"
	"github.com/thingzio/devradar/pkg/authn"
	"github.com/thingzio/devradar/pkg/config"
	"github.com/thingzio/devradar/pkg/data"
	"github.com/thingzio/devradar/pkg/data/postgres"
	"github.com/thingzio/devradar/pkg/middleware"
	"github.com/thingzio/devradar/pkg/scanner"
)

// This file implements the operator admin console (/admin/*). Access is gated by
// middleware.RequirePlatformAdmin (email allowlist, 404-on-deny); mutating routes are
// additionally wrapped in middleware.ValidateCSRF. Every action is audited to the
// log (auditLog). Account-owned mutations that use audited store methods also
// persist attribution. Mutations follow POST-redirect-GET with a ?msg= flash.
// The console is unlinked from the account
// nav and stays hidden.

const (
	adminPageSize    = 10
	adminScanRunsMax = 50
	adminFailuresMax = 50
	adminHistoryMax  = 720 // 30 days of hourly buckets
)

var (
	adminAccountPlans    = []string{"free", "paid"}
	adminAccountStatuses = []string{"active", "suspended"}
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
		{"tenants", "Accounts"},
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

// handleAdminAccounts renders the searchable, paginated account list.
func (s *Server) handleAdminAccounts(w http.ResponseWriter, r *http.Request) {
	user := middleware.UserFromContext(r.Context())
	auditLog("view_accounts", user, r.URL.Path, r.RemoteAddr, "")

	query := r.URL.Query().Get("q")
	page := clampInt(r.URL.Query().Get("page"), 1, 1<<20)
	offset := (page - 1) * adminPageSize

	accounts, total, err := s.store.AdminListAccounts(r.Context(), query, adminPageSize, offset)
	if err != nil {
		slog.Error("admin list accounts", "error", err)
		http.Error(w, "failed to list accounts", http.StatusInternalServerError)
		return
	}
	totalPages := (total + adminPageSize - 1) / adminPageSize

	render(w, "admin_tenants.html", s.adminBase(user, "accounts", map[string]any{
		"Title":      "Admin — Accounts",
		"CSRFToken":  issueCSRF(w),
		"Accounts":   accounts,
		"Query":      query,
		"Page":       page,
		"TotalPages": totalPages,
		"Total":      total,
		"HasPrev":    page > 1,
		"HasNext":    page < totalPages,
		"PrevPage":   page - 1,
		"NextPage":   page + 1,
		"Plans":      adminAccountPlans,
		"Msg":        r.URL.Query().Get("msg"),
	}))
}

// handleAdminAccountDetail renders one account with its activity rollup, members, tokens,
// and management forms.
func (s *Server) handleAdminAccountDetail(w http.ResponseWriter, r *http.Request) {
	user := middleware.UserFromContext(r.Context())
	id := r.PathValue("id")
	auditLog("view_account", user, r.URL.Path, r.RemoteAddr, "account_id="+id)

	target, err := s.store.GetAccount(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	summary, err := s.store.AdminAccountSBOMSummary(r.Context(), id)
	if err != nil {
		slog.Error("admin account summary", "error", err)
		http.Error(w, "failed to load account", http.StatusInternalServerError)
		return
	}
	members, err := s.store.ListMembers(r.Context(), id)
	if err != nil {
		slog.Error("admin account members", "account_id", id, "error", err)
		http.Error(w, "failed to load account", http.StatusInternalServerError)
		return
	}
	tokens, err := s.store.ListAPITokens(r.Context(), id, middleware.ActorFromContext(r.Context()))
	if err != nil {
		slog.Error("admin account tokens", "account_id", id,
			"request_id", middleware.RequestIDFromContext(r.Context()), "error", err)
		http.Error(w, "failed to load account", http.StatusInternalServerError)
		return
	}

	render(w, "admin_tenant.html", s.adminBase(user, "accounts", map[string]any{
		"Title":      "Admin — " + target.Name,
		"CSRFToken":  issueCSRF(w),
		"Account":    target,
		"Summary":    summary,
		"Members":    members,
		"Tokens":     tokens,
		"Plans":      adminAccountPlans,
		"Statuses":   adminAccountStatuses,
		"Severities": []string{"critical", "high", "medium", "low", "negligible"},
		"Msg":        r.URL.Query().Get("msg"),
	}))
}

// ── Mutations (CSRF-wrapped at the route; each audited + POST-redirect-GET) ─────

func (s *Server) handleAdminSetPlan(w http.ResponseWriter, r *http.Request) {
	user := middleware.UserFromContext(r.Context())
	id := r.PathValue("id")
	plan := r.FormValue("plan")
	dest := "/admin/account/" + id
	if !slices.Contains(adminAccountPlans, plan) {
		http.Redirect(w, r, dest+"?msg=invalid_plan", http.StatusSeeOther)
		return
	}
	if err := s.store.AdminSetAccountPlan(r.Context(), id, plan); err != nil {
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
	dest := "/admin/account/" + id
	if !slices.Contains(adminAccountStatuses, status) {
		http.Redirect(w, r, dest+"?msg=invalid_status", http.StatusSeeOther)
		return
	}
	if err := s.store.AdminSetAccountStatus(r.Context(), id, status); err != nil {
		if errors.Is(err, postgres.ErrAccountDeletionInProgress) {
			http.Redirect(w, r, dest+"?msg=deletion_in_progress", http.StatusSeeOther)
			return
		}
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
	dest := "/admin/account/" + id
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

func (s *Server) handleAdminDeleteAccount(w http.ResponseWriter, r *http.Request) {
	user := middleware.UserFromContext(r.Context())
	id := r.PathValue("id")
	actor := account.Actor{Kind: account.ActorPlatform, UserID: user.ID}
	objects, err := s.store.AdminPrepareAccountDeletion(r.Context(), id,
		actor, middleware.RequestIDFromContext(r.Context()))
	if err != nil {
		slog.Error("admin prepare account deletion", "account_id", id, "error", err)
		http.Redirect(w, r, "/admin/account/"+id+"?msg=cleanup_failed", http.StatusSeeOther)
		return
	}
	for _, object := range objects {
		if err := s.blobs.Delete(r.Context(), object.ObjectPath); err != nil {
			slog.Error("admin delete account object", "account_id", id,
				"sbom_id", object.SBOMID, "object_path", object.ObjectPath, "error", err)
			http.Redirect(w, r, "/admin/account/"+id+"?msg=cleanup_failed", http.StatusSeeOther)
			return
		}
		if err := s.store.AdminDeleteAccountSBOM(r.Context(), id, object.SBOMID); err != nil && !errors.Is(err, postgres.ErrNotFound) {
			slog.Error("admin commit account object deletion", "account_id", id,
				"sbom_id", object.SBOMID, "object_path", object.ObjectPath, "error", err)
			http.Redirect(w, r, "/admin/account/"+id+"?msg=cleanup_failed", http.StatusSeeOther)
			return
		}
	}
	if err := s.store.AdminFinalizeAccountDeletion(r.Context(), id); err != nil {
		if errors.Is(err, postgres.ErrAccountDeletionIncomplete) {
			http.Redirect(w, r, "/admin/account/"+id+"?msg=cleanup_in_progress", http.StatusSeeOther)
			return
		}
		slog.Error("admin finalize account deletion", "account_id", id, "error", err)
		http.Redirect(w, r, "/admin/account/"+id+"?msg=cleanup_failed", http.StatusSeeOther)
		return
	}
	auditLog("delete_account", user, r.URL.Path, r.RemoteAddr, "account_id="+id)
	http.Redirect(w, r, "/admin/accounts?msg=account_deleted", http.StatusSeeOther)
}

func (s *Server) handleAdminRevokeToken(w http.ResponseWriter, r *http.Request) {
	user := middleware.UserFromContext(r.Context())
	id := r.PathValue("id")
	tid := r.PathValue("tid")
	dest := "/admin/account/" + id
	if err := s.store.RevokeAPIToken(r.Context(), id, tid,
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
		http.Redirect(w, r, "/admin/accounts?msg=invalid_email", http.StatusSeeOther)
		return
	}
	if err := s.sendMagicLink(r.Context(), email); err != nil {
		slog.Error("admin invite", "email", email, "error", err)
		http.Redirect(w, r, "/admin/accounts?msg=error", http.StatusSeeOther)
		return
	}
	auditLog("send_signup_link", user, r.URL.Path, r.RemoteAddr, "email="+email)
	http.Redirect(w, r, "/admin/accounts?msg=signup_sent", http.StatusSeeOther)
}

func redirectAdminAccounts(w http.ResponseWriter, r *http.Request) {
	destination := "/admin/accounts"
	if r.URL.RawQuery != "" {
		destination += "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, destination, http.StatusMovedPermanently)
}

func redirectAdminAccount(w http.ResponseWriter, r *http.Request) {
	destination := "/admin/account/" + r.PathValue("id")
	if r.URL.RawQuery != "" {
		destination += "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, destination, http.StatusMovedPermanently)
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
		"Commit":   s.opts.Commit,
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
