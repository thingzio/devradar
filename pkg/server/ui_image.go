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
	"errors"
	"html/template"
	"net/http"
	"strings"

	"github.com/thingzio/devradar/pkg/data"
	"github.com/thingzio/devradar/pkg/data/postgres"
	"github.com/thingzio/devradar/pkg/middleware"
)

// sbomRow is one submitted SBOM (version/digest) of an image.
type sbomRow struct {
	SBOMID       string
	ShortDigest  string
	Version      string
	Tool         string
	PackageCount int
	GeneratedAt  string
	FromDefault  bool
	ToDefault    bool
}

// eventRow is one change-log entry, pre-formatted for display.
type eventRow struct {
	When        string
	EventType   string // added | resolved | rerated | fixed
	Cause       string // image | db | tooling
	CauseLabel  string
	Exposure    string
	Package     string
	Severity    string
	ShortDigest string
	Scanner     string
}

type imageDetailView struct {
	chromeView
	MinSeverity string
	CSRFToken   string // double-submit token for the archive form

	Repository  string
	Short       string
	Versions    []string
	Labels      []string
	SBOMCount   int
	DigestCount int

	SBOMs          []sbomRow
	CanCompare     bool
	Events         []eventRow
	NextCursor     string        // for the change log
	SBOMNextCursor string        // for the versions/SBOMs list
	SBOMSort       string        // active SBOM-list sort key
	SBOMDir        string        // active SBOM-list direction
	EvSort         string        // active change-log sort key
	EvDir          string        // active change-log direction
	IncludeUnrated bool          // change log: show unrated (unknown) rows too
	SevChart       template.HTML // inline SVG: severity composition over scans
	HasEvents      bool

	// Scan issues: why a scanner errored or returned nothing, so "scan issue" on
	// the dashboard is explainable rather than mysterious.
	Failures    []failureRow
	HasFailures bool

	// License inventory for this image's SBOMs (per-package, policy-evaluated),
	// filterable / sortable / paged.
	Packages          []packageRow
	LicenseViolations int // repo-wide, independent of the active filter/page
	PackageTotal      int // count matching the active filters (for the pager)
	PackageShown      int // rows on this page
	HasPackages       bool
	PkgQuery          string // active package-name filter
	PkgCategory       string // active category filter ("" = all)
	PkgCategories     []string
	PkgSort           string
	PkgDir            string
	PkgPage           int
	PkgHasPrev        bool
	PkgHasNext        bool
	PkgPrevPage       int
	PkgNextPage       int
	PkgRangeLo        int // 1-based index of first row on this page
	PkgRangeHi        int // 1-based index of last row on this page
}

// packageRow is one catalogued package with its license classification + policy
// verdict, for the per-image license table. (failureRow is shared with ui_sbom.go.)
type packageRow struct {
	Package   string
	Version   string
	Licenses  string // joined for display
	Category  string
	Violation bool
	Reason    string
}

// handleImageDetail renders one image (CUJ-2 + CUJ-3): its versions/SBOMs list
// and the cross-digest change log. The repository is a ?repo= query param
// (repositories contain slashes, so it can't be a path wildcard).
func (s *Server) handleImageDetail(w http.ResponseWriter, r *http.Request) {
	access := middleware.AccessFromContext(r.Context())
	repo := r.URL.Query().Get("repo")
	if repo == "" {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	min := accountMinSeverity(&access.Account)
	if q := r.URL.Query().Get("min_severity"); q != "" && data.ValidMinSeverity(q) {
		min = q
	}

	// SBOMs for the image (newest generation first by default), paginated
	// independently of the change log via its own cursor param. ErrNotFound ⇒
	// unknown image.
	sbomSort, sbomDir := r.URL.Query().Get("sbom_sort"), r.URL.Query().Get("sbom_dir")
	sboms, sbomNext, err := s.store.SBOMsForRepo(r.Context(), access.Account.ID, repo,
		sbomSort, sbomDir, r.URL.Query().Get("sbom_cursor"), 50)
	if err != nil {
		if errors.Is(err, postgres.ErrNotFound) {
			http.Error(w, "image not found", http.StatusNotFound)
			return
		}
		http.Error(w, "failed to load image", http.StatusInternalServerError)
		return
	}

	// Cross-digest change log, severity-filtered, sortable, paginated (its own
	// param prefix so it doesn't collide with the SBOMs table on this page).
	// The change-log filter is EXACT by default (unrated rows don't leak in, which
	// made the dropdown look inert); ?unrated=1 opts them back in.
	includeUnrated := r.URL.Query().Get("unrated") == "1"
	evSort, evDir := r.URL.Query().Get("ev_sort"), r.URL.Query().Get("ev_dir")
	events, next, err := s.store.RepoTimeline(r.Context(), access.Account.ID, repo, min, includeUnrated,
		evSort, evDir, r.URL.Query().Get("cursor"), 50)
	if err != nil {
		http.Error(w, "failed to load change log", http.StatusInternalServerError)
		return
	}

	// Severity-over-time from scan runs, rendered as a stacked column chart.
	sevpts, _ := s.store.RepoSeverityTimeline(r.Context(), access.Account.ID, repo, 60)
	var points []stackPoint
	for _, p := range sevpts {
		points = append(points, stackPoint{Label: p.Day, Segs: []stackSeg{
			{Sev: "critical", N: p.Critical}, {Sev: "high", N: p.High},
			{Sev: "medium", N: p.Medium}, {Sev: "low", N: p.Low},
		}})
	}

	// Authoritative header totals (independent of SBOM-list paging).
	sum, err := s.store.RepoSummary(r.Context(), access.Account.ID, repo)
	if err != nil {
		if errors.Is(err, postgres.ErrNotFound) {
			http.Error(w, "image not found", http.StatusNotFound)
			return
		}
		http.Error(w, "failed to load image", http.StatusInternalServerError)
		return
	}

	// Scan issues for this image, so the dashboard's "scan issue" flag is
	// explainable here. Best-effort — a failure to load failures shouldn't 500 the
	// page.
	failures, _ := s.store.FailuresByRepo(r.Context(), access.Account.ID, repo, 50)

	// License inventory for this image, classified + evaluated against the tenant
	// policy. Best-effort (licenses are additive). Filterable by name/category,
	// sortable, and paged (violations-first by default) so a large image (a
	// Node/Python base can catalog thousands of packages) stays navigable.
	const pkgPageSize = 50
	pkgQuery := r.URL.Query().Get("pkg_q")
	pkgCategory := r.URL.Query().Get("pkg_cat")
	if pkgCategory != "" && !data.ValidLicenseCategory(pkgCategory) {
		pkgCategory = ""
	}
	pkgSort := r.URL.Query().Get("pkg_sort")
	pkgDir := r.URL.Query().Get("pkg_dir")
	pkgPage := clampInt(r.URL.Query().Get("pkg_page"), 1, 1<<20)
	policy, _ := s.store.GetLicensePolicy(r.Context(), access.Account.ID)
	pkgs, pkgTotal, pkgViolations, _ := s.store.PackagesByRepo(r.Context(), access.Account.ID, repo, policy,
		postgres.RepoPackageQuery{
			NameFilter: pkgQuery, Category: pkgCategory, Sort: pkgSort, Dir: pkgDir,
			Offset: (pkgPage - 1) * pkgPageSize, Limit: pkgPageSize,
		})
	pkgTotalPages := (pkgTotal + pkgPageSize - 1) / pkgPageSize

	v := imageDetailView{
		chromeView:        s.chrome(access, lastPath(repo), "images"),
		MinSeverity:       min,
		CSRFToken:         issueCSRF(w),
		Repository:        repo,
		Short:             lastPath(repo),
		Versions:          sum.Versions,
		Labels:            sum.Labels,
		SBOMCount:         sum.SBOMCount,
		DigestCount:       sum.DigestCount,
		NextCursor:        next,
		SBOMNextCursor:    sbomNext,
		SBOMSort:          sbomSort,
		SBOMDir:           sbomDir,
		EvSort:            evSort,
		EvDir:             evDir,
		IncludeUnrated:    includeUnrated,
		SevChart:          stackedTimeSeries(points, 720),
		HasEvents:         len(events) > 0,
		HasFailures:       len(failures) > 0,
		HasPackages:       pkgTotal > 0 || pkgQuery != "" || pkgCategory != "",
		LicenseViolations: pkgViolations,
		PackageTotal:      pkgTotal,
		PackageShown:      len(pkgs),
		PkgQuery:          pkgQuery,
		PkgCategory:       pkgCategory,
		PkgSort:           pkgSort,
		PkgDir:            pkgDir,
		PkgPage:           pkgPage,
		PkgHasPrev:        pkgPage > 1,
		PkgHasNext:        pkgPage < pkgTotalPages,
		PkgPrevPage:       pkgPage - 1,
		PkgNextPage:       pkgPage + 1,
	}
	for _, c := range data.ValidLicenseCategories {
		v.PkgCategories = append(v.PkgCategories, string(c))
	}
	if pkgTotal > 0 {
		v.PkgRangeLo = (pkgPage-1)*pkgPageSize + 1
		v.PkgRangeHi = v.PkgRangeLo + len(pkgs) - 1
	}

	for _, f := range failures {
		v.Failures = append(v.Failures, failureRow{
			When:    f.OccurredAt.Format("2006-01-02 15:04"),
			Scanner: f.Scanner,
			Stage:   f.Stage,
			Error:   f.Error,
		})
	}

	for _, p := range pkgs {
		v.Packages = append(v.Packages, packageRow{
			Package:   p.Package,
			Version:   p.Version,
			Licenses:  strings.Join(p.Licenses, ", "),
			Category:  p.Category,
			Violation: p.Violation,
			Reason:    p.Reason,
		})
	}

	for _, sb := range sboms {
		v.SBOMs = append(v.SBOMs, sbomRow{
			SBOMID:       sb.SBOMID,
			ShortDigest:  shortDigest(sb.Digest),
			Version:      sb.Version,
			Tool:         sb.Tool,
			PackageCount: sb.PackageCount,
			GeneratedAt:  sb.EffectiveAt.Format("2006-01-02 15:04"),
		})
	}
	v.CanCompare = len(v.SBOMs) > 1
	if v.CanCompare {
		v.SBOMs[0].ToDefault = true
		v.SBOMs[len(v.SBOMs)-1].FromDefault = true
	}

	for _, e := range events {
		v.Events = append(v.Events, eventRow{
			When:        e.OccurredAt.Format("2006-01-02 15:04"),
			EventType:   e.EventType,
			Cause:       e.Cause,
			CauseLabel:  causeLabel(e.Cause),
			Exposure:    e.Exposure,
			Package:     e.Package,
			Severity:    e.Severity,
			ShortDigest: shortDigest(e.Digest),
			Scanner:     e.Scanner,
		})
	}

	render(w, "image.html", v)
}

// causeLabel explains an event's cause in plain terms — the "clean causality"
// payoff surfaced in the UI.
func causeLabel(cause string) string {
	switch cause {
	case "image":
		return "new image"
	case "db":
		return "new CVE data"
	case "tooling":
		return "scanner change"
	default:
		return cause
	}
}

// shortDigest trims "sha256:abcdef…" to a readable prefix.
func shortDigest(d string) string {
	d = strings.TrimPrefix(d, "sha256:")
	if len(d) > 12 {
		return d[:12]
	}
	return d
}
