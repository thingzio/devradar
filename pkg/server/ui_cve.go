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
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/thingzio/devradar/pkg/data"
	"github.com/thingzio/devradar/pkg/data/postgres"
	"github.com/thingzio/devradar/pkg/middleware"
	"github.com/thingzio/devradar/pkg/vex"
)

type cveListRow struct {
	CVE           string
	WorstSev      string
	ImageCount    int
	FindingCount  int
	KEV           bool
	EPSS          string // "94%" or ""
	Fixable       bool
	Repositories  []string
	VEXStatus     string
	Justification string
	Impact        string
	Suppressed    bool
	AllVEXd       bool // every occurrence VEX'd (dim the row); false = partial
}

// justifications is the OpenVEX justification enum, offered as filter options.
var justifications = []string{
	"component_not_present",
	"vulnerable_code_not_present",
	"vulnerable_code_not_in_execute_path",
	"vulnerable_code_cannot_be_controlled_by_adversary",
	"inline_mitigations_already_exist",
}

type cveListView struct {
	chromeView
	CSRFToken   string // double-submit token for the VEX-upload form
	MinSeverity string
	Sort        string
	Dir         string
	NextCursor  string
	CVEs        []cveListRow
	HasData     bool
	// Filters (echoed back to keep the controls sticky).
	FVex           string
	FJust          string
	FKEV           bool
	FFixable       bool
	Justifications []string
	// Flash summary after a VEX upload (optional).
	UploadMsg string
	UploadErr string
}

// handleCVEList renders the fleet-wide CVE list (blast radius): every
// vulnerability across the tenant's images, ranked KEV-first then severity then
// reach by default. VEX'd CVEs are shown (annotated + de-emphasized). Sortable,
// filterable (VEX status/justification/KEV/fixable), paginated.
func (s *Server) handleCVEList(w http.ResponseWriter, r *http.Request) {
	access := middleware.AccessFromContext(r.Context())
	min := accountMinSeverity(&access.Account)
	q := r.URL.Query()
	if v := q.Get("min_severity"); v != "" && data.ValidMinSeverity(v) {
		min = v
	}
	filter := postgres.FleetCVEFilter{
		VEXState:      q.Get("vex"),
		Justification: q.Get("just"),
		KEVOnly:       q.Get("kev") == "true",
		FixableOnly:   q.Get("fixable") == "true",
	}
	cves, next, err := s.store.FleetCVEs(r.Context(), access.Account.ID, min, filter, q.Get("sort"), q.Get("dir"), q.Get("cursor"), 100)
	if err != nil {
		http.Error(w, "failed to load CVEs", http.StatusInternalServerError)
		return
	}
	v := cveListView{
		chromeView:  s.chrome(access, "CVEs", "cves"),
		CSRFToken:   issueCSRF(w),
		MinSeverity: min, Sort: q.Get("sort"), Dir: q.Get("dir"), NextCursor: next, HasData: len(cves) > 0,
		FVex: filter.VEXState, FJust: filter.Justification, FKEV: filter.KEVOnly, FFixable: filter.FixableOnly,
		Justifications: justifications,
		UploadMsg:      q.Get("uploaded"), UploadErr: q.Get("upload_err"),
	}
	for _, c := range cves {
		v.CVEs = append(v.CVEs, cveListRow{
			CVE: c.CVE, WorstSev: c.WorstSev, ImageCount: c.ImageCount,
			FindingCount: c.FindingCount, KEV: c.KEV, EPSS: formatEPSS(c.EPSS),
			Fixable: c.Fixable, Repositories: c.Repositories,
			VEXStatus: c.VEXStatus, Justification: c.Justification, Impact: c.Impact,
			Suppressed: c.Suppressed, AllVEXd: c.AllVEXd,
		})
	}
	render(w, "cves.html", v)
}

type cveOccRow struct {
	Repository string
	SBOMID     string
	ShortDig   string
	Version    string
	Package    string
	PkgVersion string
	Severity   string
	Score      string
	IsFixed    bool
	Scanner    string
}

type cveDetailView struct {
	chromeView
	CVE         string
	KEV         bool
	KEVAdded    string
	EPSS        string
	ImageCount  int
	Occurrences []cveOccRow
}

// handleCVEDetail shows one CVE's enrichment context and every image/version it
// affects across the tenant.
func (s *Server) handleCVEDetail(w http.ResponseWriter, r *http.Request) {
	access := middleware.AccessFromContext(r.Context())
	cve := r.PathValue("cve")
	d, err := s.store.CVEDetail(r.Context(), access.Account.ID, cve)
	if err != nil {
		if errors.Is(err, postgres.ErrNotFound) {
			http.Error(w, "CVE not found in your images", http.StatusNotFound)
			return
		}
		http.Error(w, "failed to load CVE", http.StatusInternalServerError)
		return
	}
	v := cveDetailView{
		chromeView: s.chrome(access, cve, "cves"),
		CVE:        cve, KEV: d.KEV, KEVAdded: d.KEVAdded, EPSS: formatEPSS(d.EPSS),
	}
	repos := map[string]struct{}{}
	for _, o := range d.Occurrences {
		repos[o.Repository] = struct{}{}
		v.Occurrences = append(v.Occurrences, cveOccRow{
			Repository: o.Repository, SBOMID: o.SBOMID, ShortDig: shortDigest(o.Digest),
			Version: o.Version, Package: o.Package, PkgVersion: o.PkgVersion,
			Severity: o.Severity, Score: formatScore(o.Score), IsFixed: o.IsFixed, Scanner: o.Scanner,
		})
	}
	v.ImageCount = len(repos)
	render(w, "cve.html", v)
}

// handleUploadVEX handles a browser VEX upload from the CVEs tab (multipart file
// field "vex"). It reuses the same parse + persist path as the API, then
// redirects back to /cves with a result summary in the query string.
func (s *Server) handleUploadVEX(w http.ResponseWriter, r *http.Request) {
	access := middleware.AccessFromContext(r.Context())
	// Bound the whole request body BEFORE parsing. ParseMultipartForm's argument
	// is only the in-memory threshold — larger parts stream to a temp file with no
	// ceiling — so without this an authenticated user could exhaust container disk.
	r.Body = http.MaxBytesReader(w, r.Body, maxVEXBytes+4096) // headroom for multipart framing
	if err := r.ParseMultipartForm(maxVEXBytes + 1024); err != nil {
		logMutationDenied(r, "vex.save", "invalid multipart body")
		http.Redirect(w, r, "/cves?upload_err="+url.QueryEscape("file too large or unreadable"), http.StatusSeeOther)
		return
	}
	// CSRF: this multipart route can't use the ValidateCSRF middleware (its 4KB
	// body cap would truncate the upload), so validate the double-submit token
	// against the parsed form here, after ParseMultipartForm.
	if !middleware.CheckCSRF(r) {
		logMutationDenied(r, "vex.save", "invalid csrf")
		http.Error(w, "Forbidden: invalid or missing CSRF token", http.StatusForbidden)
		return
	}
	file, _, err := r.FormFile("vex")
	if err != nil {
		logMutationDenied(r, "vex.save", "missing file")
		http.Redirect(w, r, "/cves?upload_err="+url.QueryEscape("no file selected"), http.StatusSeeOther)
		return
	}
	defer func() { _ = file.Close() }()
	body, err := io.ReadAll(io.LimitReader(file, maxVEXBytes+1))
	if err != nil || len(body) == 0 {
		logMutationDenied(r, "vex.save", "empty or unreadable file")
		http.Redirect(w, r, "/cves?upload_err="+url.QueryEscape("empty or unreadable file"), http.StatusSeeOther)
		return
	}
	if len(body) > maxVEXBytes {
		logMutationDenied(r, "vex.save", "document too large")
		http.Redirect(w, r, "/cves?upload_err="+url.QueryEscape("file too large"), http.StatusSeeOther)
		return
	}
	doc, err := vex.Parse(body)
	if err != nil {
		logMutationDenied(r, "vex.save", "invalid document")
		http.Redirect(w, r, "/cves?upload_err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	_, matched, err := s.store.SaveVEXDocumentAudited(r.Context(), access.Account.ID, doc,
		middleware.ActorFromContext(r.Context()), middleware.RequestIDFromContext(r.Context()))
	if err != nil {
		logMutationFailure(r, "vex.save", access.Account.ID, "", err)
		http.Redirect(w, r, "/cves?upload_err="+url.QueryEscape("failed to store VEX"), http.StatusSeeOther)
		return
	}
	msg := fmt.Sprintf("%d statement(s) parsed, %d matched your images", len(doc.Statements), matched)
	http.Redirect(w, r, "/cves?uploaded="+url.QueryEscape(msg), http.StatusSeeOther)
}
