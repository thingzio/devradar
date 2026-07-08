package server

import (
	"html/template"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/thingzio/devradar/pkg/middleware"
)

// cvePattern recognizes a CVE id so the unified search can route CVE lookups to
// the CVE view and everything else to an image search.
var cvePattern = regexp.MustCompile(`(?i)^CVE-\d{4}-\d{4,}$`)

type overviewView struct {
	Title    string
	SignedIn bool
	Tab      string
	Email    string
	Version  string
	// Fleet headline stats.
	ImageCount int
	TotalCount int
	CriticalCT int
	HighCT     int
	KEVCount   int
	FixablePct int
	FailureCT  int
	HasData    bool
	ScanStatus string        // e.g. "Last scan 12 min ago" (scan heartbeat)
	SevChart   template.HTML // inline SVG: fleet severity composition (donut)
	RemedChart template.HTML // inline SVG: fixable-now vs open, per severity
	// Top-risk images teaser.
	TopImages []imageRow
}

// handleOverview is the signed-in landing tab: fleet headline stats, a unified
// image/CVE search box, and a short top-risk images teaser. Search routing is
// handled by handleSearch.
func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	tn := middleware.TenantFromContext(r.Context())
	min := tenantMinSeverity(tn)

	fs, err := s.store.FleetStats(r.Context(), tn.ID)
	if err != nil {
		http.Error(w, "failed to load overview", http.StatusInternalServerError)
		return
	}
	// Top 5 images by risk (default sort), no filter.
	images, _, err := s.store.ListRepoImages(r.Context(), tn.ID, min, "", "", "", "", "", 5)
	if err != nil {
		http.Error(w, "failed to load overview", http.StatusInternalServerError)
		return
	}

	v := overviewView{
		Title: "Overview", SignedIn: true, Tab: "overview", Email: tn.Email, Version: s.opts.Version,
		ImageCount: fs.Images, TotalCount: fs.Total, CriticalCT: fs.Critical, HighCT: fs.High,
		KEVCount: fs.KEV, FixablePct: pct(fs.Fixable, fs.Total), FailureCT: fs.Failures,
		HasData:    fs.Total > 0,
		ScanStatus: scanStatus(fs.LastScanAt),
	}
	v.SevChart = donutChart([]slice{
		{Label: "Critical", Value: fs.Critical, Sev: "critical"},
		{Label: "High", Value: fs.High, Sev: "high"},
		{Label: "Medium", Value: fs.Medium, Sev: "medium"},
		{Label: "Low", Value: fs.Low, Sev: "low"},
	}, "findings", 200)
	v.RemedChart = remediationChart([]remedRow{
		{Label: "Critical", Sev: "critical", Fixable: fs.FixCritical, Total: fs.Critical},
		{Label: "High", Sev: "high", Fixable: fs.FixHigh, Total: fs.High},
		{Label: "Medium", Sev: "medium", Fixable: fs.FixMedium, Total: fs.Medium},
		{Label: "Low", Sev: "low", Fixable: fs.FixLow, Total: fs.Low},
	}, 440)
	for _, im := range images {
		row := imageRow{
			Repository: im.Repository, Short: lastPath(im.Repository),
			Critical: im.Counts.Critical, High: im.Counts.High, Medium: im.Counts.Medium,
			Low: im.Counts.Low, Total: im.Counts.Total,
		}
		row.Bar = severityBar(im.Counts)
		v.TopImages = append(v.TopImages, row)
	}
	render(w, "overview.html", v)
}

// handleSearch routes a unified query: a CVE id jumps to that CVE's detail page;
// anything else becomes an image-name filter on the Images tab. Empty → Overview.
func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	switch {
	case q == "":
		http.Redirect(w, r, "/overview", http.StatusSeeOther)
	case cvePattern.MatchString(q):
		http.Redirect(w, r, "/cves/"+strings.ToUpper(q), http.StatusSeeOther)
	default:
		http.Redirect(w, r, "/dashboard?q="+url.QueryEscape(q), http.StatusSeeOther)
	}
}
