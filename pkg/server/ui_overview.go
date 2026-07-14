package server

import (
	"context"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/thingzio/devradar/pkg/data"
	"github.com/thingzio/devradar/pkg/data/postgres"
	"github.com/thingzio/devradar/pkg/middleware"
)

// cvePattern recognizes a CVE id so the unified search can route CVE lookups to
// the CVE view and everything else to an image search.
var cvePattern = regexp.MustCompile(`(?i)^CVE-\d{4}-\d{4,}$`)

type overviewTrendSignal struct {
	Empty       bool
	HasData     bool
	HasPrevious bool
	Date        string
	Total       int
	Delta       int
	Comparison  string
	Change      string
}

type overviewLicenseSignal struct {
	Configured bool
	Violations int
	Packages   int
}

type overviewLicenseReader interface {
	GetLicensePolicy(context.Context, string) (data.LicensePolicy, error)
	FleetLicenseStats(context.Context, string, data.LicensePolicy) (postgres.FleetLicenseStats, error)
}

type overviewView struct {
	chromeView
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
	TopImages             []imageRow
	Alerts                []alertRow
	AlertsUnavailable     bool
	WorkItems             []workRow
	WorkUnavailable       bool
	Trend                 overviewTrendSignal
	TrendUnavailable      bool
	License               overviewLicenseSignal
	LicenseUnavailable    bool
	ComparisonReady       int
	ComparisonUnavailable bool
}

// handleOverview is the signed-in landing tab: fleet headline stats, a unified
// image/CVE search box, and a short top-risk images teaser. Search routing is
// handled by handleSearch.
func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	access := middleware.AccessFromContext(r.Context())
	min := accountMinSeverity(&access.Account)

	fs, err := s.store.FleetStats(r.Context(), access.Account.ID)
	if err != nil {
		http.Error(w, "failed to load overview", http.StatusInternalServerError)
		return
	}
	// Top 5 images by risk (default sort), no filter.
	images, _, err := s.store.ListRepoImages(r.Context(), access.Account.ID, min, "", "", "", "", "", 5)
	if err != nil {
		http.Error(w, "failed to load overview", http.StatusInternalServerError)
		return
	}

	v := overviewView{
		chromeView: s.chrome(access, "Overview", "overview"),
		ImageCount: fs.Images, TotalCount: fs.Total, CriticalCT: fs.Critical, HighCT: fs.High,
		KEVCount: fs.KEV, FixablePct: pct(fs.Fixable, fs.Total), FailureCT: fs.Failures,
		HasData:    fs.Images > 0,
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
	alerts, err := s.store.UnreadAlerts(r.Context(), access.Account.ID, 5)
	if err != nil {
		slog.Warn("load overview alerts", "account_id", access.Account.ID, "error", err)
		v.AlertsUnavailable = true
	} else {
		for _, item := range alerts {
			v.Alerts = append(v.Alerts, makeAlertRow(item))
		}
	}

	work, _, err := s.store.FleetCVEs(r.Context(), access.Account.ID, min,
		postgres.FleetCVEFilter{}, "risk", "desc", "", 3)
	if err != nil {
		slog.Warn("load overview work", "account_id", access.Account.ID, "error", err)
		v.WorkUnavailable = true
	} else {
		v.WorkItems = workRows(work)
	}

	points, err := s.store.TenantPostureTrend(r.Context(), access.Account.ID, 30)
	if err != nil {
		slog.Warn("load overview trend", "account_id", access.Account.ID, "error", err)
		v.TrendUnavailable = true
	} else {
		v.Trend = overviewTrend(points)
	}

	v.License, err = loadOverviewLicense(r.Context(), s.store, access.Account.ID)
	if err != nil {
		slog.Warn("load overview license signal", "account_id", access.Account.ID, "error", err)
		v.LicenseUnavailable = true
	}

	v.ComparisonReady, err = s.store.ComparisonReadyRepositoryCount(r.Context(), access.Account.ID)
	if err != nil {
		slog.Warn("load overview comparison readiness", "account_id", access.Account.ID, "error", err)
		v.ComparisonUnavailable = true
	}
	render(w, "overview.html", v)
}

func loadOverviewLicense(ctx context.Context, reader overviewLicenseReader, tenantID string) (overviewLicenseSignal, error) {
	policy, err := reader.GetLicensePolicy(ctx, tenantID)
	if err != nil {
		return overviewLicenseSignal{}, err
	}
	if policy.IsEmpty() {
		return overviewLicenseSignal{}, nil
	}
	stats, err := reader.FleetLicenseStats(ctx, tenantID, policy)
	if err != nil {
		return overviewLicenseSignal{}, err
	}
	return overviewLicenseSignal{Configured: true, Violations: stats.Violations, Packages: stats.Packages}, nil
}

func overviewTrend(points []postgres.TenantPosturePoint) overviewTrendSignal {
	if len(points) == 0 {
		return overviewTrendSignal{Empty: true}
	}
	current := points[len(points)-1]
	out := overviewTrendSignal{
		HasData: true,
		Date:    current.Date.Format(time.DateOnly),
		Total:   current.Total,
	}
	if len(points) == 1 {
		out.Comparison = "No prior snapshot"
		return out
	}
	previous := points[len(points)-2]
	out.HasPrevious = true
	out.Delta = current.Total - previous.Total
	switch {
	case out.Delta > 0:
		out.Change = fmt.Sprintf("%d more findings", out.Delta)
	case out.Delta < 0:
		out.Change = fmt.Sprintf("%d fewer findings", -out.Delta)
	default:
		out.Change = "No change"
	}
	if previous.Date.AddDate(0, 0, 1).Equal(current.Date) {
		out.Comparison = "Day-over-day change"
	} else {
		out.Comparison = "Change since " + previous.Date.Format(time.DateOnly)
	}
	return out
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
