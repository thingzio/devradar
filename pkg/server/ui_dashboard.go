package server

import (
	"net/http"
	"sort"

	"github.com/thingzio/devradar/pkg/data"
	"github.com/thingzio/devradar/pkg/data/postgres"
	"github.com/thingzio/devradar/pkg/middleware"
)

// imageRow is one repository in the dashboard table, pre-computed for the
// template: the raw counts plus the flexbox segment widths for the stacked
// severity bar (percentages of this row's total, so every bar fills its track).
type imageRow struct {
	Repository string
	Short      string // last path segment, for a compact primary label
	Versions   []string
	SBOMCount  int
	Critical   int
	High       int
	Medium     int
	Low        int
	Total      int
	Fixable    int
	FixablePct int
	Failures   int
	Bar        []barSeg // ordered crit→low segments with non-zero width
	RiskScore  int      // ranking key; not shown
}

type barSeg struct {
	Class string // css severity class
	Pct   int    // width percentage
}

// dashboardView is the whole page model.
type dashboardView struct {
	Title       string
	SignedIn    bool
	Email       string
	Version     string
	MinSeverity string
	Images      []imageRow
	// Fleet headline stats.
	ImageCount int
	TotalCount int
	CriticalCT int
	HighCT     int
	FixableCT  int
	FixablePct int
	FailureCT  int
	HasData    bool
}

// handleDashboard renders the fleet overview (CUJ-1): headline stats plus a
// risk-ranked table of tracked images, each with a stacked severity bar.
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	tn := middleware.TenantFromContext(r.Context())
	min := defaultStr(tn.MinSeverity, data.DefaultMinSeverity)
	if q := r.URL.Query().Get("min_severity"); q != "" && data.ValidMinSeverity(q) {
		min = q
	}

	// Pull the full inventory (grouped). The dashboard is a rollup, so it reads
	// with a high limit rather than paginating — a tenant's distinct-image count
	// is small relative to SBOMs. (When that stops holding, page it.)
	images, _, err := s.store.ListRepoImages(r.Context(), tn.ID, min, "", 500)
	if err != nil {
		http.Error(w, "failed to load dashboard", http.StatusInternalServerError)
		return
	}

	v := dashboardView{
		Title:       "Dashboard",
		SignedIn:    true,
		Email:       tn.Email,
		Version:     s.opts.Version,
		MinSeverity: min,
		ImageCount:  len(images),
	}
	for _, im := range images {
		row := imageRow{
			Repository: im.Repository,
			Short:      lastPath(im.Repository),
			Versions:   im.Versions,
			SBOMCount:  im.SBOMCount,
			Critical:   im.Counts.Critical,
			High:       im.Counts.High,
			Medium:     im.Counts.Medium,
			Low:        im.Counts.Low,
			Total:      im.Counts.Total,
			Fixable:    im.Fixable,
			Failures:   im.Failures,
			RiskScore:  im.Counts.Critical*1_000_000 + im.Counts.High*1_000 + im.Counts.Total,
		}
		row.Bar = severityBar(im.Counts)
		if im.Counts.Total > 0 {
			row.FixablePct = pct(im.Fixable, im.Counts.Total)
		}
		v.Images = append(v.Images, row)

		v.TotalCount += im.Counts.Total
		v.CriticalCT += im.Counts.Critical
		v.HighCT += im.Counts.High
		v.FixableCT += im.Fixable
		v.FailureCT += im.Failures
	}
	sort.SliceStable(v.Images, func(i, j int) bool {
		return v.Images[i].RiskScore > v.Images[j].RiskScore
	})
	v.HasData = v.TotalCount > 0
	v.FixablePct = pct(v.FixableCT, v.TotalCount)

	render(w, "dashboard.html", v)
}

// severityBar turns a count breakdown into ordered crit→low segments sized as a
// percentage of the row total. Sub-1% non-zero buckets still get 1% so they stay
// visible. unknown/negligible are folded into "low" visually to keep the bar to
// four meaningful bands.
func severityBar(c postgres.SeverityCounts) []barSeg {
	if c.Total == 0 {
		return nil
	}
	low := c.Low + c.Negligible + c.Unknown
	bands := []struct {
		class string
		n     int
	}{
		{"sev-critical", c.Critical},
		{"sev-high", c.High},
		{"sev-medium", c.Medium},
		{"sev-low", low},
	}
	var segs []barSeg
	for _, b := range bands {
		if b.n == 0 {
			continue
		}
		p := pct(b.n, c.Total)
		if p == 0 {
			p = 1
		}
		segs = append(segs, barSeg{Class: b.class, Pct: p})
	}
	return segs
}

func pct(n, total int) int {
	if total == 0 {
		return 0
	}
	return n * 100 / total
}

func lastPath(repo string) string {
	for i := len(repo) - 1; i >= 0; i-- {
		if repo[i] == '/' {
			return repo[i+1:]
		}
	}
	return repo
}
