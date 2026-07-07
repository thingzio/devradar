package server

import (
	"net/http"

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
}

type barSeg struct {
	Class string // css severity class
	Pct   int    // width percentage
}

// dashboardView is the whole page model.
type dashboardView struct {
	Title       string
	SignedIn    bool
	Tab         string
	Email       string
	Version     string
	MinSeverity string
	Query       string // active image name search
	Sort        string
	Dir         string
	NextCursor  string
	Images      []imageRow
	// Fleet headline stats.
	ImageCount int
	TotalCount int
	CriticalCT int
	HighCT     int
	FixableCT  int
	FixablePct int
	KEVCount   int
	FailureCT  int
	HasData    bool
}

// handleDashboard renders the Images tab: fleet headline stats + a sortable,
// searchable, risk-ranked table of tracked images.
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	tn := middleware.TenantFromContext(r.Context())
	min := tenantMinSeverity(tn)
	if q := r.URL.Query().Get("min_severity"); q != "" && data.ValidMinSeverity(q) {
		min = q
	}

	// Headline stats are fleet-wide (all active images), computed independently of
	// the paginated image list below — summing one page would undercount.
	fs, err := s.store.FleetStats(r.Context(), tn.ID)
	if err != nil {
		http.Error(w, "failed to load dashboard", http.StatusInternalServerError)
		return
	}

	// Image list: one page, sorted in SQL (default risk-rank; so page order is
	// global order). Optional ?q filters by repository substring.
	q := r.URL.Query()
	query := q.Get("q")
	images, next, err := s.store.ListRepoImages(r.Context(), tn.ID, min, query,
		q.Get("sort"), q.Get("dir"), q.Get("cursor"), 50)
	if err != nil {
		http.Error(w, "failed to load dashboard", http.StatusInternalServerError)
		return
	}

	v := dashboardView{
		Title:       "Images",
		SignedIn:    true,
		Tab:         "images",
		Email:       tn.Email,
		Version:     s.opts.Version,
		MinSeverity: min,
		Query:       query,
		Sort:        q.Get("sort"),
		Dir:         q.Get("dir"),
		NextCursor:  next,
		ImageCount:  fs.Images,
		TotalCount:  fs.Total,
		CriticalCT:  fs.Critical,
		HighCT:      fs.High,
		FixableCT:   fs.Fixable,
		KEVCount:    fs.KEV,
		FailureCT:   fs.Failures,
		HasData:     fs.Total > 0,
		FixablePct:  pct(fs.Fixable, fs.Total),
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
		}
		row.Bar = severityBar(im.Counts)
		if im.Counts.Total > 0 {
			row.FixablePct = pct(im.Fixable, im.Counts.Total)
		}
		v.Images = append(v.Images, row)
	}

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
