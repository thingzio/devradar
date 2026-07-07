package server

import (
	"errors"
	"net/http"

	"github.com/thingzio/devradar/pkg/data"
	"github.com/thingzio/devradar/pkg/data/postgres"
	"github.com/thingzio/devradar/pkg/middleware"
)

type cveListRow struct {
	CVE          string
	WorstSev     string
	ImageCount   int
	FindingCount int
	KEV          bool
	EPSS         string // "94%" or ""
	Fixable      bool
	Repositories []string
}

type cveListView struct {
	Title       string
	SignedIn    bool
	Tab         string
	Email       string
	Version     string
	MinSeverity string
	Sort        string
	Dir         string
	NextCursor  string
	CVEs        []cveListRow
	HasData     bool
}

// handleCVEList renders the fleet-wide CVE list (blast radius): every
// vulnerability across the tenant's images, ranked KEV-first then severity then
// reach by default; sortable. Paginated.
func (s *Server) handleCVEList(w http.ResponseWriter, r *http.Request) {
	tn := middleware.TenantFromContext(r.Context())
	min := tenantMinSeverity(tn)
	if q := r.URL.Query().Get("min_severity"); q != "" && data.ValidMinSeverity(q) {
		min = q
	}
	q := r.URL.Query()
	cves, next, err := s.store.FleetCVEs(r.Context(), tn.ID, min, q.Get("sort"), q.Get("dir"), q.Get("cursor"), 100)
	if err != nil {
		http.Error(w, "failed to load CVEs", http.StatusInternalServerError)
		return
	}
	v := cveListView{
		Title: "CVEs", SignedIn: true, Tab: "cves", Email: tn.Email, Version: s.opts.Version,
		MinSeverity: min, Sort: q.Get("sort"), Dir: q.Get("dir"), NextCursor: next, HasData: len(cves) > 0,
	}
	for _, c := range cves {
		v.CVEs = append(v.CVEs, cveListRow{
			CVE: c.CVE, WorstSev: c.WorstSev, ImageCount: c.ImageCount,
			FindingCount: c.FindingCount, KEV: c.KEV, EPSS: formatEPSS(c.EPSS),
			Fixable: c.Fixable, Repositories: c.Repositories,
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
	Title       string
	SignedIn    bool
	Tab         string
	Email       string
	Version     string
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
	tn := middleware.TenantFromContext(r.Context())
	cve := r.PathValue("cve")
	d, err := s.store.CVEDetail(r.Context(), tn.ID, cve)
	if err != nil {
		if errors.Is(err, postgres.ErrNotFound) {
			http.Error(w, "CVE not found in your images", http.StatusNotFound)
			return
		}
		http.Error(w, "failed to load CVE", http.StatusInternalServerError)
		return
	}
	v := cveDetailView{
		Title: cve, SignedIn: true, Tab: "cves", Email: tn.Email, Version: s.opts.Version,
		CVE: cve, KEV: d.KEV, KEVAdded: d.KEVAdded, EPSS: formatEPSS(d.EPSS),
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
