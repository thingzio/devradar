package server

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strconv"

	"github.com/thingzio/devradar/pkg/data"
	"github.com/thingzio/devradar/pkg/data/postgres"
	"github.com/thingzio/devradar/pkg/middleware"
	"github.com/thingzio/devradar/pkg/sbom"
)

type findingRow struct {
	Severity  string
	Exposure  string
	Package   string
	Version   string
	Score     string
	IsFixed   bool
	Scanner   string
	KEV       bool
	EPSS      string // percentage, e.g. "94%"; "" when no data
	VEXStatus string // "", not_affected, under_investigation, affected, fixed
}

type pkgRow struct {
	Package  string
	Count    int
	Fixable  int
	WorstSev string
}

type failureRow struct {
	Scanner string
	Stage   string
	Error   string
	When    string
}

type sbomDetailView struct {
	Title       string
	SignedIn    bool
	Tab         string
	Email       string
	AvatarURL   string
	Version     string
	MinSeverity string

	SBOMID      string
	Repository  string
	Short       string
	ImageRef    string
	VersionTag  string
	ShortDigest string
	Digest      string
	Tool        string
	ToolVersion string
	GeneratedAt string
	SubmittedAt string
	Counts      postgres.SeverityCounts

	FixableOnly    bool
	ShowSuppressed bool
	Sort           string // active sort key
	Dir            string // active direction (asc/desc)
	Findings       []findingRow
	NextCursor     string
	Packages       []pkgRow
	PkgChart       template.HTML // inline SVG: findings-per-package bar chart
	Failures       []failureRow
}

// handleSBOMDetail renders one SBOM: metadata + severity rollup, a paginated
// findings table (with a fixable-only filter), a package rollup, and scan
// health (recorded failures).
func (s *Server) handleSBOMDetail(w http.ResponseWriter, r *http.Request) {
	tn := middleware.TenantFromContext(r.Context())
	id := r.PathValue("id")
	min := tenantMinSeverity(tn)
	if q := r.URL.Query().Get("min_severity"); q != "" && data.ValidMinSeverity(q) {
		min = q
	}
	fixableOnly := r.URL.Query().Get("fixable") == "true"
	showSuppressed := r.URL.Query().Get("suppressed") == "true"
	sortKey := r.URL.Query().Get("sort")
	sortDir := r.URL.Query().Get("dir")

	detail, err := s.store.GetSBOM(r.Context(), tn.ID, id, min)
	if err != nil {
		if errors.Is(err, postgres.ErrNotFound) {
			http.Error(w, "SBOM not found", http.StatusNotFound)
			return
		}
		http.Error(w, "failed to load SBOM", http.StatusInternalServerError)
		return
	}

	findings, next, err := s.store.FindingsBySBOM(r.Context(), tn.ID, id, min, fixableOnly,
		showSuppressed, sortKey, sortDir, r.URL.Query().Get("cursor"), 100)
	if err != nil {
		http.Error(w, "failed to load findings", http.StatusInternalServerError)
		return
	}
	pkgs, err := s.store.PackageRollup(r.Context(), tn.ID, id, min, 15)
	if err != nil {
		http.Error(w, "failed to load package rollup", http.StatusInternalServerError)
		return
	}
	failures, err := s.store.FailuresBySBOM(r.Context(), tn.ID, id, 50)
	if err != nil {
		http.Error(w, "failed to load scan health", http.StatusInternalServerError)
		return
	}

	repo, tag, _ := sbom.SplitRef(detail.ImageRef)
	v := sbomDetailView{
		Title:          shortDigest(detail.Digest),
		SignedIn:       true,
		Tab:            "images",
		Email:          tn.Email,
		AvatarURL:      tn.AvatarURL,
		Version:        s.opts.Version,
		MinSeverity:    min,
		SBOMID:         detail.SBOMID,
		Repository:     repo,
		Short:          lastPath(repo),
		ImageRef:       detail.ImageRef,
		VersionTag:     tag,
		ShortDigest:    shortDigest(detail.Digest),
		Digest:         detail.Digest,
		Tool:           detail.Tool,
		ToolVersion:    detail.ToolVersion,
		SubmittedAt:    detail.SubmittedAt.Format("2006-01-02 15:04"),
		Counts:         detail.Counts,
		FixableOnly:    fixableOnly,
		ShowSuppressed: showSuppressed,
		Sort:           sortKey,
		Dir:            sortDir,
		NextCursor:     next,
	}
	if detail.GeneratedAt != nil {
		v.GeneratedAt = detail.GeneratedAt.Format("2006-01-02 15:04")
	}

	for _, f := range findings {
		v.Findings = append(v.Findings, findingRow{
			Severity:  f.Severity,
			Exposure:  f.Exposure,
			Package:   f.Package,
			Version:   f.Version,
			Score:     formatScore(f.Score),
			IsFixed:   f.IsFixed,
			Scanner:   f.Scanner,
			KEV:       f.KEV,
			EPSS:      formatEPSS(f.EPSS),
			VEXStatus: f.VEXStatus,
		})
	}
	var bars []hbar
	for _, p := range pkgs {
		v.Packages = append(v.Packages, pkgRow{
			Package: p.Package, Count: p.Count, Fixable: p.Fixable, WorstSev: p.WorstSev,
		})
		sub := ""
		if p.Fixable > 0 {
			sub = fmt.Sprintf("(%d fixable)", p.Fixable)
		}
		bars = append(bars, hbar{Label: p.Package, Value: p.Count, Sev: p.WorstSev, Sub: sub})
	}
	v.PkgChart = hbarChart(bars, 720)
	for _, f := range failures {
		v.Failures = append(v.Failures, failureRow{
			Scanner: f.Scanner, Stage: f.Stage, Error: f.Error,
			When: f.OccurredAt.Format("2006-01-02 15:04"),
		})
	}

	render(w, "sbom.html", v)
}

func formatScore(f float32) string {
	if f == 0 {
		return "—"
	}
	return strconv.FormatFloat(float64(f), 'g', -1, 32)
}

// formatEPSS renders an EPSS probability [0,1] as a percentage; "" when absent.
func formatEPSS(p *float32) string {
	if p == nil {
		return ""
	}
	return strconv.Itoa(int(*p*100+0.5)) + "%"
}
