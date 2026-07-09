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
	Title       string
	SignedIn    bool
	Tab         string
	Email       string
	AvatarURL   string
	Version     string
	MinSeverity string

	Repository  string
	Short       string
	Versions    []string
	SBOMCount   int
	DigestCount int

	SBOMs          []sbomRow
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

	// License inventory for this image's SBOMs (per-package, policy-evaluated).
	Packages          []packageRow
	LicenseViolations int
	PackageTotal      int // full count (Packages may be capped)
	HasPackages       bool
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
	tn := middleware.TenantFromContext(r.Context())
	repo := r.URL.Query().Get("repo")
	if repo == "" {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	min := tenantMinSeverity(tn)
	if q := r.URL.Query().Get("min_severity"); q != "" && data.ValidMinSeverity(q) {
		min = q
	}

	// SBOMs for the image (newest generation first by default), paginated
	// independently of the change log via its own cursor param. ErrNotFound ⇒
	// unknown image.
	sbomSort, sbomDir := r.URL.Query().Get("sbom_sort"), r.URL.Query().Get("sbom_dir")
	sboms, sbomNext, err := s.store.SBOMsForRepo(r.Context(), tn.ID, repo,
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
	events, next, err := s.store.RepoTimeline(r.Context(), tn.ID, repo, min, includeUnrated,
		evSort, evDir, r.URL.Query().Get("cursor"), 50)
	if err != nil {
		http.Error(w, "failed to load change log", http.StatusInternalServerError)
		return
	}

	// Severity-over-time from scan runs, rendered as a stacked column chart.
	sevpts, _ := s.store.RepoSeverityTimeline(r.Context(), tn.ID, repo, 60)
	var points []stackPoint
	for _, p := range sevpts {
		points = append(points, stackPoint{Label: p.Day, Segs: []stackSeg{
			{Sev: "critical", N: p.Critical}, {Sev: "high", N: p.High},
			{Sev: "medium", N: p.Medium}, {Sev: "low", N: p.Low},
		}})
	}

	// Authoritative header totals (independent of SBOM-list paging).
	sum, err := s.store.RepoSummary(r.Context(), tn.ID, repo)
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
	failures, _ := s.store.FailuresByRepo(r.Context(), tn.ID, repo, 50)

	// License inventory for this image, classified + evaluated against the tenant
	// policy. Best-effort (licenses are additive). Capped (violations-first) so a
	// large image doesn't render thousands of rows.
	const pkgTableLimit = 200
	policy, _ := s.store.GetLicensePolicy(r.Context(), tn.ID)
	pkgs, pkgTotal, _ := s.store.PackagesByRepo(r.Context(), tn.ID, repo, policy, pkgTableLimit)

	v := imageDetailView{
		Title:          lastPath(repo),
		SignedIn:       true,
		Tab:            "images",
		Email:          tn.Email,
		AvatarURL:      tn.AvatarURL,
		Version:        s.opts.Version,
		MinSeverity:    min,
		Repository:     repo,
		Short:          lastPath(repo),
		Versions:       sum.Versions,
		SBOMCount:      sum.SBOMCount,
		DigestCount:    sum.DigestCount,
		NextCursor:     next,
		SBOMNextCursor: sbomNext,
		SBOMSort:       sbomSort,
		SBOMDir:        sbomDir,
		EvSort:         evSort,
		EvDir:          evDir,
		IncludeUnrated: includeUnrated,
		SevChart:       stackedTimeSeries(points, 720),
		HasEvents:      len(events) > 0,
		HasFailures:    len(failures) > 0,
		HasPackages:    len(pkgs) > 0,
		PackageTotal:   pkgTotal,
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
		if p.Violation {
			v.LicenseViolations++
		}
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
