package server

import (
	"errors"
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
	Email       string
	Version     string
	MinSeverity string

	Repository  string
	Short       string
	Versions    []string
	SBOMCount   int
	DigestCount int

	SBOMs      []sbomRow
	Events     []eventRow
	NextCursor string // for the change log
	HasEvents  bool
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
	min := defaultStr(tn.MinSeverity, data.DefaultMinSeverity)
	if q := r.URL.Query().Get("min_severity"); q != "" && data.ValidMinSeverity(q) {
		min = q
	}

	// SBOMs for the image (newest generation first). ErrNotFound ⇒ unknown image.
	sboms, _, err := s.store.SBOMsForRepo(r.Context(), tn.ID, repo, "", 100)
	if err != nil {
		if errors.Is(err, postgres.ErrNotFound) {
			http.Error(w, "image not found", http.StatusNotFound)
			return
		}
		http.Error(w, "failed to load image", http.StatusInternalServerError)
		return
	}

	// Cross-digest change log, severity-filtered, paginated.
	events, next, err := s.store.RepoTimeline(r.Context(), tn.ID, repo, min,
		r.URL.Query().Get("cursor"), 100)
	if err != nil {
		http.Error(w, "failed to load change log", http.StatusInternalServerError)
		return
	}

	v := imageDetailView{
		Title:       lastPath(repo),
		SignedIn:    true,
		Email:       tn.Email,
		Version:     s.opts.Version,
		MinSeverity: min,
		Repository:  repo,
		Short:       lastPath(repo),
		SBOMCount:   len(sboms),
		NextCursor:  next,
		HasEvents:   len(events) > 0,
	}

	seenDigest := map[string]struct{}{}
	seenVer := map[string]struct{}{}
	for _, sb := range sboms {
		if _, ok := seenDigest[sb.Digest]; !ok {
			seenDigest[sb.Digest] = struct{}{}
			v.DigestCount++
		}
		if sb.Version != "" {
			if _, ok := seenVer[sb.Version]; !ok {
				seenVer[sb.Version] = struct{}{}
				v.Versions = append(v.Versions, sb.Version)
			}
		}
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
