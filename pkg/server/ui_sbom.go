package server

import (
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"

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
	chromeView
	MinSeverity string
	CSRFToken   string // double-submit token for the archive form

	SBOMID      string
	Repository  string
	Short       string
	ImageRef    string
	VersionTag  string
	ShortDigest string
	Digest      string
	Labels      []string
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

	VerificationStatus string           // unverified | verified | failed
	Attestation        *attestationView // nil when no attestation has been evaluated
}

// attestationView is the SBOM detail page's verification evidence panel.
type attestationView struct {
	Result        string // verified | failed
	Mode          string // keyless | key
	Binding       string // sbom-bytes | image-digest
	BindingLabel  string // human phrase for the binding strength
	Identity      string // Fulcio SAN (keyless)
	Issuer        string // OIDC issuer (keyless)
	KeyID         string // public-key fingerprint (key mode)
	PredicateType string
	LogRef        string // Rekor reference
	FailureReason string
	VerifiedAt    string
}

// handleSBOMDetail renders one SBOM: metadata + severity rollup, a paginated
// findings table (with a fixable-only filter), a package rollup, and scan
// health (recorded failures).
func (s *Server) handleSBOMDetail(w http.ResponseWriter, r *http.Request) {
	access := middleware.AccessFromContext(r.Context())
	id := r.PathValue("id")
	min := accountMinSeverity(&access.Account)
	if q := r.URL.Query().Get("min_severity"); q != "" && data.ValidMinSeverity(q) {
		min = q
	}
	fixableOnly := r.URL.Query().Get("fixable") == "true"
	showSuppressed := r.URL.Query().Get("suppressed") == "true"
	sortKey := r.URL.Query().Get("sort")
	sortDir := r.URL.Query().Get("dir")

	detail, err := s.store.GetSBOM(r.Context(), access.Account.ID, id, min)
	if err != nil {
		if errors.Is(err, postgres.ErrNotFound) {
			http.Error(w, "SBOM not found", http.StatusNotFound)
			return
		}
		http.Error(w, "failed to load SBOM", http.StatusInternalServerError)
		return
	}

	findings, next, err := s.store.FindingsBySBOM(r.Context(), access.Account.ID, id, min, fixableOnly,
		showSuppressed, sortKey, sortDir, r.URL.Query().Get("cursor"), 100)
	if err != nil {
		http.Error(w, "failed to load findings", http.StatusInternalServerError)
		return
	}
	pkgs, err := s.store.PackageRollup(r.Context(), access.Account.ID, id, min, 15)
	if err != nil {
		http.Error(w, "failed to load package rollup", http.StatusInternalServerError)
		return
	}
	failures, err := s.store.FailuresBySBOM(r.Context(), access.Account.ID, id, 50)
	if err != nil {
		http.Error(w, "failed to load scan health", http.StatusInternalServerError)
		return
	}

	repo, tag, _ := sbom.SplitRef(detail.ImageRef)
	v := sbomDetailView{
		chromeView:     s.chrome(access, shortDigest(detail.Digest), "images"),
		MinSeverity:    min,
		CSRFToken:      issueCSRF(w),
		SBOMID:         detail.SBOMID,
		Repository:     repo,
		Short:          lastPath(repo),
		ImageRef:       detail.ImageRef,
		VersionTag:     tag,
		ShortDigest:    shortDigest(detail.Digest),
		Digest:         detail.Digest,
		Labels:         detail.Labels,
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

	v.VerificationStatus = detail.VerificationStatus
	if att, aerr := s.store.GetAttestation(r.Context(), access.Account.ID, id); aerr == nil {
		v.Attestation = attestationPanel(att)
	} else if !errors.Is(aerr, postgres.ErrNotFound) {
		slog.Warn("load attestation evidence", "sbom_id", id, "error", aerr)
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

// attestationPanel maps stored verification evidence to its display view. The
// binding label makes the strength explicit: sbom-bytes proves the exact stored
// bytes were signed; image-digest proves only that the attestation names the
// resolved image digest.
func attestationPanel(a *postgres.Attestation) *attestationView {
	bindingLabel := "Attestation binds the image digest"
	if a.Binding == "sbom-bytes" {
		bindingLabel = "Attestation signs the exact SBOM bytes"
	}
	v := &attestationView{
		Result: a.Result, Mode: a.Mode, Binding: a.Binding, BindingLabel: bindingLabel,
		Identity: a.CertIdentity, Issuer: a.OIDCIssuer, KeyID: a.KeyID,
		PredicateType: a.PredicateType, LogRef: a.TransparencyLogRef,
		FailureReason: a.FailureReason,
	}
	if !a.VerifiedAt.IsZero() {
		v.VerifiedAt = a.VerifiedAt.Format("2006-01-02 15:04")
	}
	return v
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

// handleArchiveSBOMUI archives one SBOM (one digest) from the UI — the "stop
// tracking this version" action on the SBOM detail page. Soft archive (findings
// retained), tenant-scoped, idempotent. Redirects back to the image page (or the
// dashboard if the repository can't be resolved) via POST-redirect-GET.
func (s *Server) handleArchiveSBOMUI(w http.ResponseWriter, r *http.Request) {
	access := middleware.AccessFromContext(r.Context())
	id := r.PathValue("id")

	// Resolve the repository before archiving so we can redirect to the image page.
	dest := "/dashboard"
	if detail, err := s.store.GetSBOM(r.Context(), access.Account.ID, id, data.DefaultMinSeverity); err == nil {
		if repo, _, _ := sbom.SplitRef(detail.ImageRef); repo != "" {
			dest = "/images?repo=" + url.QueryEscape(repo)
		}
	}

	if err := s.store.ArchiveSBOMAudited(r.Context(), access.Account.ID, id,
		middleware.ActorFromContext(r.Context()), middleware.RequestIDFromContext(r.Context())); err != nil {
		logMutationFailure(r, "sbom.archive", access.Account.ID, id, err)
		if errors.Is(err, postgres.ErrNotFound) {
			http.Error(w, "SBOM not found", http.StatusNotFound)
			return
		}
		http.Error(w, "failed to archive SBOM", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, dest+addMsg(dest, "sbom_archived"), http.StatusSeeOther)
}

// handleArchiveRepoUI archives an entire image (every active digest of a
// repository) from the UI — the "stop tracking this image" action on the image
// page. Soft archive, tenant-scoped, idempotent. Redirects to the dashboard.
func (s *Server) handleArchiveRepoUI(w http.ResponseWriter, r *http.Request) {
	access := middleware.AccessFromContext(r.Context())
	repo := r.FormValue("repo")
	if repo == "" {
		logMutationDenied(r, "repository.archive", "missing repository")
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	if _, err := s.store.ArchiveRepoAudited(r.Context(), access.Account.ID, repo,
		middleware.ActorFromContext(r.Context()), middleware.RequestIDFromContext(r.Context())); err != nil {
		logMutationFailure(r, "repository.archive", access.Account.ID, repo, err)
		http.Error(w, "failed to archive image", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/dashboard?msg=image_archived", http.StatusSeeOther)
}

// addMsg appends a ?msg= (or &msg=) flash to a destination that may already carry
// a query string.
func addMsg(dest, msg string) string {
	if strings.Contains(dest, "?") {
		return "&msg=" + msg
	}
	return "?msg=" + msg
}
