package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/thingzio/devradar/pkg/data/postgres"
	"github.com/thingzio/devradar/pkg/middleware"
)

type compareFindingRow struct {
	Exposure, Package, Version, Severity string
	PreviousSeverity                     string
	Fixed                                bool
}

type comparePackageRow struct {
	Package, Version, Licenses string
}

type compareLicenseRow struct {
	Package, Version, From, To string
}

type compareLicensePolicyRegressionRow struct {
	Package, Version, From, To, Reason string
}

type compareRecommendationView struct {
	Link             string
	BaselineVersion  string
	BaselineDigest   string
	CandidateVersion string
	CandidateDigest  string
}

type compareView struct {
	chromeView
	Comparison                             *postgres.SBOMComparison
	Verdict                                string
	Added, Resolved, Rerated, NewlyFixable []compareFindingRow
	PackagesAdded, PackagesRemoved         []comparePackageRow
	LicenseChanges                         []compareLicenseRow
	LicensePolicyRegressions               []compareLicensePolicyRegressionRow
	Recommendation                         *compareRecommendationView
}

type compareRecommendationReader interface {
	RecommendUpgrade(context.Context, string, string) (*postgres.UpgradeRecommendation, error)
}

func (s *Server) handleCompare(w http.ResponseWriter, r *http.Request) {
	access := middleware.AccessFromContext(r.Context())
	fromID, toID := r.URL.Query().Get("from"), r.URL.Query().Get("to")
	if fromID == "" || toID == "" {
		http.Error(w, "from and to SBOMs are required", http.StatusBadRequest)
		return
	}
	comparison, err := s.store.CompareSBOMs(r.Context(), access.Account.ID, fromID, toID)
	if errors.Is(err, postgres.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if errors.Is(err, postgres.ErrInvalidComparison) {
		http.Error(w, "SBOMs must be different generations of the same image", http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, "failed to compare SBOMs", http.StatusInternalServerError)
		return
	}
	v := compareView{
		chromeView: s.chrome(access, "Digest comparison", "images"), Comparison: comparison,
		Verdict: comparisonVerdict(comparison.Verdict),
	}
	v.Added = compareFindingRows(comparison.Added)
	v.Resolved = compareFindingRows(comparison.Resolved)
	v.Rerated = compareFindingRows(comparison.Rerated)
	v.NewlyFixable = compareFindingRows(comparison.NewlyFixable)
	for _, p := range comparison.PackagesAdded {
		v.PackagesAdded = append(v.PackagesAdded, comparePackageRow{p.Package, p.Version, strings.Join(p.Licenses, ", ")})
	}
	for _, p := range comparison.PackagesRemoved {
		v.PackagesRemoved = append(v.PackagesRemoved, comparePackageRow{p.Package, p.Version, strings.Join(p.Licenses, ", ")})
	}
	for _, change := range comparison.LicenseChanges {
		v.LicenseChanges = append(v.LicenseChanges, compareLicenseRow{
			Package: change.Package, Version: change.Version,
			From: strings.Join(change.From, ", "), To: strings.Join(change.To, ", "),
		})
	}
	for _, regression := range comparison.LicensePolicyRegressions {
		v.LicensePolicyRegressions = append(v.LicensePolicyRegressions, compareLicensePolicyRegressionRow{
			Package: regression.Package, Version: regression.Version,
			From: strings.Join(regression.From, ", "), To: strings.Join(regression.To, ", "), Reason: regression.Reason,
		})
	}
	if err := applyCompareRecommendation(r.Context(), s.store, access.Account.ID, toID, &v); err != nil {
		slog.Warn("load comparison upgrade guidance", "account_id", access.Account.ID, "sbom_id", toID, "error", err)
	}
	render(w, "compare.html", v)
}

func applyCompareRecommendation(ctx context.Context, reader compareRecommendationReader, tenantID, baselineID string, v *compareView) error {
	recommendation, err := reader.RecommendUpgrade(ctx, tenantID, baselineID)
	if err != nil {
		return err
	}
	if recommendation != nil {
		v.Recommendation = &compareRecommendationView{
			Link: "/compare?" + url.Values{
				"from": {recommendation.Baseline.SBOMID},
				"to":   {recommendation.Candidate.SBOMID},
			}.Encode(),
			BaselineVersion: recommendation.Baseline.Version, BaselineDigest: recommendation.Baseline.Digest,
			CandidateVersion: recommendation.Candidate.Version, CandidateDigest: recommendation.Candidate.Digest,
		}
	}
	return nil
}

func compareFindingRows(items []postgres.ComparisonFinding) []compareFindingRow {
	out := make([]compareFindingRow, 0, len(items))
	for _, item := range items {
		out = append(out, compareFindingRow{
			Exposure: item.Exposure, Package: item.Package, Version: item.Version,
			Severity: item.Severity, PreviousSeverity: item.PreviousSeverity, Fixed: item.Fixed,
		})
	}
	return out
}

func comparisonVerdict(verdict string) string {
	switch verdict {
	case postgres.PostureImproves:
		return "Improves posture"
	case postgres.PostureRegresses:
		return "Regresses posture"
	default:
		return "No material change"
	}
}
