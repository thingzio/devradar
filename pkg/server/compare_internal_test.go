package server

import (
	"context"
	"errors"
	"testing"

	"github.com/thingzio/devradar/pkg/data/postgres"
)

type failingCompareRecommendationReader struct{}

func (failingCompareRecommendationReader) RecommendUpgrade(context.Context, string, string) (*postgres.UpgradeRecommendation, error) {
	return nil, errors.New("recommendation unavailable")
}

func TestApplyCompareRecommendationFailurePreservesComparisonView(t *testing.T) {
	comparison := &postgres.SBOMComparison{Verdict: postgres.PostureRegresses}
	view := compareView{Comparison: comparison, Verdict: "Regresses posture"}

	err := applyCompareRecommendation(context.Background(), failingCompareRecommendationReader{}, "tenant", "sbom", &view)
	if err == nil || err.Error() != "recommendation unavailable" {
		t.Fatalf("apply recommendation error = %v", err)
	}
	if view.Comparison != comparison || view.Verdict != "Regresses posture" || view.Recommendation != nil {
		t.Fatalf("comparison view changed after recommendation failure: %+v", view)
	}
}
