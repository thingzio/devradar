package alert

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/thingzio/devradar/pkg/data"
	"github.com/thingzio/devradar/pkg/data/postgres"
)

func TestEvaluator_MatchesAndIsolatesMalformedEvents(t *testing.T) {
	policy := postgres.AlertPolicy{ID: "policy-1", Enabled: true, MinSeverity: data.SeverityMedium,
		AlertKEV: true, AlertFixAvailable: true, IncludeImage: true, IncludeDB: true}
	valid := evaluatorEvent(1)
	malformed := evaluatorEvent(2)
	malformed.Exposure = ""
	unmatched := evaluatorEvent(3)
	unmatched.Severity = data.SeverityLow
	store := &fakeEvaluatorStore{batches: [][]postgres.AlertCandidate{{
		{Policy: policy, Event: valid},
		{Policy: policy, Event: malformed},
		{Policy: policy, Event: unmatched},
	}}}

	got, err := (Evaluator{Store: store, Consumer: "test", BatchSize: 100}).Evaluate(context.Background())
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}
	if got.Examined != 3 || got.Matched != 1 || got.Failures != 1 || store.commits != 1 {
		t.Fatalf("result = %+v, commits=%d", got, store.commits)
	}
	if len(store.drafts) != 1 || store.drafts[0].Kind != KindNewFinding {
		t.Fatalf("drafts = %+v", store.drafts)
	}
	if len(store.failures) != 1 || store.failures[0].Position.EventID != malformed.ID {
		t.Fatalf("failures = %+v", store.failures)
	}
	if len(store.processed) != 3 || store.processed[0].EventID != valid.ID ||
		store.processed[1].EventID != malformed.ID || store.processed[2].EventID != unmatched.ID {
		t.Fatalf("processed = %+v, want matched, failed, and unmatched positions", store.processed)
	}
}

func TestEvaluator_DrainsBoundedBatches(t *testing.T) {
	policy := postgres.AlertPolicy{ID: "policy-1", Enabled: true, MinSeverity: data.SeverityMedium,
		AlertKEV: true, AlertFixAvailable: true, IncludeImage: true, IncludeDB: true}
	store := &fakeEvaluatorStore{batches: [][]postgres.AlertCandidate{
		{{Policy: policy, Event: evaluatorEvent(1)}, {Policy: policy, Event: evaluatorEvent(2)}},
		{{Policy: policy, Event: evaluatorEvent(3)}},
	}}

	got, err := (Evaluator{Store: store, Consumer: "test", BatchSize: 2}).Evaluate(context.Background())
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}
	if got.Examined != 3 || got.Matched != 3 || store.commits != 2 {
		t.Fatalf("result = %+v, commits=%d", got, store.commits)
	}
	if len(store.processed) != 3 {
		t.Fatalf("processed = %d, want every examined candidate", len(store.processed))
	}
}

func TestEvaluator_PostureRegressionDetectionIsOptionalAndBounded(t *testing.T) {
	policy := postgres.AlertPolicy{ID: "policy-1", Enabled: true, MinSeverity: data.SeverityMedium,
		AlertKEV: true, AlertFixAvailable: true, IncludeImage: true, IncludeDB: true,
		UpdatedAt: time.Unix(1, 0).UTC()}
	first := evaluatorEvent(1)
	first.SBOMID, first.Cause = "sbom-regresses", data.CauseImage
	secondFinding := evaluatorEvent(2)
	secondFinding.SBOMID, secondFinding.FindingID, secondFinding.Cause = first.SBOMID, "finding-2", data.CauseImage
	dbEvent := evaluatorEvent(3)
	dbEvent.SBOMID = "sbom-db"
	store := &fakeEvaluatorStore{
		batches: [][]postgres.AlertCandidate{{
			{Policy: policy, Event: first},
			{Policy: policy, Event: secondFinding},
			{Policy: policy, Event: dbEvent},
		}},
		comparisons: map[string]*postgres.SBOMComparison{
			first.SBOMID: {Verdict: postgres.PostureRegresses},
		},
	}

	got, err := (Evaluator{Store: store, Consumer: "test", BatchSize: 100}).Evaluate(context.Background())
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}
	if got.Examined != 3 || got.Matched != 4 || got.Failures != 0 {
		t.Fatalf("result = %+v, want examined=3 matched=4 failures=0", got)
	}
	if len(store.compareSBOMIDs) != 1 || store.compareSBOMIDs[0] != first.SBOMID {
		t.Fatalf("compared SBOMs = %v, want one pass per eligible image SBOM", store.compareSBOMIDs)
	}
	var normal, regressions int
	for _, draft := range store.drafts {
		if !draft.PolicyUpdatedAt.Equal(policy.UpdatedAt) {
			t.Fatalf("draft policy version = %v, want %v", draft.PolicyUpdatedAt, policy.UpdatedAt)
		}
		if draft.Kind == KindPostureRegression {
			regressions++
			if draft.Event.ID != first.ID {
				t.Fatalf("regression source event = %d, want %d", draft.Event.ID, first.ID)
			}
		} else {
			normal++
		}
	}
	if normal != 3 || regressions != 1 {
		t.Fatalf("draft kinds = %+v, want 3 normal and 1 regression", store.drafts)
	}
	if len(store.failures) != 0 {
		t.Fatalf("failures = %+v, want none", store.failures)
	}
}

func TestEvaluator_PostureRegressionComparisonFailureIsIsolated(t *testing.T) {
	policy := postgres.AlertPolicy{ID: "policy-1", Enabled: true, MinSeverity: data.SeverityMedium,
		AlertKEV: true, IncludeImage: true}
	failed := evaluatorEvent(1)
	failed.SBOMID, failed.Cause = "sbom-fails", data.CauseImage
	later := evaluatorEvent(2)
	later.SBOMID, later.FindingID, later.Cause = "sbom-later", "finding-2", data.CauseImage
	store := &fakeEvaluatorStore{
		batches: [][]postgres.AlertCandidate{{
			{Policy: policy, Event: failed},
			{Policy: policy, Event: later},
		}},
		comparisons:    make(map[string]*postgres.SBOMComparison),
		comparisonErrs: map[string]error{failed.SBOMID: errors.New("compare boom")},
	}

	got, err := (Evaluator{Store: store, Consumer: "test", BatchSize: 100}).Evaluate(context.Background())
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}
	if got.Examined != 2 || got.Matched != 2 || got.Failures != 1 || store.commits != 1 {
		t.Fatalf("result = %+v, commits=%d, want examined=2 matched=2 failures=1 commits=1", got, store.commits)
	}
	if len(store.drafts) != 2 || store.drafts[0].Kind != KindNewFinding || store.drafts[1].Kind != KindNewFinding {
		t.Fatalf("drafts = %+v, want both normal alerts", store.drafts)
	}
	if len(store.failures) != 1 || store.failures[0].Position.EventID != failed.ID ||
		store.failures[0].Error != `compare previous SBOM "sbom-fails": compare boom` {
		t.Fatalf("failures = %+v, want persisted comparison failure", store.failures)
	}
	if len(store.processed) != 2 || store.processed[0].EventID != failed.ID || store.processed[1].EventID != later.ID {
		t.Fatalf("processed = %+v, want failed and later positions", store.processed)
	}
	if len(store.compareSBOMIDs) != 2 || store.compareSBOMIDs[0] != failed.SBOMID || store.compareSBOMIDs[1] != later.SBOMID {
		t.Fatalf("compared SBOMs = %v, want failed and later SBOMs", store.compareSBOMIDs)
	}
}

func TestEvaluator_InitializationAndErrors(t *testing.T) {
	t.Run("new cursor does not commit", func(t *testing.T) {
		store := &fakeEvaluatorStore{initialized: true}
		got, err := (Evaluator{Store: store}).Evaluate(context.Background())
		if err != nil || got != (Result{}) || store.commits != 0 {
			t.Fatalf("result=%+v commits=%d error=%v", got, store.commits, err)
		}
	})

	t.Run("read failure is returned", func(t *testing.T) {
		store := &fakeEvaluatorStore{nextErr: errors.New("read boom")}
		if _, err := (Evaluator{Store: store}).Evaluate(context.Background()); err == nil {
			t.Fatal("expected read error")
		}
	})

	t.Run("commit failure is returned", func(t *testing.T) {
		policy := postgres.AlertPolicy{ID: "policy-1", Enabled: true, MinSeverity: data.SeverityMedium,
			IncludeImage: true, IncludeDB: true}
		store := &fakeEvaluatorStore{
			batches:   [][]postgres.AlertCandidate{{{Policy: policy, Event: evaluatorEvent(1)}}},
			commitErr: errors.New("write boom"),
		}
		if _, err := (Evaluator{Store: store}).Evaluate(context.Background()); err == nil {
			t.Fatal("expected commit error")
		}
	})

	t.Run("cancelled context stops before read", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		store := &fakeEvaluatorStore{}
		if _, err := (Evaluator{Store: store}).Evaluate(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context cancellation", err)
		}
		if store.nextCalls != 0 {
			t.Fatalf("NextAlertEvents calls = %d, want 0", store.nextCalls)
		}
	})
}

type fakeEvaluatorStore struct {
	batches        [][]postgres.AlertCandidate
	batchIndex     int
	initialized    bool
	nextErr        error
	commitErr      error
	nextCalls      int
	commits        int
	drafts         []postgres.AlertDraft
	failures       []postgres.AlertFailure
	processed      []postgres.AlertPosition
	comparisons    map[string]*postgres.SBOMComparison
	comparisonErrs map[string]error
	compareSBOMIDs []string
}

func (f *fakeEvaluatorStore) NextAlertEvents(context.Context, string, int) ([]postgres.AlertCandidate, postgres.AlertPosition, bool, error) {
	f.nextCalls++
	if f.nextErr != nil {
		return nil, postgres.AlertPosition{}, false, f.nextErr
	}
	if f.initialized {
		return nil, postgres.AlertPosition{}, true, nil
	}
	if f.batchIndex >= len(f.batches) {
		return nil, postgres.AlertPosition{}, false, nil
	}
	batch := f.batches[f.batchIndex]
	last := batch[len(batch)-1].Event
	return batch, postgres.AlertPosition{OccurredAt: last.OccurredAt, EventID: last.ID}, false, nil
}

func (f *fakeEvaluatorStore) CommitAlertBatch(_ context.Context, _ string, drafts []postgres.AlertDraft, failures []postgres.AlertFailure, processed []postgres.AlertPosition, _ postgres.AlertPosition) error {
	f.commits++
	if f.commitErr != nil {
		return f.commitErr
	}
	f.drafts = append(f.drafts, drafts...)
	f.failures = append(f.failures, failures...)
	f.processed = append(f.processed, processed...)
	f.batchIndex++
	return nil
}

func (f *fakeEvaluatorStore) ComparePreviousSBOM(_ context.Context, _, sbomID string) (*postgres.SBOMComparison, error) {
	f.compareSBOMIDs = append(f.compareSBOMIDs, sbomID)
	if err := f.comparisonErrs[sbomID]; err != nil {
		return nil, err
	}
	return f.comparisons[sbomID], nil
}

func evaluatorEvent(id int64) postgres.AlertEvent {
	return postgres.AlertEvent{
		ID: id, OccurredAt: time.Unix(id, 0).UTC(), TenantID: "tenant-1", SBOMID: "sbom-1",
		Repository: "registry.test/app", Digest: "sha256:abc", FindingID: "finding-1",
		EventType: data.EventAdded, Exposure: "CVE-2026-0001", Package: "openssl",
		Version: "1.0.0", Severity: data.SeverityHigh, Cause: data.CauseDB, Score: 8.1,
	}
}
