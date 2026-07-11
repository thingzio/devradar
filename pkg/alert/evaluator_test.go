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
	store := &fakeEvaluatorStore{batches: [][]postgres.AlertCandidate{{
		{Policy: policy, Event: valid},
		{Policy: policy, Event: malformed},
	}}}

	got, err := (Evaluator{Store: store, Consumer: "test", BatchSize: 100}).Evaluate(context.Background())
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}
	if got.Examined != 2 || got.Matched != 1 || got.Failures != 1 || store.commits != 1 {
		t.Fatalf("result = %+v, commits=%d", got, store.commits)
	}
	if len(store.drafts) != 1 || store.drafts[0].Kind != KindNewFinding {
		t.Fatalf("drafts = %+v", store.drafts)
	}
	if len(store.failures) != 1 || store.failures[0].Position.EventID != malformed.ID {
		t.Fatalf("failures = %+v", store.failures)
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
	batches     [][]postgres.AlertCandidate
	initialized bool
	nextErr     error
	commitErr   error
	nextCalls   int
	commits     int
	drafts      []postgres.AlertDraft
	failures    []postgres.AlertFailure
}

func (f *fakeEvaluatorStore) NextAlertEvents(context.Context, string, int) ([]postgres.AlertCandidate, postgres.AlertPosition, bool, error) {
	f.nextCalls++
	if f.nextErr != nil {
		return nil, postgres.AlertPosition{}, false, f.nextErr
	}
	if f.initialized {
		return nil, postgres.AlertPosition{}, true, nil
	}
	if len(f.batches) == 0 {
		return nil, postgres.AlertPosition{}, false, nil
	}
	batch := f.batches[0]
	f.batches = f.batches[1:]
	last := batch[len(batch)-1].Event
	return batch, postgres.AlertPosition{OccurredAt: last.OccurredAt, EventID: last.ID}, false, nil
}

func (f *fakeEvaluatorStore) CommitAlertBatch(_ context.Context, _ string, drafts []postgres.AlertDraft, failures []postgres.AlertFailure, _ postgres.AlertPosition) error {
	f.commits++
	if f.commitErr != nil {
		return f.commitErr
	}
	f.drafts = append(f.drafts, drafts...)
	f.failures = append(f.failures, failures...)
	return nil
}

func evaluatorEvent(id int64) postgres.AlertEvent {
	return postgres.AlertEvent{
		ID: id, OccurredAt: time.Unix(id, 0).UTC(), TenantID: "tenant-1", SBOMID: "sbom-1",
		Repository: "registry.test/app", Digest: "sha256:abc", FindingID: "finding-1",
		EventType: data.EventAdded, Exposure: "CVE-2026-0001", Package: "openssl",
		Version: "1.0.0", Severity: data.SeverityHigh, Cause: data.CauseDB, Score: 8.1,
	}
}
