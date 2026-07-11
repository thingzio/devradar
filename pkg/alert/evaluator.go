package alert

import (
	"context"
	"fmt"

	"github.com/thingzio/devradar/pkg/data/postgres"
)

const (
	DefaultConsumer  = "browser-alerts-v1"
	DefaultBatchSize = 100
)

// Store is the durable event/cursor boundary required by the evaluator.
type Store interface {
	NextAlertEvents(ctx context.Context, consumer string, limit int) ([]postgres.AlertCandidate, postgres.AlertPosition, bool, error)
	CommitAlertBatch(ctx context.Context, consumer string, drafts []postgres.AlertDraft, failures []postgres.AlertFailure, end postgres.AlertPosition) error
}

// Evaluator drains new finding events in bounded batches.
type Evaluator struct {
	Store     Store
	Consumer  string
	BatchSize int
}

// Result summarizes one evaluator pass.
type Result struct {
	Examined int
	Matched  int
	Failures int
}

// Evaluate processes events until the current tail. Matcher failures are
// persisted with the same cursor transaction so one malformed row cannot wedge
// later events.
func (e Evaluator) Evaluate(ctx context.Context) (Result, error) {
	if e.Store == nil {
		return Result{}, fmt.Errorf("alert evaluator store is nil")
	}
	consumer := e.Consumer
	if consumer == "" {
		consumer = DefaultConsumer
	}
	batchSize := e.BatchSize
	if batchSize <= 0 {
		batchSize = DefaultBatchSize
	}

	var result Result
	for {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		candidates, end, initialized, err := e.Store.NextAlertEvents(ctx, consumer, batchSize)
		if err != nil {
			return result, fmt.Errorf("read alert events: %w", err)
		}
		if initialized || len(candidates) == 0 {
			return result, nil
		}

		drafts := make([]postgres.AlertDraft, 0, len(candidates))
		failures := make([]postgres.AlertFailure, 0)
		for _, candidate := range candidates {
			result.Examined++
			matched, err := Match(candidate.Policy, candidate.Event)
			if err != nil {
				failures = append(failures, postgres.AlertFailure{
					Position: postgres.AlertPosition{
						OccurredAt: candidate.Event.OccurredAt,
						EventID:    candidate.Event.ID,
					},
					Error: err.Error(),
				})
				result.Failures++
				continue
			}
			drafts = append(drafts, matched...)
			result.Matched += len(matched)
		}
		if err := e.Store.CommitAlertBatch(ctx, consumer, drafts, failures, end); err != nil {
			return result, fmt.Errorf("commit alert events: %w", err)
		}
		if len(candidates) < batchSize {
			return result, nil
		}
	}
}
