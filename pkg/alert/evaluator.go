// Copyright 2026 Thingz LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package alert

import (
	"context"
	"fmt"

	"github.com/thingzio/devradar/pkg/data"
	"github.com/thingzio/devradar/pkg/data/postgres"
)

const (
	DefaultConsumer  = "browser-alerts-v1"
	DefaultBatchSize = 100
)

// Store is the durable event/cursor boundary required by the evaluator.
type Store interface {
	NextAlertEvents(ctx context.Context, consumer string, limit int) ([]postgres.AlertCandidate, postgres.AlertPosition, bool, error)
	CommitAlertBatch(ctx context.Context, consumer string, drafts []postgres.AlertDraft, failures []postgres.AlertFailure, processed []postgres.AlertPosition, end postgres.AlertPosition) error
}

type postureRegressionStore interface {
	ComparePreviousSBOM(context.Context, string, string) (*postgres.SBOMComparison, error)
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
	regressionStore, detectsRegressions := e.Store.(postureRegressionStore)
	seenSBOM := make(map[string]struct{})
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
		processed := make([]postgres.AlertPosition, 0, len(candidates))
		for _, candidate := range candidates {
			result.Examined++
			processed = append(processed, postgres.AlertPosition{
				OccurredAt: candidate.Event.OccurredAt,
				EventID:    candidate.Event.ID,
			})
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
			if !detectsRegressions || len(matched) == 0 || candidate.Event.EventType != data.EventAdded || candidate.Event.Cause != data.CauseImage {
				continue
			}
			if _, seen := seenSBOM[candidate.Event.SBOMID]; seen {
				continue
			}
			seenSBOM[candidate.Event.SBOMID] = struct{}{}
			comparison, err := regressionStore.ComparePreviousSBOM(ctx, candidate.Event.TenantID, candidate.Event.SBOMID)
			if err != nil {
				failures = append(failures, postgres.AlertFailure{
					Position: postgres.AlertPosition{
						OccurredAt: candidate.Event.OccurredAt,
						EventID:    candidate.Event.ID,
					},
					Error: fmt.Sprintf("compare previous SBOM %q: %v", candidate.Event.SBOMID, err),
				})
				result.Failures++
				continue
			}
			if comparison != nil && comparison.Verdict == postgres.PostureRegresses {
				drafts = append(drafts, postgres.AlertDraft{
					PolicyID:        candidate.Policy.ID,
					PolicyUpdatedAt: candidate.Policy.UpdatedAt,
					Kind:            KindPostureRegression,
					Event:           candidate.Event,
				})
				result.Matched++
			}
		}
		if err := e.Store.CommitAlertBatch(ctx, consumer, drafts, failures, processed, end); err != nil {
			return result, fmt.Errorf("commit alert events: %w", err)
		}
		if len(candidates) < batchSize {
			return result, nil
		}
	}
}
