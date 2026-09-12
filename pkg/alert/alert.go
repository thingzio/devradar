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

// Package alert evaluates finding events against tenant alert policies.
package alert

import (
	"fmt"

	"github.com/thingzio/devradar/pkg/data"
	"github.com/thingzio/devradar/pkg/data/postgres"
)

const (
	KindNewKEV            = "new_kev"
	KindNewFinding        = "new_finding"
	KindFixAvailable      = "fix_available"
	KindPostureRegression = "posture_regression"
)

// Match returns at most one alert draft for a finding event. Specific signals
// take precedence over the general new-finding rule so one event cannot create
// redundant tenant alerts.
func Match(policy postgres.AlertPolicy, event postgres.AlertEvent) ([]postgres.AlertDraft, error) {
	if err := validateEvent(event); err != nil {
		return nil, err
	}
	if !policy.UpdatedAt.IsZero() && event.OccurredAt.Before(policy.UpdatedAt) {
		return nil, nil
	}
	if !policy.Enabled || !causeEnabled(policy, event.Cause) || !labelsMatch(policy.Labels, event.Labels) {
		return nil, nil
	}

	kind := ""
	switch event.EventType {
	case data.EventFixed:
		if policy.AlertFixAvailable {
			kind = KindFixAvailable
		}
	case data.EventAdded:
		switch {
		case event.KEV && policy.AlertKEV:
			kind = KindNewKEV
		case data.MeetsThreshold(event.Severity, policy.MinSeverity):
			kind = KindNewFinding
		}
	case data.EventResolved, data.EventRerated:
		return nil, nil
	}
	if kind == "" {
		return nil, nil
	}
	return []postgres.AlertDraft{{
		PolicyID:        policy.ID,
		PolicyUpdatedAt: policy.UpdatedAt,
		Kind:            kind,
		Event:           event,
	}}, nil
}

func validateEvent(event postgres.AlertEvent) error {
	if event.ID <= 0 || event.OccurredAt.IsZero() || event.TenantID == "" || event.SBOMID == "" ||
		event.FindingID == "" || event.Exposure == "" {
		return fmt.Errorf("invalid alert event identity")
	}
	switch event.Cause {
	case data.CauseImage, data.CauseDB, data.CauseTooling:
	default:
		return fmt.Errorf("invalid alert event cause %q", event.Cause)
	}
	switch event.EventType {
	case data.EventAdded, data.EventResolved, data.EventRerated, data.EventFixed:
	default:
		return fmt.Errorf("invalid alert event type %q", event.EventType)
	}
	return nil
}

func causeEnabled(policy postgres.AlertPolicy, cause string) bool {
	switch cause {
	case data.CauseImage:
		return policy.IncludeImage
	case data.CauseDB:
		return policy.IncludeDB
	default:
		return false
	}
}

func labelsMatch(required, actual []string) bool {
	if len(required) == 0 {
		return true
	}
	for _, want := range required {
		for _, got := range actual {
			if want == got {
				return true
			}
		}
	}
	return false
}
