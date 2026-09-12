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
	"slices"
	"testing"
	"time"

	"github.com/thingzio/devradar/pkg/data"
	"github.com/thingzio/devradar/pkg/data/postgres"
)

func TestMatch(t *testing.T) {
	policy := postgres.AlertPolicy{
		ID:                "policy-1",
		Enabled:           true,
		MinSeverity:       data.SeverityMedium,
		AlertKEV:          true,
		AlertFixAvailable: true,
		IncludeImage:      true,
		IncludeDB:         true,
	}
	event := postgres.AlertEvent{
		ID:         1,
		OccurredAt: time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC),
		TenantID:   "tenant-1",
		SBOMID:     "sbom-1",
		Repository: "registry.test/app",
		Digest:     "sha256:abc",
		FindingID:  "finding-1",
		EventType:  data.EventAdded,
		Exposure:   "CVE-2026-0001",
		Package:    "openssl",
		Version:    "1.0.0",
		Severity:   data.SeverityHigh,
		Cause:      data.CauseDB,
		Score:      8.1,
		Labels:     []string{"prod", "team-a"},
	}

	tests := []struct {
		name    string
		policy  postgres.AlertPolicy
		event   postgres.AlertEvent
		want    []string
		wantErr bool
	}{
		{name: "disabled", policy: changePolicy(policy, func(p *postgres.AlertPolicy) { p.Enabled = false }), event: event},
		{name: "new finding", policy: policy, event: event, want: []string{KindNewFinding}},
		{name: "before policy update", policy: changePolicy(policy, func(p *postgres.AlertPolicy) { p.UpdatedAt = event.OccurredAt.Add(time.Nanosecond) }), event: event},
		{name: "at policy update", policy: changePolicy(policy, func(p *postgres.AlertPolicy) { p.UpdatedAt = event.OccurredAt }), event: event, want: []string{KindNewFinding}},
		{name: "KEV takes precedence", policy: policy, event: changeEvent(event, func(e *postgres.AlertEvent) { e.KEV = true }), want: []string{KindNewKEV}},
		{name: "KEV disabled falls through", policy: changePolicy(policy, func(p *postgres.AlertPolicy) { p.AlertKEV = false }), event: changeEvent(event, func(e *postgres.AlertEvent) { e.KEV = true }), want: []string{KindNewFinding}},
		{name: "fix available", policy: policy, event: changeEvent(event, func(e *postgres.AlertEvent) { e.EventType = data.EventFixed }), want: []string{KindFixAvailable}},
		{name: "fix alert disabled", policy: changePolicy(policy, func(p *postgres.AlertPolicy) { p.AlertFixAvailable = false }), event: changeEvent(event, func(e *postgres.AlertEvent) { e.EventType = data.EventFixed })},
		{name: "below threshold", policy: policy, event: changeEvent(event, func(e *postgres.AlertEvent) { e.Severity = data.SeverityLow })},
		{name: "unknown severity surfaces", policy: policy, event: changeEvent(event, func(e *postgres.AlertEvent) { e.Severity = data.SeverityUnknown }), want: []string{KindNewFinding}},
		{name: "tooling ignored", policy: policy, event: changeEvent(event, func(e *postgres.AlertEvent) { e.Cause = data.CauseTooling })},
		{name: "image excluded", policy: changePolicy(policy, func(p *postgres.AlertPolicy) { p.IncludeImage = false }), event: changeEvent(event, func(e *postgres.AlertEvent) { e.Cause = data.CauseImage })},
		{name: "db excluded", policy: changePolicy(policy, func(p *postgres.AlertPolicy) { p.IncludeDB = false }), event: event},
		{name: "label matches", policy: changePolicy(policy, func(p *postgres.AlertPolicy) { p.Labels = []string{"prod"} }), event: event, want: []string{KindNewFinding}},
		{name: "label misses", policy: changePolicy(policy, func(p *postgres.AlertPolicy) { p.Labels = []string{"staging"} }), event: event},
		{name: "resolved ignored", policy: policy, event: changeEvent(event, func(e *postgres.AlertEvent) { e.EventType = data.EventResolved })},
		{name: "rerated deferred", policy: policy, event: changeEvent(event, func(e *postgres.AlertEvent) { e.EventType = data.EventRerated })},
		{name: "malformed event", policy: policy, event: changeEvent(event, func(e *postgres.AlertEvent) { e.Exposure = "" }), wantErr: true},
		{name: "unknown cause", policy: policy, event: changeEvent(event, func(e *postgres.AlertEvent) { e.Cause = "mystery" }), wantErr: true},
		{name: "unknown event type", policy: policy, event: changeEvent(event, func(e *postgres.AlertEvent) { e.EventType = "mystery" }), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Match(tt.policy, tt.event)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Match() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !slices.Equal(kinds(got), tt.want) {
				t.Fatalf("Match() kinds = %v, want %v", kinds(got), tt.want)
			}
			for _, draft := range got {
				if !draft.PolicyUpdatedAt.Equal(tt.policy.UpdatedAt) {
					t.Fatalf("Match() policy version = %v, want %v", draft.PolicyUpdatedAt, tt.policy.UpdatedAt)
				}
			}
		})
	}
}

func kinds(drafts []postgres.AlertDraft) []string {
	out := make([]string, len(drafts))
	for i := range drafts {
		out[i] = drafts[i].Kind
	}
	return out
}

func changePolicy(p postgres.AlertPolicy, change func(*postgres.AlertPolicy)) postgres.AlertPolicy {
	change(&p)
	return p
}

func changeEvent(e postgres.AlertEvent, change func(*postgres.AlertEvent)) postgres.AlertEvent {
	change(&e)
	return e
}
