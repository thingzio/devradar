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

package server

import (
	"context"
	"errors"
	"testing"

	"github.com/thingzio/devradar/pkg/data"
	"github.com/thingzio/devradar/pkg/data/postgres"
)

type overviewLicenseReaderFake struct {
	policy     data.LicensePolicy
	policyErr  error
	stats      postgres.FleetLicenseStats
	statsErr   error
	statsCalls int
}

func (f *overviewLicenseReaderFake) GetLicensePolicy(context.Context, string) (data.LicensePolicy, error) {
	return f.policy, f.policyErr
}

func (f *overviewLicenseReaderFake) FleetLicenseStats(context.Context, string, data.LicensePolicy) (postgres.FleetLicenseStats, error) {
	f.statsCalls++
	return f.stats, f.statsErr
}

func TestLoadOverviewLicenseSkipsInventoryForEmptyPolicy(t *testing.T) {
	reader := &overviewLicenseReaderFake{}
	signal, err := loadOverviewLicense(context.Background(), reader, "tenant")
	if err != nil {
		t.Fatal(err)
	}
	if signal.Configured || reader.statsCalls != 0 {
		t.Fatalf("empty policy signal=%+v stats calls=%d, want unconfigured and no inventory query", signal, reader.statsCalls)
	}
}

func TestLoadOverviewLicenseConfiguredAndErrors(t *testing.T) {
	reader := &overviewLicenseReaderFake{
		policy: data.LicensePolicy{DeniedCategories: []data.LicenseCategory{data.CategoryStrongCopyleft}},
		stats:  postgres.FleetLicenseStats{Packages: 12, Violations: 3},
	}
	signal, err := loadOverviewLicense(context.Background(), reader, "tenant")
	if err != nil {
		t.Fatal(err)
	}
	if !signal.Configured || signal.Packages != 12 || signal.Violations != 3 || reader.statsCalls != 1 {
		t.Fatalf("configured policy signal=%+v stats calls=%d", signal, reader.statsCalls)
	}

	reader.statsErr = errors.New("inventory unavailable")
	if _, err := loadOverviewLicense(context.Background(), reader, "tenant"); err == nil {
		t.Fatal("configured policy inventory error was swallowed")
	}
}
