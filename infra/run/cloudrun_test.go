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

package run

import (
	"os"
	"regexp"
	"testing"
)

func TestAccountSharingFeatureFlagIsTerraformManagedAndDisabledByDefault(t *testing.T) {
	t.Parallel()

	variables, err := os.ReadFile("variables.tf")
	if err != nil {
		t.Fatal(err)
	}
	variable := terraformVariableBlock(t, string(variables), "account_sharing_enabled")
	for _, want := range []string{
		`type\s*=\s*bool`,
		`default\s*=\s*false`,
	} {
		if !regexp.MustCompile(want).MatchString(variable) {
			t.Fatalf("account sharing variable missing %q:\n%s", want, variable)
		}
	}

	cloudRun, err := os.ReadFile("cloudrun.tf")
	if err != nil {
		t.Fatal(err)
	}
	serve := terraformResourceBlock(t, string(cloudRun),
		"google_cloud_run_v2_service", "serve")
	environment := regexp.MustCompile(`(?ms)^\s*env \{\n(.*?^\s*\})`).FindAllString(serve, -1)
	for _, block := range environment {
		if regexp.MustCompile(`name\s*=\s*"DEVRADAR_ACCOUNT_SHARING_ENABLED"`).MatchString(block) {
			if !regexp.MustCompile(`value\s*=\s*tostring\(var\.account_sharing_enabled\)`).MatchString(block) {
				t.Fatalf("account sharing environment variable is not sourced from Terraform:\n%s", block)
			}
			return
		}
	}
	t.Fatal("serve service does not set DEVRADAR_ACCOUNT_SHARING_ENABLED")
}

func TestDeliveryJobUsesCloudRunGen2MinimumMemory(t *testing.T) {
	t.Parallel()

	cloudRun, err := os.ReadFile("cloudrun.tf")
	if err != nil {
		t.Fatal(err)
	}
	delivery := terraformResourceBlock(t, string(cloudRun),
		"google_cloud_run_v2_job", "delivery")
	if !regexp.MustCompile(`(?m)^\s*memory\s*=\s*"512Mi"\s*$`).MatchString(delivery) {
		t.Fatalf("delivery job must use at least 512Mi with Cloud Run gen2:\n%s", delivery)
	}
}

func terraformVariableBlock(t *testing.T, source, name string) string {
	t.Helper()
	pattern := `(?ms)^variable "` + regexp.QuoteMeta(name) + `" \{\n(.*?^\})`
	block := regexp.MustCompile(pattern).FindString(source)
	if block == "" {
		t.Fatalf("missing Terraform variable %s", name)
	}
	return block
}
