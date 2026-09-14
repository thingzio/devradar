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

package main

import (
	"testing"

	"github.com/thingzio/devradar/pkg/version"
)

func TestRunFailsClosedWithoutDeliveryKey(t *testing.T) {
	t.Setenv("DEVRADAR_DELIVERY_KEY", "")
	t.Setenv("SEND_API_KEY", "")
	t.Setenv("DEVRADAR_DEV_MODE", "true")
	if got := run(version.Info{}); got != 1 {
		t.Fatalf("run exit code = %d, want 1", got)
	}
}
