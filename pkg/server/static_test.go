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
	"strings"
	"testing"
)

func TestAccountMenuEscapeRestoresFocusButClickOutsideDoesNot(t *testing.T) {
	t.Parallel()
	body, err := staticFS.ReadFile("static/js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(body)
	for _, want := range []string{
		"function close(restoreFocus)",
		"if (restoreFocus) toggle.focus();",
		"!menu.contains(e.target) && e.target !== toggle) close(false);",
		`if (e.key === "Escape" && !menu.hidden) close(true);`,
	} {
		if !strings.Contains(source, want) {
			t.Errorf("account menu script missing %q", want)
		}
	}
}
