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

package sbom

import "testing"

func TestSplitRef(t *testing.T) {
	const dig = "sha256:6f5a644135887b2aa7d5cc145072fa56421560e3586ff1f184358022d490f4e1"
	cases := []struct {
		in                        string
		wantRepo, wantTag, wantDg string
	}{
		{"quay.io/jetstack/cainjector:v1.20.2@" + dig, "quay.io/jetstack/cainjector", "v1.20.2", dig},
		{"quay.io/jetstack/cainjector@" + dig, "quay.io/jetstack/cainjector", "", dig},
		{"quay.io/jetstack/cainjector:v1.20.2", "quay.io/jetstack/cainjector", "v1.20.2", ""},
		{"registry:5000/app:1.2", "registry:5000/app", "1.2", ""},
		{"registry:5000/app", "registry:5000/app", "", ""},
		{"alpine", "alpine", "", ""},
		{"alpine:3.19", "alpine", "3.19", ""},
		{"library/alpine@" + dig, "library/alpine", "", dig},
	}
	for _, c := range cases {
		repo, tag, dg := SplitRef(c.in)
		if repo != c.wantRepo || tag != c.wantTag || dg != c.wantDg {
			t.Errorf("SplitRef(%q) = (%q,%q,%q), want (%q,%q,%q)",
				c.in, repo, tag, dg, c.wantRepo, c.wantTag, c.wantDg)
		}
		if got := Repository(c.in); got != c.wantRepo {
			t.Errorf("Repository(%q) = %q, want %q", c.in, got, c.wantRepo)
		}
	}
}
