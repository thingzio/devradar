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

package converter

// DefaultRegistry returns a registry with the v1 converters registered: grype
// and trivy. Additional scanners register here without touching callers.
func DefaultRegistry() *Registry {
	r := NewRegistry()
	r.Register(NewGrype())
	r.Register(NewTrivy())
	return r
}
