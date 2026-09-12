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
	"net/http"

	"github.com/thingzio/devradar/pkg/config"
	"github.com/thingzio/devradar/pkg/middleware"
)

// handleSubmitGuide renders the Docs page: how DevRadar works (concepts) plus
// the SBOM submission guide — create a token, install syft, generate an SBOM by
// digest, and POST it — all with copy-paste examples targeting this deployment's
// own base URL so a user can paste them verbatim.
func (s *Server) handleSubmitGuide(w http.ResponseWriter, r *http.Request) {
	access := middleware.AccessFromContext(r.Context())
	render(w, "submit.html", struct {
		chromeView
		BaseURL string
	}{chromeView: s.chrome(access, "Docs", "docs"), BaseURL: config.BaseURL()})
}
