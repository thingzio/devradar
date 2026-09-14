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
	"reflect"
	"runtime"
	"testing"

	"github.com/thingzio/devradar/pkg/account"
)

func TestAuthenticatedRouteInventory(t *testing.T) {
	t.Parallel()

	want := map[string]struct {
		cap     account.Capability
		csrf    bool
		handler browserHandler
	}{
		"GET /overview":                     {account.ReadAccount, false, (*Server).handleOverview},
		"GET /search":                       {account.ReadAccount, false, (*Server).handleSearch},
		"GET /dashboard":                    {account.ReadAccount, false, (*Server).handleDashboard},
		"GET /trends":                       {account.ReadAccount, false, (*Server).handleTrends},
		"GET /images":                       {account.ReadAccount, false, (*Server).handleImageDetail},
		"GET /compare":                      {account.ReadAccount, false, (*Server).handleCompare},
		"GET /sboms/{id}":                   {account.ReadAccount, false, (*Server).handleSBOMDetail},
		"POST /sboms/{id}/archive":          {account.WriteEvidence, true, (*Server).handleArchiveSBOMUI},
		"POST /images/archive":              {account.WriteEvidence, true, (*Server).handleArchiveRepoUI},
		"GET /cves":                         {account.ReadAccount, false, (*Server).handleCVEList},
		"GET /work":                         {account.ReadAccount, false, (*Server).handleWorkQueue},
		"GET /cves/{cve}":                   {account.ReadAccount, false, (*Server).handleCVEDetail},
		"GET /licenses":                     {account.ReadAccount, false, (*Server).handleLicensesPage},
		"GET /licenses/family":              {account.ReadAccount, false, (*Server).handleLicenseFamily},
		"GET /alerts":                       {account.ReadAccount, false, (*Server).handleAlerts},
		"GET /alerts/{id}":                  {account.ReadAccount, false, (*Server).handleAlertDetail},
		"POST /alerts/{id}/read":            {account.WritePersonal, true, (*Server).handleMarkAlertRead},
		"POST /settings/license-policy":     {account.ManageSettings, true, (*Server).handleSetLicensePolicy},
		"GET /submit":                       {account.ReadAccount, false, (*Server).handleSubmitRedirect},
		"POST /vex/upload":                  {account.WriteEvidence, false, (*Server).handleUploadVEX},
		"GET /tokens":                       {account.ManageCredentials, false, (*Server).handleTokensPage},
		"POST /tokens":                      {account.ManageCredentials, true, (*Server).handleCreateToken},
		"POST /tokens/{id}/revoke":          {account.ManageCredentials, true, (*Server).handleRevokeToken},
		"POST /settings/min-severity":       {account.ManageSettings, true, (*Server).handleSetMinSeverity},
		"POST /settings/alerts":             {account.ManageSettings, true, (*Server).handleSetAlertPolicy},
		"GET /account/settings":             {account.ManageSettings, false, (*Server).handleAccountSettings},
		"POST /account/settings/name":       {account.ManageSettings, true, (*Server).handleUpdateAccountName},
		"GET /account/members":              {account.ManageMembers, false, (*Server).handleAccountMembers},
		"POST /account/members/{id}/role":   {account.ManageMembers, true, (*Server).handleChangeMemberRole},
		"POST /account/members/{id}/revoke": {account.ManageMembers, true, (*Server).handleRevokeMembership},
	}

	if len(browserRoutePolicy) != len(want) {
		t.Fatalf("authenticated route policy has %d routes, want %d", len(browserRoutePolicy), len(want))
	}
	seen := make(map[string]struct{}, len(browserRoutePolicy))
	for _, route := range browserRoutePolicy {
		if _, duplicate := seen[route.Pattern]; duplicate {
			t.Errorf("duplicate authenticated route declaration %q", route.Pattern)
			continue
		}
		seen[route.Pattern] = struct{}{}
		expected, ok := want[route.Pattern]
		if !ok {
			t.Errorf("unexpected authenticated route declaration %q", route.Pattern)
			continue
		}
		if route.Capability != expected.cap || route.CSRF != expected.csrf {
			t.Errorf("route %q = capability %q, csrf %v; want %q, %v",
				route.Pattern, route.Capability, route.CSRF, expected.cap, expected.csrf)
		}
		if route.Handler == nil {
			t.Errorf("route %q has no handler", route.Pattern)
			continue
		}
		gotHandler := reflect.ValueOf(route.Handler).Pointer()
		wantHandler := reflect.ValueOf(expected.handler).Pointer()
		if gotHandler != wantHandler {
			t.Errorf("route %q handler = %q, want %q", route.Pattern,
				functionName(gotHandler), functionName(wantHandler))
		}
	}
}

func functionName(pointer uintptr) string {
	if function := runtime.FuncForPC(pointer); function != nil {
		return function.Name()
	}
	return "<nil>"
}
