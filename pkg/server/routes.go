package server

import (
	"net/http"

	"github.com/thingzio/devradar/pkg/account"
	"github.com/thingzio/devradar/pkg/middleware"
)

type browserHandler func(*Server, http.ResponseWriter, *http.Request)

type browserRoute struct {
	Pattern    string
	Capability account.Capability
	CSRF       bool
	Handler    browserHandler
}

// browserRoutePolicy is the complete active-account browser surface. User-only
// auth routes, platform-admin routes, API-token routes, and public/health routes
// stay with their distinct authentication boundaries and do not belong here.
var browserRoutePolicy = []browserRoute{
	{"GET /overview", account.ReadAccount, false, (*Server).handleOverview},
	{"GET /search", account.ReadAccount, false, (*Server).handleSearch},
	{"GET /dashboard", account.ReadAccount, false, (*Server).handleDashboard},
	{"GET /trends", account.ReadAccount, false, (*Server).handleTrends},
	{"GET /images", account.ReadAccount, false, (*Server).handleImageDetail},
	{"GET /compare", account.ReadAccount, false, (*Server).handleCompare},
	{"GET /sboms/{id}", account.ReadAccount, false, (*Server).handleSBOMDetail},
	{"POST /sboms/{id}/archive", account.WriteEvidence, true, (*Server).handleArchiveSBOMUI},
	{"POST /images/archive", account.WriteEvidence, true, (*Server).handleArchiveRepoUI},
	{"GET /cves", account.ReadAccount, false, (*Server).handleCVEList},
	{"GET /work", account.ReadAccount, false, (*Server).handleWorkQueue},
	{"GET /cves/{cve}", account.ReadAccount, false, (*Server).handleCVEDetail},
	{"GET /licenses", account.ReadAccount, false, (*Server).handleLicensesPage},
	{"GET /licenses/family", account.ReadAccount, false, (*Server).handleLicenseFamily},
	{"GET /alerts", account.ReadAccount, false, (*Server).handleAlerts},
	{"GET /alerts/{id}", account.ReadAccount, false, (*Server).handleAlertDetail},
	{"POST /alerts/{id}/read", account.WritePersonal, true, (*Server).handleMarkAlertRead},
	{"POST /settings/license-policy", account.ManageSettings, true, (*Server).handleSetLicensePolicy},
	{"GET /docs", account.ReadAccount, false, (*Server).handleSubmitGuide},
	{"GET /submit", account.ReadAccount, false, (*Server).handleSubmitRedirect},
	// Multipart VEX validates CSRF inside the handler after its bounded parse.
	{"POST /vex/upload", account.WriteEvidence, false, (*Server).handleUploadVEX},
	{"GET /tokens", account.ManageCredentials, false, (*Server).handleTokensPage},
	{"POST /tokens", account.ManageCredentials, true, (*Server).handleCreateToken},
	{"POST /tokens/{id}/revoke", account.ManageCredentials, true, (*Server).handleRevokeToken},
	{"POST /settings/min-severity", account.ManageSettings, true, (*Server).handleSetMinSeverity},
	{"POST /settings/alerts", account.ManageSettings, true, (*Server).handleSetAlertPolicy},
	{"GET /account/settings", account.ManageSettings, false, (*Server).handleAccountSettings},
	{"POST /account/settings/name", account.ManageSettings, true, (*Server).handleUpdateAccountName},
	{"GET /account/members", account.ManageMembers, false, (*Server).handleAccountMembers},
	{"POST /account/members/{id}/role", account.ManageMembers, true, (*Server).handleChangeMemberRole},
	{"POST /account/members/{id}/revoke", account.ManageMembers, true, (*Server).handleRevokeMembership},
}

func (s *Server) registerAccountRoutes(mux *http.ServeMux) {
	requireUser := middleware.RequireUser(s.store, loginPath)
	requireAccount := middleware.RequireAccount(s.store, "/accounts")
	for _, route := range browserRoutePolicy {
		var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			route.Handler(s, w, r)
		})
		handler = middleware.RequireCapability(route.Capability)(handler)
		if route.CSRF {
			handler = middleware.ValidateCSRF(handler)
		}
		mux.Handle(route.Pattern, requireUser(requireAccount(handler)))
	}
}

func (s *Server) handleSubmitRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/docs", http.StatusMovedPermanently)
}
