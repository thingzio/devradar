package server

import (
	"bytes"
	"io/fs"
	"sort"
	"strings"
	"testing"

	"github.com/thingzio/devradar/pkg/account"
	"github.com/thingzio/devradar/pkg/data/postgres"
)

func TestRoleMatrixTemplateControls(t *testing.T) {
	t.Parallel()

	for _, role := range []account.Role{account.RoleAdmin, account.RoleEditor, account.RoleReader} {
		t.Run(string(role), func(t *testing.T) {
			t.Parallel()
			chrome := chromeForRole(role)
			member := account.Access{
				Actor:      account.User{ID: "member-id", Email: "member@example.com"},
				Membership: account.Membership{Role: account.RoleReader},
			}
			pages := map[string]string{
				"account_settings": renderTemplateForRole(t, "account_settings.html", accountSettingsView{
					chromeView: chrome, CSRFToken: "csrf",
				}),
				"account_members": renderTemplateForRole(t, "account_members.html", accountMembersView{
					chromeView: chrome, Members: []account.Access{member}, CSRFToken: "csrf",
				}),
				"alerts": renderTemplateForRole(t, "alerts.html", alertsView{chromeView: chrome}),
				"api": renderTemplateForRole(t, "api.html", struct {
					chromeView
					BaseURL string
				}{chromeView: chrome}),
				"cves":     renderTemplateForRole(t, "cves.html", cveListView{chromeView: chrome}),
				"image":    renderTemplateForRole(t, "image.html", imageDetailView{chromeView: chrome}),
				"sbom":     renderTemplateForRole(t, "sbom.html", sbomDetailView{chromeView: chrome, SBOMID: "id"}),
				"licenses": renderTemplateForRole(t, "licenses.html", licensesView{chromeView: chrome}),
				"overview_data": renderTemplateForRole(t, "overview.html", overviewView{
					chromeView: chrome, HasData: true,
				}),
				"overview_empty": renderTemplateForRole(t, "overview.html", overviewView{
					chromeView: chrome,
				}),
				"submit": renderTemplateForRole(t, "submit.html", struct {
					chromeView
					BaseURL string
				}{chromeView: chrome}),
				"tokens": renderTemplateForRole(t, "tokens.html", tokensView{
					chromeView: chrome, AlertPolicy: &postgres.AlertPolicy{},
				}),
			}

			assertTemplateControl(t, pages["cves"], `action="/vex/upload"`, role.Can(account.WriteEvidence))
			assertTemplateControl(t, pages["image"], `action="/images/archive"`, role.Can(account.WriteEvidence))
			assertTemplateControl(t, pages["sbom"], `action="/sboms/id/archive"`, role.Can(account.WriteEvidence))
			assertTemplateControl(t, pages["licenses"], `action="/settings/license-policy"`, role.Can(account.ManageSettings))
			assertTemplateControl(t, pages["tokens"], `action="/settings/alerts"`, role.Can(account.ManageSettings))
			assertTemplateControl(t, pages["tokens"], `action="/settings/min-severity"`, role.Can(account.ManageSettings))
			assertTemplateControl(t, pages["tokens"], `action="/tokens"`, role.Can(account.ManageCredentials))
			assertTemplateControl(t, pages["alerts"], `href="/tokens">Alert settings`, role.Can(account.ManageSettings))
			assertTemplateControl(t, pages["alerts"], `href="/tokens">Open settings`, role.Can(account.ManageSettings))
			assertTemplateControl(t, pages["overview_data"], `href="/tokens">Settings`, role.Can(account.ManageSettings))
			assertTemplateControl(t, pages["overview_empty"], `href="/tokens" class="btn secondary">Create an API token`, role.Can(account.ManageCredentials))
			assertTemplateControl(t, pages["submit"], `href="/tokens">Tokens &amp; settings`, role.Can(account.ManageCredentials))
			assertTemplateControl(t, pages["api"], `href="/tokens">Tokens &amp; settings`, role.Can(account.ManageCredentials))
			assertTemplateControl(t, pages["account_settings"], `action="/account/settings/name"`, role.Can(account.ManageSettings))
			assertTemplateControl(t, pages["account_members"], `action="/account/members/member-id/role"`, role.Can(account.ManageMembers))
			assertTemplateControl(t, pages["account_members"], `action="/account/members/member-id/revoke"`, role.Can(account.ManageMembers))

			for name, page := range pages {
				assertTemplateControl(t, page, `href="/tokens" class="user-menu-item"`, role.Can(account.ManageCredentials))
				assertTemplateControl(t, page, `href="/accounts" class="user-menu-item"`, true)
				assertTemplateControl(t, page, `href="/account/settings" class="user-menu-item"`, role.Can(account.ManageSettings))
				assertTemplateControl(t, page, `href="/account/members" class="user-menu-item"`, role.Can(account.ManageMembers))
				if !role.Can(account.ManageCredentials) && strings.Contains(page, `href="/tokens"`) {
					t.Errorf("%s rendered an admin-only token entry point", name)
				}
				if !role.Can(account.ManageSettings) && strings.Contains(page, `action="/settings/`) {
					t.Errorf("%s rendered an admin-only settings entry point", name)
				}
				if !role.Can(account.ManageMembers) && strings.Contains(page, `action="/account/members`) {
					t.Errorf("%s rendered an admin-only member mutation control", name)
				}
			}
		})
	}
}

func TestAccountTemplateAdminEntryPointInventory(t *testing.T) {
	t.Parallel()

	want := []string{
		"templates/_chrome.html",
		"templates/account_members.html",
		"templates/account_settings.html",
		"templates/alerts.html",
		"templates/api.html",
		"templates/licenses.html",
		"templates/overview.html",
		"templates/submit.html",
		"templates/tokens.html",
	}
	var got []string
	err := fs.WalkDir(templateFS, "templates", func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		body, err := templateFS.ReadFile(path)
		if err != nil {
			return err
		}
		if !strings.HasPrefix(path, "templates/admin_") &&
			(bytes.Contains(body, []byte(`/tokens`)) || bytes.Contains(body, []byte(`/settings/`)) ||
				bytes.Contains(body, []byte(`/account/`))) {
			got = append(got, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("inventory account template entry points: %v", err)
	}
	sort.Strings(got)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("account template entry-point files = %q, want %q", got, want)
	}
}

func TestAccountsTemplateHasEqualRoleControlsAndNoCreatorPrivilege(t *testing.T) {
	t.Parallel()
	for _, role := range []account.Role{account.RoleAdmin, account.RoleEditor, account.RoleReader} {
		access := account.Access{
			Actor:      account.User{ID: "user-id", Email: "member@example.com"},
			Account:    account.Account{ID: "account-id", Name: "Shared account"},
			Membership: account.Membership{AccountID: "account-id", UserID: "user-id", Role: role},
		}
		page := renderTemplateForRole(t, "accounts.html", accountsView{
			chromeView: chromeView{Title: "Accounts", SignedIn: true},
			Accounts:   []account.Access{access}, CSRFToken: "csrf",
		})
		for _, marker := range []string{
			`action="/accounts/select"`, `action="/accounts/account-id/leave"`, ">" + string(role) + "<",
		} {
			if !strings.Contains(page, marker) {
				t.Errorf("%s account chooser missing %q", role, marker)
			}
		}
		for _, forbidden := range []string{"owner", "creator", "Create account"} {
			if strings.Contains(strings.ToLower(page), strings.ToLower(forbidden)) {
				t.Errorf("%s account chooser exposed hidden privilege/action %q", role, forbidden)
			}
		}
	}
}

func TestAccountSettingsNameUsesUnicodeCodePointLimit(t *testing.T) {
	t.Parallel()
	page := renderTemplateForRole(t, "account_settings.html", accountSettingsView{
		chromeView: chromeForRole(account.RoleAdmin), CSRFToken: "csrf",
	})
	if !strings.Contains(page, `data-max-codepoints="80"`) {
		t.Fatal("account name input missing Unicode code-point limit")
	}
	if strings.Contains(page, `maxlength="80"`) {
		t.Fatal("account name input uses UTF-16 maxlength instead of code-point validation")
	}
	if !strings.Contains(page, `<label for="account-name">Account name</label>`) ||
		!strings.Contains(page, `id="account-name"`) {
		t.Fatal("account name input is not associated with an explicit label")
	}
}

func TestTopNavigationMarksOnlyActiveTabCurrent(t *testing.T) {
	t.Parallel()
	accountTabs := map[string]string{
		"overview": "/overview",
		"images":   "/dashboard",
		"work":     "/work",
		"trends":   "/trends",
		"cves":     "/cves",
		"alerts":   "/alerts",
		"licenses": "/licenses",
		"docs":     "/docs",
		"api":      "/api",
	}
	for tab, href := range accountTabs {
		t.Run("account_"+tab, func(t *testing.T) {
			var body bytes.Buffer
			if err := templates.ExecuteTemplate(&body, "nav", chromeView{
				SignedIn: true, HasAccount: true, Tab: tab,
			}); err != nil {
				t.Fatal(err)
			}
			if strings.Count(body.String(), `aria-current="page"`) != 1 ||
				!strings.Contains(body.String(), `href="`+href+`" class="tab active" aria-current="page"`) {
				t.Fatalf("active %s tab not uniquely current: %s", tab, body.String())
			}
		})
	}

	adminTabs := map[string]string{
		"dashboard": "/admin",
		"scans":     "/admin/scans",
		"accounts":  "/admin/accounts",
		"metrics":   "/admin/metrics",
	}
	for tab, href := range adminTabs {
		t.Run("admin_"+tab, func(t *testing.T) {
			var body bytes.Buffer
			if err := templates.ExecuteTemplate(&body, "admin-nav", map[string]any{"AdminTab": tab}); err != nil {
				t.Fatal(err)
			}
			if strings.Count(body.String(), `aria-current="page"`) != 1 ||
				!strings.Contains(body.String(), `href="`+href+`" class="tab active" aria-current="page"`) {
				t.Fatalf("active admin %s tab not uniquely current: %s", tab, body.String())
			}
		})
	}
}

func chromeForRole(role account.Role) chromeView {
	access := &account.Access{
		Actor:      account.User{Email: "member@example.com"},
		Account:    account.Account{Name: "Shared account"},
		Membership: account.Membership{Role: role},
	}
	return (&Server{}).chrome(access, "Capabilities", "")
}

func renderTemplateForRole(t *testing.T, name string, view any) string {
	t.Helper()
	var body bytes.Buffer
	if err := templates.ExecuteTemplate(&body, name, view); err != nil {
		t.Fatalf("render %s: %v", name, err)
	}
	return body.String()
}

func assertTemplateControl(t *testing.T, body, marker string, want bool) {
	t.Helper()
	if got := strings.Contains(body, marker); got != want {
		t.Errorf("control %q present = %v, want %v", marker, got, want)
	}
}
