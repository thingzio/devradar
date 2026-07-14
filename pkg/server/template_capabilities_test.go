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
			pages := map[string]string{
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

			for name, page := range pages {
				assertTemplateControl(t, page, `href="/tokens" class="user-menu-item"`, role.Can(account.ManageCredentials))
				if !role.Can(account.ManageCredentials) && strings.Contains(page, `href="/tokens"`) {
					t.Errorf("%s rendered an admin-only token entry point", name)
				}
				if !role.Can(account.ManageSettings) && strings.Contains(page, `action="/settings/`) {
					t.Errorf("%s rendered an admin-only settings entry point", name)
				}
				if strings.Contains(page, `action="/account/members`) {
					t.Errorf("%s rendered a future member mutation control", name)
				}
			}
		})
	}
}

func TestAccountTemplateAdminEntryPointInventory(t *testing.T) {
	t.Parallel()

	want := []string{
		"templates/_chrome.html",
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
		if bytes.Contains(body, []byte(`/tokens`)) || bytes.Contains(body, []byte(`/settings/`)) {
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
