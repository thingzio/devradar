# Account Menu Identity Labels Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Label the selected account and signed-in user explicitly in the account menu.

**Architecture:** Keep the change in the existing server-rendered navigation template. Use the closed `admin`/`editor`/`reader` role set to render title-cased labels, with template regressions proving the active-account and account-chooser states.

**Tech Stack:** Go `html/template`, Go tests, existing `pkg/server` template harness.

## Global Constraints

- With an active account, render `Account: <account name>` before `User: <user email> (<membership role>)`.
- Role labels are exactly `Admin`, `Editor`, and `Reader`.
- Without an active account, render only `User: <user email>`.
- Preserve template escaping, menu links, permissions, keyboard behavior, layout, and responsive styling.
- Do not rename settings or token UI and do not add a User settings page.
- Work locally on `main`; sign commits; do not push, deploy, apply Terraform, or enable account sharing.

---

### Task 1: Render Explicit Account and User Identity Labels

**Files:**
- Modify: `pkg/server/templates/_chrome.html:36`
- Test: `pkg/server/template_capabilities_test.go`

**Interfaces:**
- Consumes: `chromeView.Email`, `chromeView.AccountName`, `chromeView.AccountRole`, and `chromeView.HasAccount`.
- Produces: the approved account-menu identity copy; no Go API changes.

- [ ] **Step 1: Write the failing template regressions**

Add:

```go
func TestAccountMenuLabelsAccountAndUser(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		role  account.Role
		label string
	}{
		{account.RoleAdmin, "Admin"},
		{account.RoleEditor, "Editor"},
		{account.RoleReader, "Reader"},
	} {
		t.Run(string(test.role), func(t *testing.T) {
			t.Parallel()
			var body bytes.Buffer
			err := templates.ExecuteTemplate(&body, "nav", chromeView{
				SignedIn: true, HasAccount: true,
				Email: "member@example.com", AccountName: "member@example.com",
				AccountRole: test.role,
			})
			if err != nil {
				t.Fatal(err)
			}
			want := "Account: member@example.com<br>User: member@example.com (" + test.label + ")"
			if !strings.Contains(body.String(), want) {
				t.Fatalf("account menu missing %q: %s", want, body.String())
			}
		})
	}
}

func TestAccountMenuWithoutSelectionLabelsOnlyUser(t *testing.T) {
	t.Parallel()
	var body bytes.Buffer
	if err := templates.ExecuteTemplate(&body, "nav", chromeView{
		SignedIn: true, Email: "member@example.com",
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body.String(), "User: member@example.com") ||
		strings.Contains(body.String(), "Account:") ||
		strings.Contains(body.String(), "(Admin)") {
		t.Fatalf("chooser account menu identity is incorrect: %s", body.String())
	}
}
```

- [ ] **Step 2: Run the focused tests and verify RED**

Run:

```bash
go test -race ./pkg/server -run '^TestAccountMenu' -count=1
```

Expected: FAIL because the current header renders the raw email followed by the account name and lowercase role without labels.

- [ ] **Step 3: Implement the minimal template change**

Replace the menu header with:

```html
<div class="user-menu-header">{{if .HasAccount}}Account: {{.AccountName}}<br>{{end}}User: {{.Email}}{{if .HasAccount}} ({{if eq .AccountRole "admin"}}Admin{{else if eq .AccountRole "editor"}}Editor{{else if eq .AccountRole "reader"}}Reader{{end}}){{end}}</div>
```

- [ ] **Step 4: Run focused and package tests**

Run:

```bash
go test -race ./pkg/server -run '^(TestAccountMenu|TestRoleMatrixTemplateControls|TestTopNavigation)' -count=1
go test -race ./pkg/server -count=1
git diff --check
```

Expected: PASS with no race failures or whitespace errors.

- [ ] **Step 5: Commit the implementation**

```bash
git add pkg/server/templates/_chrome.html pkg/server/template_capabilities_test.go
git commit -S -m "fix: label account menu identities"
```
