package server

import (
	"bytes"
	"strings"
	"testing"
)

func renderFoot(t *testing.T, view chromeView) string {
	t.Helper()
	var buf bytes.Buffer
	if err := templates.ExecuteTemplate(&buf, "foot", view); err != nil {
		t.Fatalf("render foot: %v", err)
	}
	return buf.String()
}

func TestFooterLinks(t *testing.T) {
	body := renderFoot(t, chromeView{Version: "v1.2.3", Commit: "abc1234"})

	for _, want := range []string{
		`href="/docs">DOCS<`,
		`href="/api">API<`,
		`href="/help">HELP<`,
		`href="/tos">TERMS<`,
		`href="https://github.com/thingzio/devradar"`,
		"VERSION v1.2.3",
		"(abc1234)",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("footer missing %q", want)
		}
	}
	for _, unwanted := range []string{"CHANGELOG", "Container vulnerability tracking"} {
		if strings.Contains(body, unwanted) {
			t.Errorf("footer still contains %q", unwanted)
		}
	}
}

func TestFooterOmitsVersionWhenUnset(t *testing.T) {
	body := renderFoot(t, chromeView{})

	if strings.Contains(body, "VERSION") {
		t.Error("footer rendered a version label with no version")
	}
	if !strings.Contains(body, `href="/help">HELP<`) {
		t.Error("footer lost its links when the version was absent")
	}
}

// TestAccountInvitationRendersOnTaggedBuild guards against a regression where
// accountInvitationView had no Commit field: the "foot" template's
// {{.Commit}} is only reached once {{.Version}} is non-empty, so an empty
// Version masked the missing field entirely. A non-empty Version here is
// load-bearing — it is what reproduces the tagged-build failure.
func TestAccountInvitationRendersOnTaggedBuild(t *testing.T) {
	var buf bytes.Buffer
	view := accountInvitationView{Title: "Account invitation", Version: "v1.2.3", Error: "This invitation is invalid or no longer available."}
	if err := templates.ExecuteTemplate(&buf, "account_invitation.html", view); err != nil {
		t.Fatalf("render account_invitation.html: %v", err)
	}
	body := buf.String()
	if !strings.Contains(body, "VERSION v1.2.3") {
		t.Error("footer missing rendered version")
	}
}
