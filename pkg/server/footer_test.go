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
