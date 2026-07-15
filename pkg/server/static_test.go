package server

import (
	"strings"
	"testing"
)

func TestAccountMenuEscapeRestoresFocusButClickOutsideDoesNot(t *testing.T) {
	t.Parallel()
	body, err := staticFS.ReadFile("static/js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(body)
	for _, want := range []string{
		"function close(restoreFocus)",
		"if (restoreFocus) toggle.focus();",
		"!menu.contains(e.target) && e.target !== toggle) close(false);",
		`if (e.key === "Escape" && !menu.hidden) close(true);`,
	} {
		if !strings.Contains(source, want) {
			t.Errorf("account menu script missing %q", want)
		}
	}
}
