package webui

import (
	"regexp"
	"strings"
	"testing"
)

// cssRule returns the declarations of the page's CSS rule for selector
func cssRule(t *testing.T, selector string) string {
	t.Helper()
	m := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(selector) + `\s*\{([^}]*)\}`).FindStringSubmatch(pageHTML)
	if m == nil {
		t.Fatalf("page.html has no CSS rule for %s", selector)
	}
	return strings.Join(strings.Fields(m[1]), " ")
}

// The page's message sticks to the top of the window while the page
// scrolls, and a list to read stays until the next message. One as long as
// a subscription's list of every node it left out (40 XHTTP nodes of a 3x-ui
// provider) must not cover the page: it scrolls inside itself, bounded to a
// part of the window, and the user can close it.
func TestPageMessageDoesNotCoverThePage(t *testing.T) {
	if rule := cssRule(t, "#msg"); !strings.Contains(rule, "position: sticky") {
		t.Fatalf("#msg { %s }: no longer sticky", rule)
	}
	text := cssRule(t, "#msg-text")
	for _, want := range []string{"max-height: 40vh", "overflow: auto", "white-space: pre-wrap"} {
		if !strings.Contains(text, want) {
			t.Errorf("#msg-text { %s }: no %q", text, want)
		}
	}
	if !regexp.MustCompile(`<div id="msg"><div id="msg-text"></div><button id="msg-close" [^>]*onclick="hideMsg\(\)">`).MatchString(pageHTML) {
		t.Error("the message has no close button")
	}
	// The text goes into its own element: written over the whole message it
	// would take the close button with it
	if !strings.Contains(pageHTML, "body.textContent = text;") || strings.Contains(pageHTML, "el.textContent = text") {
		t.Error("show() does not write into #msg-text")
	}
}
