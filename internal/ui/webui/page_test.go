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

// The latency test on the page: its buttons and caption hidden until the
// app says it has the test, the elements the sandbox test drives kept, and
// everything of a report written as text — tags and notes come from
// subscriptions
func TestPageLatency(t *testing.T) {
	for _, want := range []string{
		`<div id="outbound-list"></div>`,
		`<button id="switch-btn" onclick="switchOutbound()">`,
		`<button id="latency-btn" class="secondary" onclick="testLatency()" hidden>Проверить задержку</button>`,
		`<button id="fastest-btn" class="secondary" onclick="selectFastest()" hidden>Выбрать самый быстрый</button>`,
		`<div id="latency-note" class="vpn-state" style="margin-top:10px" hidden>`,
		"Задержка — время до ответа https://www.gstatic.com через сервер (подключение, рукопожатие и один запрос; так же меряет группа urltest). " +
			"Каждый сервер проверяется напрямую, мимо правил маршрутизации, отдельным временным sing-box — работающий VPN не затрагивается. " +
			"Проверка подключается ко всем серверам списка с вашего адреса.",
		"'Проверяю задержку серверов… (до 30 с)'",
		"const latency = !!d.latency && !missing;",
	} {
		if !strings.Contains(pageHTML, want) {
			t.Errorf("page.html has no %q", want)
		}
	}
	start := strings.Index(pageHTML, "// --- the latency test")
	end := strings.Index(pageHTML, "async function refreshAppUpdate")
	if start < 0 || end < start {
		t.Fatal("no latency section in the script")
	}
	if section := pageHTML[start:end]; strings.Contains(section, "innerHTML") || !strings.Contains(section, "span.textContent = r.delay_ms + ' мс';") {
		t.Error("the latency marks are not written as text")
	}
	// The notes as hints, through textContent like the static ones
	if !strings.Contains(pageHTML, "hint.textContent = text;") {
		t.Error("the notes are not written as text")
	}
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
