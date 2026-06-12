package configfile

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Modeled after the user's real config: per-process rules use a proxy,
// route.final stays direct.
const routedConfig = `{
  "log": {"level": "error"},
  "outbounds": [
    {"type": "vless", "tag": "proxy_vless", "server": "a.example.com"},
    {"type": "hysteria2", "tag": "proxy_hy2", "server": "b.example.com"},
    {"type": "direct", "tag": "direct"}
  ],
  "route": {
    "rules": [
      {"action": "sniff"},
      {"protocol": "dns", "action": "hijack-dns"},
      {"process_name": ["opera.exe"], "outbound": "proxy_hy2"},
      {"process_name": ["chrome.exe"], "outbound": "proxy_hy2"}
    ],
    "final": "direct"
  }
}`

func writeRouted(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(routedConfig), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadSection(t *testing.T) {
	e := New(writeRouted(t))

	text, err := e.ReadSection("outbounds")
	if err != nil {
		t.Fatalf("ReadSection: %v", err)
	}
	var arr []any
	if err := json.Unmarshal([]byte(text), &arr); err != nil || len(arr) != 3 {
		t.Fatalf("outbounds text wrong: %v / %s", err, text)
	}

	text, err = e.ReadSection("route")
	if err != nil {
		t.Fatalf("ReadSection route: %v", err)
	}
	if !strings.Contains(text, `"final"`) {
		t.Fatalf("route text wrong: %s", text)
	}

	if _, err := e.ReadSection("log"); err == nil {
		t.Fatal("non-editable section must be rejected")
	}
}

func TestWriteSectionRoute(t *testing.T) {
	path := writeRouted(t)
	e := New(path)

	if err := e.WriteSection("route", []byte(`{"final": "proxy_vless"}`)); err != nil {
		t.Fatalf("WriteSection: %v", err)
	}

	cfg := load(t, path)
	route := cfg["route"].(map[string]any)
	if route["final"] != "proxy_vless" {
		t.Fatalf("route not replaced: %v", route)
	}
	// Other sections intact
	if len(cfg["outbounds"].([]any)) != 3 {
		t.Fatal("outbounds damaged")
	}
}

func TestWriteSectionRejectsBadInput(t *testing.T) {
	e := New(writeRouted(t))

	if err := e.WriteSection("route", []byte(`{"final": `)); err == nil {
		t.Fatal("invalid JSON must be rejected")
	}
	if err := e.WriteSection("route", []byte(`[1,2]`)); err == nil {
		t.Fatal("array for route must be rejected")
	}
	if err := e.WriteSection("outbounds", []byte(`{"a":1}`)); err == nil {
		t.Fatal("object for outbounds must be rejected")
	}
	if err := e.WriteSection("outbounds", []byte(`[] trailing`)); err == nil {
		t.Fatal("trailing garbage must be rejected")
	}
	if err := e.WriteSection("dns", []byte(`{}`)); err == nil {
		t.Fatal("non-editable section must be rejected")
	}
}

func TestWriteSectionValidatorBlocksSave(t *testing.T) {
	path := writeRouted(t)
	e := New(path)
	e.SetValidator(func(configJSON []byte) error {
		return errors.New("sing-box check failed")
	})

	err := e.WriteSection("route", []byte(`{"final": "direct"}`))
	if err == nil || !strings.Contains(err.Error(), "sing-box check failed") {
		t.Fatalf("validator error not propagated: %v", err)
	}

	// Original file untouched
	raw, _ := os.ReadFile(path)
	if string(raw) != routedConfig {
		t.Fatal("config was modified despite failed validation")
	}
}

func TestListOutbounds(t *testing.T) {
	list, err := New(writeRouted(t)).ListOutbounds()
	if err != nil {
		t.Fatalf("ListOutbounds: %v", err)
	}
	if len(list) != 3 || list[0].Tag != "proxy_vless" || list[2].Type != "direct" {
		t.Fatalf("list = %v", list)
	}
}

func TestActiveOutboundFromRules(t *testing.T) {
	active, err := New(writeRouted(t)).ActiveOutbound()
	if err != nil {
		t.Fatalf("ActiveOutbound: %v", err)
	}
	if active != "proxy_hy2" {
		t.Fatalf("active = %q", active)
	}
}

func TestSwitchOutboundRepointsRules(t *testing.T) {
	path := writeRouted(t)
	e := New(path)

	if err := e.SwitchOutbound("proxy_vless"); err != nil {
		t.Fatalf("SwitchOutbound: %v", err)
	}

	cfg := load(t, path)
	route := cfg["route"].(map[string]any)
	rules := route["rules"].([]any)
	for _, item := range rules {
		rule := item.(map[string]any)
		if out, ok := rule["outbound"].(string); ok && out != "proxy_vless" {
			t.Fatalf("rule not repointed: %v", rule)
		}
	}
	// final stays direct: it never pointed at a proxy
	if route["final"] != "direct" {
		t.Fatalf("final must stay direct, got %v", route["final"])
	}

	active, _ := e.ActiveOutbound()
	if active != "proxy_vless" {
		t.Fatalf("active after switch = %q", active)
	}
}

func TestSwitchOutboundSetsFinalWhenNothingRouted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	cfg := `{
  "outbounds": [
    {"type": "vless", "tag": "p1"},
    {"type": "direct", "tag": "direct"}
  ],
  "route": {"rules": [{"action": "sniff"}], "final": "direct"}
}`
	if err := os.WriteFile(path, []byte(cfg), 0644); err != nil {
		t.Fatal(err)
	}

	if err := New(path).SwitchOutbound("p1"); err != nil {
		t.Fatalf("SwitchOutbound: %v", err)
	}
	loaded := load(t, path)
	if loaded["route"].(map[string]any)["final"] != "p1" {
		t.Fatal("final not set to the selected outbound")
	}
}

func TestSwitchOutboundRejectsNonProxy(t *testing.T) {
	e := New(writeRouted(t))
	if err := e.SwitchOutbound("direct"); err == nil {
		t.Fatal("direct must not be selectable")
	}
	if err := e.SwitchOutbound("missing"); err == nil {
		t.Fatal("unknown tag must be rejected")
	}
}
