package configfile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"tray-sing-box/internal/domain"
)

const sampleConfig = `{
  "log": {"level": "info"},
  "inbounds": [{"type": "tun", "tag": "tun-in"}],
  "outbounds": [
    {"type": "selector", "tag": "proxy", "outbounds": ["old-node", "direct"]},
    {"type": "vless", "tag": "old-node", "server": "old.example.com", "server_port": 443},
    {"type": "direct", "tag": "direct"}
  ],
  "route": {"final": "proxy"}
}`

func writeSample(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(sampleConfig), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func load(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("config is not valid JSON after edit: %v", err)
	}
	return cfg
}

func outboundByTag(t *testing.T, cfg map[string]any, tag string) map[string]any {
	t.Helper()
	for _, item := range cfg["outbounds"].([]any) {
		o := item.(map[string]any)
		if o["tag"] == tag {
			return o
		}
	}
	return nil
}

func TestAddOutboundAppendsAndRegistersInSelector(t *testing.T) {
	path := writeSample(t)

	err := New(path).AddOutbound(map[string]any{
		"type": "vless", "tag": "new-node", "server": "new.example.com", "server_port": 8443,
	})
	if err != nil {
		t.Fatalf("AddOutbound: %v", err)
	}

	cfg := load(t, path)
	added := outboundByTag(t, cfg, "new-node")
	if added == nil || added["server"] != "new.example.com" {
		t.Fatalf("outbound not added: %v", cfg["outbounds"])
	}

	selector := outboundByTag(t, cfg, "proxy")
	members := selector["outbounds"].([]any)
	found := false
	for _, m := range members {
		if m == "new-node" {
			found = true
		}
	}
	if !found {
		t.Fatalf("tag not registered in selector: %v", members)
	}

	// Untouched parts must survive
	if cfg["route"].(map[string]any)["final"] != "proxy" {
		t.Fatal("route section was damaged")
	}
	if _, err := os.Stat(path + ".bak"); err != nil {
		t.Fatal("backup file was not created")
	}
}

func TestAddOutboundReplacesSameTag(t *testing.T) {
	path := writeSample(t)

	err := New(path).AddOutbound(map[string]any{
		"type": "vless", "tag": "old-node", "server": "updated.example.com", "server_port": 443,
	})
	if err != nil {
		t.Fatalf("AddOutbound: %v", err)
	}

	cfg := load(t, path)
	replaced := outboundByTag(t, cfg, "old-node")
	if replaced["server"] != "updated.example.com" {
		t.Fatalf("outbound not replaced: %v", replaced)
	}

	// No duplicates in selector
	members := outboundByTag(t, cfg, "proxy")["outbounds"].([]any)
	count := 0
	for _, m := range members {
		if m == "old-node" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("selector members corrupted: %v", members)
	}
}

// A server named like a group is saved under another name: the group stays,
// and one such node does not fail the whole import
func TestAddOutboundSuffixesGroupTag(t *testing.T) {
	path := writeSample(t)

	result, err := New(path).AddOutbounds([]map[string]any{{"type": "vless", "tag": "proxy", "server": "p.example.com"}}, nil)
	if err != nil {
		t.Fatalf("AddOutbounds: %v", err)
	}
	if !reflect.DeepEqual(result.Tags, []string{"proxy (2)"}) ||
		!reflect.DeepEqual(result.Renamed, []domain.TagRename{{From: "proxy", To: "proxy (2)"}}) {
		t.Fatalf("result = %+v", result)
	}
	cfg := load(t, path)
	if outboundByTag(t, cfg, "proxy")["type"] != "selector" {
		t.Fatal("the selector was replaced")
	}
	if outboundByTag(t, cfg, "proxy (2)")["server"] != "p.example.com" {
		t.Fatalf("imported node missing: %v", cfg["outbounds"])
	}
}

// An import never takes over direct, block, dns, the DPI-bypass outbound or
// a subscription's node: a link or a QR code named "direct" would otherwise
// send the traffic the user routes past the VPN to its server
func TestImportDoesNotReplaceProtectedOutbounds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{
  "outbounds": [
    {"type": "selector", "tag": "proxy", "outbounds": ["sub-node", "direct"]},
    {"type": "direct", "tag": "direct"},
    {"type": "block", "tag": "block"},
    {"type": "http", "tag": "dpi-bypass", "server": "127.0.0.1", "server_port": 3128},
    {"type": "vless", "tag": "sub-node", "server": "s.example.com"}
  ],
  "route": {"rules": [{"domain_suffix": [".example.org"], "outbound": "direct"}], "final": "proxy"}
}`), 0644); err != nil {
		t.Fatal(err)
	}

	var incoming []map[string]any
	for _, tag := range []string{"direct", "block", "dpi-bypass", "sub-node"} {
		incoming = append(incoming, map[string]any{"type": "vless", "tag": tag, "server": "evil.example.com"})
	}
	result, err := New(path).AddOutbounds(incoming, []string{"sub-node"})
	if err != nil {
		t.Fatalf("AddOutbounds: %v", err)
	}
	want := []string{"direct (2)", "block (2)", "dpi-bypass (2)", "sub-node (2)"}
	if !reflect.DeepEqual(result.Tags, want) || len(result.Renamed) != 4 {
		t.Fatalf("result = %+v", result)
	}

	cfg := load(t, path)
	for tag, typ := range map[string]string{"direct": "direct", "block": "block", "dpi-bypass": "http"} {
		if got := outboundByTag(t, cfg, tag); got["type"] != typ {
			t.Fatalf("%s was replaced: %v", tag, got)
		}
	}
	if outboundByTag(t, cfg, "sub-node")["server"] != "s.example.com" {
		t.Fatal("the subscription's node was replaced")
	}
	rule := cfg["route"].(map[string]any)["rules"].([]any)[0].(map[string]any)
	if rule["outbound"] != "direct" {
		t.Fatalf("route rule changed: %v", rule)
	}

	// Importing the same link again updates the renamed server instead of
	// adding "direct (3)"
	again, err := New(path).AddOutbounds([]map[string]any{{"type": "vless", "tag": "direct", "server": "new.example.com"}}, []string{"sub-node"})
	if err != nil {
		t.Fatalf("AddOutbounds again: %v", err)
	}
	if !reflect.DeepEqual(again.Tags, []string{"direct (2)"}) {
		t.Fatalf("re-import tags = %v", again.Tags)
	}
	cfg = load(t, path)
	if outboundByTag(t, cfg, "direct (2)")["server"] != "new.example.com" || outboundByTag(t, cfg, "direct (3)") != nil {
		t.Fatalf("re-import did not update the renamed server: %v", cfg["outbounds"])
	}
}

// Re-importing a server keeps the detour the DPI chain (or the user) set on
// it: a share link never carries one
func TestReimportKeepsDetour(t *testing.T) {
	path := writeSample(t)
	editor := New(path)
	if _, err := editor.AddOutbounds([]map[string]any{{"type": "vless", "tag": "old-node", "server": "old.example.com", "server_port": 443, "detour": "direct"}}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := editor.AddOutbounds([]map[string]any{{"type": "vless", "tag": "old-node", "server": "new.example.com", "server_port": 443}}, nil); err != nil {
		t.Fatal(err)
	}
	node := outboundByTag(t, load(t, path), "old-node")
	if node["server"] != "new.example.com" || node["detour"] != "direct" {
		t.Fatalf("node = %v", node)
	}
}

// An identical re-import leaves the file alone (nothing to restart for)
func TestIdenticalImportDoesNotRewrite(t *testing.T) {
	path := writeSample(t)
	result, err := New(path).AddOutbounds([]map[string]any{{"type": "vless", "tag": "old-node", "server": "old.example.com", "server_port": 443}}, nil)
	if err != nil {
		t.Fatalf("AddOutbounds: %v", err)
	}
	if result.Changed || !reflect.DeepEqual(result.Tags, []string{"old-node"}) {
		t.Fatalf("result = %+v", result)
	}
	if _, err := os.Stat(path + ".bak"); !os.IsNotExist(err) {
		t.Fatal("an unchanged config was rewritten")
	}
}

func TestAddOutboundMissingConfig(t *testing.T) {
	err := New(filepath.Join(t.TempDir(), "missing.json")).AddOutbound(map[string]any{"tag": "x"})
	if err == nil {
		t.Fatal("expected error for missing config")
	}
}
