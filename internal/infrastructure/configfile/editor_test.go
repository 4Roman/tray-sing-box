package configfile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
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

func TestAddOutboundRejectsGroupTagCollision(t *testing.T) {
	path := writeSample(t)

	err := New(path).AddOutbound(map[string]any{"type": "vless", "tag": "proxy"})
	if err == nil {
		t.Fatal("expected error when tag collides with a selector group")
	}
}

func TestAddOutboundMissingConfig(t *testing.T) {
	err := New(filepath.Join(t.TempDir(), "missing.json")).AddOutbound(map[string]any{"tag": "x"})
	if err == nil {
		t.Fatal("expected error for missing config")
	}
}
