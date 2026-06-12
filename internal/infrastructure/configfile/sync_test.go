package configfile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

const syncBaseConfig = `{
  "outbounds": [
    {"type": "vless", "tag": "sub-a", "server": "a.example.com"},
    {"type": "vless", "tag": "sub-b", "server": "b.example.com"},
    {"type": "vless", "tag": "user-node", "server": "u.example.com", "detour": "sub-a"},
    {"type": "selector", "tag": "select", "outbounds": ["sub-a", "sub-b", "user-node"]},
    {"type": "direct", "tag": "direct"}
  ],
  "route": {
    "rules": [{"domain": ["x.com"], "outbound": "sub-a"}],
    "final": "sub-b"
  }
}`

func newSyncEditor(t *testing.T) (*Editor, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(syncBaseConfig), 0644); err != nil {
		t.Fatal(err)
	}
	return New(path), path
}

func loadConfig(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func outboundTags(cfg map[string]any) []string {
	var tags []string
	for _, item := range cfg["outbounds"].([]any) {
		o := item.(map[string]any)
		tags = append(tags, o["tag"].(string))
	}
	return tags
}

func TestSyncReplacesAddsAndRemoves(t *testing.T) {
	editor, path := newSyncEditor(t)

	// Subscription owned sub-a and sub-b; new fetch has sub-b and sub-c
	result, err := editor.SyncOutbounds([]string{"sub-a", "sub-b"}, []map[string]any{
		{"type": "vless", "tag": "sub-b", "server": "b2.example.com"},
		{"type": "vless", "tag": "sub-c", "server": "c.example.com"},
	})
	if err != nil {
		t.Fatalf("SyncOutbounds: %v", err)
	}
	if !result.Changed {
		t.Fatal("config must be marked changed")
	}
	if !reflect.DeepEqual(result.Added, []string{"sub-c"}) {
		t.Fatalf("Added = %v", result.Added)
	}
	if !reflect.DeepEqual(result.Removed, []string{"sub-a"}) {
		t.Fatalf("Removed = %v", result.Removed)
	}

	cfg := loadConfig(t, path)
	tags := outboundTags(cfg)
	sort.Strings(tags)
	want := []string{"direct", "select", "sub-b", "sub-c", "user-node"}
	if !reflect.DeepEqual(tags, want) {
		t.Fatalf("outbound tags = %v, want %v", tags, want)
	}

	// sub-b replaced with the new server
	for _, item := range cfg["outbounds"].([]any) {
		o := item.(map[string]any)
		if o["tag"] == "sub-b" && o["server"] != "b2.example.com" {
			t.Fatalf("sub-b not replaced: %v", o)
		}
		// detour to the removed sub-a must be cleared
		if o["tag"] == "user-node" {
			if _, has := o["detour"]; has {
				t.Fatalf("detour to removed outbound not cleared: %v", o)
			}
		}
		// selector membership: sub-a out, sub-c in
		if o["tag"] == "select" {
			members := o["outbounds"].([]any)
			got := make([]string, len(members))
			for i, m := range members {
				got[i] = m.(string)
			}
			sort.Strings(got)
			if !reflect.DeepEqual(got, []string{"sub-b", "sub-c", "user-node"}) {
				t.Fatalf("selector members = %v", got)
			}
		}
	}

	// Route rule pointed at removed sub-a -> repointed to the first new tag
	route := cfg["route"].(map[string]any)
	rule := route["rules"].([]any)[0].(map[string]any)
	if rule["outbound"] != "sub-b" {
		t.Fatalf("rule not repointed: %v", rule)
	}
	if route["final"] != "sub-b" {
		t.Fatalf("final must be untouched, got %v", route["final"])
	}
}

func TestSyncRemoveAllRepointsToSurvivingProxy(t *testing.T) {
	editor, path := newSyncEditor(t)

	result, err := editor.SyncOutbounds([]string{"sub-a", "sub-b"}, nil)
	if err != nil {
		t.Fatalf("SyncOutbounds: %v", err)
	}
	if !result.Changed || len(result.Removed) != 2 {
		t.Fatalf("result = %+v", result)
	}

	cfg := loadConfig(t, path)
	route := cfg["route"].(map[string]any)
	rule := route["rules"].([]any)[0].(map[string]any)
	if rule["outbound"] != "user-node" {
		t.Fatalf("rule must be repointed to the surviving proxy: %v", rule)
	}
	if route["final"] != "user-node" {
		t.Fatalf("final must be repointed to the surviving proxy: %v", route["final"])
	}
}

func TestSyncNoChangeDoesNotRewrite(t *testing.T) {
	editor, path := newSyncEditor(t)

	// Same outbounds as already in the config
	result, err := editor.SyncOutbounds([]string{"sub-a", "sub-b"}, []map[string]any{
		{"type": "vless", "tag": "sub-a", "server": "a.example.com"},
		{"type": "vless", "tag": "sub-b", "server": "b.example.com"},
	})
	if err != nil {
		t.Fatalf("SyncOutbounds: %v", err)
	}
	if result.Changed {
		t.Fatal("identical sync must not be reported as a change")
	}
	if _, err := os.Stat(path + ".bak"); !os.IsNotExist(err) {
		t.Fatal("identical sync must not write a backup")
	}
}

func TestSyncRequiresTags(t *testing.T) {
	editor, _ := newSyncEditor(t)
	if _, err := editor.SyncOutbounds(nil, []map[string]any{{"type": "vless"}}); err == nil {
		t.Fatal("outbound without tag must be rejected")
	}
}
