package configfile

import (
	"bytes"
	"os"
	"reflect"
	"strings"
	"testing"

	"tray-sing-box/internal/domain"
)

// 3x-ui's default remark carries the traffic and the days left, so the
// provider "renames" its nodes at every refresh
const (
	deOld = "DE|📊12.4GB|⏳29D"
	nlOld = "NL|📊12.4GB|⏳29D"
	deNew = "DE|📊11.9GB|⏳28D"
	nlNew = "NL|📊11.9GB|⏳28D"
)

const renameConfig = `{
  "dns": {
    "servers": [{"type": "https", "tag": "remote", "server": "dns.example.com", "detour": "` + nlOld + `"}],
    "rules": [{"outbound": ["` + nlOld + `"], "server": "remote"}]
  },
  "outbounds": [
    {"type": "selector", "tag": "proxy", "outbounds": ["` + deOld + `", "` + nlOld + `", "direct"], "default": "` + nlOld + `"},
    {"type": "vless", "tag": "` + deOld + `", "server": "192.0.2.10", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555555"},
    {"type": "vless", "tag": "` + nlOld + `", "server": "192.0.2.11", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555555", "detour": "dpi-bypass"},
    {"type": "http", "tag": "dpi-bypass", "server": "127.0.0.1", "server_port": 3128},
    {"type": "direct", "tag": "direct"}
  ],
  "route": {
    "rules": [
      {"domain_suffix": [".example.org"], "outbound": "` + nlOld + `"},
      {"type": "logical", "mode": "and", "rules": [{"network": "udp"}, {"port": 443}], "outbound": "` + nlOld + `"}
    ],
    "rule_set": [{"type": "remote", "tag": "geo", "format": "binary", "url": "https://example.com/geo.srs", "download_detour": "` + nlOld + `"}],
    "final": "proxy"
  }
}`

func vlessNode(tag, server string) map[string]any {
	return map[string]any{"type": "vless", "tag": tag, "server": server, "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555555"}
}

// A node renamed by the provider stays the same node: its place, the detour
// the DPI chain set on it and every reference follow the new name, and the
// running VPN is not restarted for it
func TestSyncKeepsRenamedNode(t *testing.T) {
	path := writeConfig(t, renameConfig)
	editor := New(path)

	fresh := []map[string]any{vlessNode(deNew, "192.0.2.10"), vlessNode(nlNew, "192.0.2.11")}
	result, err := editor.SyncOutbounds([]string{deOld, nlOld}, fresh)
	if err != nil {
		t.Fatalf("SyncOutbounds: %v", err)
	}
	wantRenamed := []domain.TagRename{{From: deOld, To: deNew}, {From: nlOld, To: nlNew}}
	if !reflect.DeepEqual(result.Renamed, wantRenamed) || len(result.Added) != 0 || len(result.Removed) != 0 {
		t.Fatalf("result = %+v", result)
	}
	if !result.Changed || result.NeedsRestart {
		t.Fatalf("renames only: Changed %v, NeedsRestart %v", result.Changed, result.NeedsRestart)
	}
	if !reflect.DeepEqual(result.Tags, []string{deNew, nlNew}) {
		t.Fatalf("tags = %v", result.Tags)
	}

	cfg := load(t, path)
	if got := outboundTags(cfg); !reflect.DeepEqual(got, []string{"proxy", deNew, nlNew, "dpi-bypass", "direct"}) {
		t.Fatalf("outbounds = %v", got)
	}
	if outboundByTag(t, cfg, nlNew)["detour"] != "dpi-bypass" {
		t.Fatal("the DPI detour was lost")
	}
	selector := outboundByTag(t, cfg, "proxy")
	if !reflect.DeepEqual(selector["outbounds"], []any{deNew, nlNew, "direct"}) || selector["default"] != nlNew {
		t.Fatalf("selector = %v", selector)
	}
	route := cfg["route"].(map[string]any)
	for i, item := range route["rules"].([]any) {
		if out := item.(map[string]any)["outbound"]; out != nlNew {
			t.Fatalf("rule %d points at %v", i, out)
		}
	}
	if route["rule_set"].([]any)[0].(map[string]any)["download_detour"] != nlNew || route["final"] != "proxy" {
		t.Fatalf("route = %v", route)
	}
	dns := cfg["dns"].(map[string]any)
	if dns["servers"].([]any)[0].(map[string]any)["detour"] != nlNew {
		t.Fatalf("dns server detour = %v", dns["servers"])
	}
	if !reflect.DeepEqual(dns["rules"].([]any)[0].(map[string]any)["outbound"], []any{nlNew}) {
		t.Fatalf("dns rule = %v", dns["rules"])
	}

	// The same fetch again changes nothing
	again, err := editor.SyncOutbounds(result.Tags, fresh)
	if err != nil || again.Changed || len(again.Renamed) != 0 {
		t.Fatalf("second sync: %+v, %v", again, err)
	}
}

// A renamed node that also changed is still the same node (same server and
// account), but the change needs a restart
func TestSyncRenamedAndChangedRestarts(t *testing.T) {
	path := writeConfig(t, renameConfig)
	changed := vlessNode(nlNew, "192.0.2.11")
	changed["flow"] = "xtls-rprx-vision"

	result, err := New(path).SyncOutbounds([]string{deOld, nlOld}, []map[string]any{vlessNode(deNew, "192.0.2.10"), changed})
	if err != nil {
		t.Fatalf("SyncOutbounds: %v", err)
	}
	if len(result.Renamed) != 2 || !result.NeedsRestart {
		t.Fatalf("result = %+v", result)
	}
	cfg := load(t, path)
	if n := outboundByTag(t, cfg, nlNew); n["flow"] != "xtls-rprx-vision" || n["detour"] != "dpi-bypass" {
		t.Fatalf("node = %v", n)
	}
	if outboundByTag(t, cfg, "proxy")["default"] != nlNew {
		t.Fatal("selector default not renamed")
	}
}

// Nodes are paired by identity only when it is unambiguous: several nodes on
// one server and account that differ in the transport are different nodes
func TestSyncDoesNotPairAmbiguousNodes(t *testing.T) {
	ws := func(tag, path, alpn string) map[string]any {
		o := vlessNode(tag, "192.0.2.20")
		o["transport"] = map[string]any{"type": "ws", "path": path}
		o["tls"] = map[string]any{"enabled": true, "server_name": "example.com", "alpn": []any{alpn}}
		return o
	}
	for name, tc := range map[string]struct {
		owned    []map[string]any
		incoming []map[string]any
	}{
		"other transport path": {
			owned:    []map[string]any{ws("X", "/a", "h2")},
			incoming: []map[string]any{ws("Y", "/b", "h2")},
		},
		"identity not unique": {
			owned:    []map[string]any{ws("X1", "/a", "h2"), ws("X2", "/a", "http/1.1")},
			incoming: []map[string]any{ws("Y", "/a", "h3")},
		},
	} {
		t.Run(name, func(t *testing.T) {
			var tags []string
			var list []string
			for _, o := range tc.owned {
				tags = append(tags, tagString(o))
				raw, _ := marshalIndent(o)
				list = append(list, string(raw))
			}
			path := writeConfig(t, `{"outbounds": [`+strings.Join(list, ",")+`, {"type": "direct", "tag": "direct"}]}`)
			result, err := New(path).SyncOutbounds(tags, tc.incoming)
			if err != nil {
				t.Fatalf("SyncOutbounds: %v", err)
			}
			if len(result.Renamed) != 0 || len(result.Removed) != len(tc.owned) || !reflect.DeepEqual(result.Added, []string{"Y"}) {
				t.Fatalf("result = %+v", result)
			}
		})
	}
}

// A selector default naming a removed node is repointed with the other
// references, or dropped when the replacement is not a member: sing-box looks
// the default up among the members and does not start without it, and
// sing-box check does not notice
func TestSyncSelectorDefaultOfRemovedNode(t *testing.T) {
	const config = `{
  "outbounds": [
    {"type": "selector", "tag": "proxy", "outbounds": ["DE-1", "direct"], "default": "DE-1"},
    {"type": "vless", "tag": "DE-1", "server": "192.0.2.10", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555555"},
    {"type": "vless", "tag": "user-node", "server": "192.0.2.30", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555555"},
    {"type": "direct", "tag": "direct"}
  ],
  "route": {"final": "proxy"}
}`
	// The subscription's new node replaces it: a member of the selector
	path := writeConfig(t, config)
	if _, err := New(path).SyncOutbounds([]string{"DE-1"}, []map[string]any{vlessNode("DE-2", "192.0.2.12")}); err != nil {
		t.Fatalf("SyncOutbounds: %v", err)
	}
	if def := outboundByTag(t, load(t, path), "proxy")["default"]; def != "DE-2" {
		t.Fatalf("default = %v, want DE-2", def)
	}

	// No new node: the surviving proxy is not a member, the default goes
	path = writeConfig(t, config)
	if _, err := New(path).SyncOutbounds([]string{"DE-1"}, nil); err != nil {
		t.Fatalf("SyncOutbounds: %v", err)
	}
	selector := outboundByTag(t, load(t, path), "proxy")
	if _, has := selector["default"]; has || !reflect.DeepEqual(selector["outbounds"], []any{"direct"}) {
		t.Fatalf("selector = %v", selector)
	}
}

// A subscription never takes over an outbound it does not own — direct, or
// another subscription's node of the same name: its node gets a stable
// suffix, and each subscription keeps and removes only its own
func TestSyncSuffixesForeignNames(t *testing.T) {
	path := writeConfig(t, `{
  "outbounds": [
    {"type": "selector", "tag": "proxy", "outbounds": ["NL-1", "direct"]},
    {"type": "vless", "tag": "NL-1", "server": "192.0.2.40", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555555"},
    {"type": "direct", "tag": "direct"}
  ],
  "route": {"rules": [{"domain_suffix": [".example.org"], "outbound": "direct"}], "final": "proxy"}
}`)
	editor := New(path)
	nodeB := func() map[string]any { return vlessNode("NL-1", "192.0.2.41") }

	// Subscription B brings its own "NL-1" and one named "direct"
	result, err := editor.SyncOutbounds(nil, []map[string]any{nodeB(), vlessNode("direct", "192.0.2.42")})
	if err != nil {
		t.Fatalf("SyncOutbounds: %v", err)
	}
	wantSuffixed := []domain.TagRename{{From: "NL-1", To: "NL-1 (2)"}, {From: "direct", To: "direct (2)"}}
	if !reflect.DeepEqual(result.Suffixed, wantSuffixed) || !reflect.DeepEqual(result.Tags, []string{"NL-1 (2)", "direct (2)"}) {
		t.Fatalf("result = %+v", result)
	}
	cfg := load(t, path)
	if outboundByTag(t, cfg, "NL-1")["server"] != "192.0.2.40" || outboundByTag(t, cfg, "direct")["type"] != "direct" {
		t.Fatalf("an outbound B does not own was replaced: %v", cfg["outbounds"])
	}
	if rule := cfg["route"].(map[string]any)["rules"].([]any)[0].(map[string]any); rule["outbound"] != "direct" {
		t.Fatalf("rule = %v", rule)
	}

	// B's next refresh keeps the same names: nothing to rewrite
	result, err = editor.SyncOutbounds([]string{"NL-1 (2)", "direct (2)"}, []map[string]any{nodeB(), vlessNode("direct", "192.0.2.42")})
	if err != nil || result.Changed || !reflect.DeepEqual(result.Tags, []string{"NL-1 (2)", "direct (2)"}) {
		t.Fatalf("second refresh: %+v, %v", result, err)
	}

	// Removing subscription A takes only A's node
	if _, err := editor.SyncOutbounds([]string{"NL-1"}, nil); err != nil {
		t.Fatalf("SyncOutbounds: %v", err)
	}
	if outboundByTag(t, load(t, path), "NL-1 (2)") == nil {
		t.Fatal("B's node went with A")
	}

	// Now the name is free: B's node takes it, in place and without a restart
	result, err = editor.SyncOutbounds([]string{"NL-1 (2)", "direct (2)"}, []map[string]any{nodeB(), vlessNode("direct", "192.0.2.42")})
	if err != nil {
		t.Fatalf("SyncOutbounds: %v", err)
	}
	if !reflect.DeepEqual(result.Renamed, []domain.TagRename{{From: "NL-1 (2)", To: "NL-1"}}) || result.NeedsRestart {
		t.Fatalf("result = %+v", result)
	}
}

// One node sing-box refuses does not stop the subscription: the rest is
// synced; when it refuses every node, nothing changes
func TestSyncLeavesOutRefused(t *testing.T) {
	editor, path, _ := checkedEditor(t, syncBaseConfig)

	bad := map[string]any{"type": "vless", "tag": "sub-c", "server": "c.example.com", "flow": "xtls-rprx-vision-udp443"}
	result, err := editor.SyncOutbounds([]string{"sub-a", "sub-b"}, []map[string]any{
		{"type": "vless", "tag": "sub-a", "server": "a.example.com"},
		{"type": "vless", "tag": "sub-b", "server": "b.example.com"},
		bad,
	})
	if err != nil {
		t.Fatalf("SyncOutbounds: %v", err)
	}
	if !reflect.DeepEqual(result.Tags, []string{"sub-a", "sub-b"}) || len(result.Skipped) != 1 || result.Skipped[0].Name != "sub-c" {
		t.Fatalf("result = %+v", result)
	}
	if outboundByTag(t, load(t, path), "sub-c") != nil {
		t.Fatal("the refused node was saved")
	}

	before, _ := os.ReadFile(path)
	result, err = editor.SyncOutbounds([]string{"sub-a", "sub-b"}, []map[string]any{bad})
	if err != nil {
		t.Fatalf("SyncOutbounds: %v", err)
	}
	if len(result.Tags) != 0 || len(result.Skipped) != 1 || result.Changed {
		t.Fatalf("all refused: %+v", result)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("the owned nodes were touched although every new one was refused")
	}
}
