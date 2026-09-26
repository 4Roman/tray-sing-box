//go:build windows

package configfile

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"tray-sing-box/internal/infrastructure/singboxcheck"
)

// Against the real sing-box check. Enabled by pointing SINGBOX_REAL_DIR at a
// directory with sing-box.exe; it is only run from there — the config under
// check and sing-box's TEMP are in a temp dir of the test.
func realValidator(t *testing.T) Validator {
	t.Helper()
	dir := os.Getenv("SINGBOX_REAL_DIR")
	if dir == "" {
		t.Skip("SINGBOX_REAL_DIR not set")
	}
	if _, err := os.Stat(filepath.Join(dir, "sing-box.exe")); err != nil {
		t.Skipf("sing-box.exe not found in %s", dir)
	}
	return singboxcheck.NewValidator(dir, t.TempDir())
}

const realBaseConfig = `{
  "log": {"level": "warn"},
  "outbounds": [
    {"type": "selector", "tag": "proxy", "outbounds": ["direct"]},
    {"type": "direct", "tag": "direct"}
  ],
  "route": {"final": "proxy"}
}`

// realityNode is a VLESS REALITY node as the parser makes it; utls false
// leaves out the uTLS block sing-box requires for REALITY
func realityNode(tag, server string, utls bool) map[string]any {
	tls := map[string]any{
		"enabled":     true,
		"server_name": "www.example.com",
		"reality": map[string]any{
			"enabled":    true,
			"public_key": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
			"short_id":   "6ba85179",
		},
	}
	if utls {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": "chrome"}
	}
	return map[string]any{
		"type": "vless", "tag": tag, "server": server, "server_port": 443,
		"uuid": "11111111-2222-4333-8444-555555555555", "flow": "xtls-rprx-vision", "tls": tls,
	}
}

// A batch with nodes sing-box refuses keeps the others: each refused one is
// named with sing-box's own reason, the saved config passes the real check
func TestRealCheckLeavesOutRefusedNodes(t *testing.T) {
	validate := realValidator(t)
	path := writeConfig(t, realBaseConfig)
	editor := New(path)
	editor.SetValidator(validate)

	badFlow := realityNode("bad-flow", "192.0.2.13", true)
	badFlow["flow"] = "xtls-rprx-vision-udp443"
	result, err := editor.AddOutbounds([]map[string]any{
		realityNode("DE-1", "192.0.2.10", true),
		realityNode("no-utls", "192.0.2.11", false),
		realityNode("NL-1", "192.0.2.12", true),
		badFlow,
	}, nil)
	if err != nil {
		t.Fatalf("AddOutbounds: %v", err)
	}
	if !reflect.DeepEqual(result.Tags, []string{"DE-1", "NL-1"}) {
		t.Fatalf("saved %v, skipped %+v", result.Tags, result.Skipped)
	}
	reasons := map[string]string{}
	for _, sk := range result.Skipped {
		reasons[sk.Name] = sk.Reason
		t.Logf("skipped %q: %s", sk.Name, sk.Reason)
	}
	if !strings.Contains(reasons["no-utls"], "uTLS is required by reality client") ||
		!strings.Contains(reasons["bad-flow"], "unsupported flow: xtls-rprx-vision-udp443") {
		t.Fatalf("reasons = %v", reasons)
	}
	for name, reason := range reasons {
		if strings.Contains(reason, "outbound[") || strings.Contains(reason, "FATAL") {
			t.Fatalf("reason for %s = %q", name, reason)
		}
	}

	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := validate(saved); err != nil {
		t.Fatalf("the saved config fails sing-box check: %v", err)
	}

	// The same nodes as a subscription that renamed them (live counters)
	// and brought one more sing-box refuses: kept in place, no restart
	sync, err := editor.SyncOutbounds(result.Tags, []map[string]any{
		realityNode("DE-1 | 11GB", "192.0.2.10", true),
		realityNode("NL-1 | 11GB", "192.0.2.12", true),
		realityNode("no-utls-2", "192.0.2.14", false),
	})
	if err != nil {
		t.Fatalf("SyncOutbounds: %v", err)
	}
	if len(sync.Renamed) != 2 || len(sync.Skipped) != 1 || sync.NeedsRestart || !reflect.DeepEqual(sync.Tags, []string{"DE-1 | 11GB", "NL-1 | 11GB"}) {
		t.Fatalf("sync = %+v", sync)
	}
	saved, _ = os.ReadFile(path)
	if err := validate(saved); err != nil {
		t.Fatalf("the synced config fails sing-box check: %v", err)
	}
}

// A refusal that is about the config around the new nodes names the
// outbound by tag, not by its position in the file
func TestRealCheckErrorNamesTheOutbound(t *testing.T) {
	validate := realValidator(t)
	broken := strings.Replace(realBaseConfig, `{"type": "direct", "tag": "direct"}`,
		`{"type": "direct", "tag": "direct"}, {"type": "vless", "tag": "hand-made", "server": "192.0.2.20", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555555", "flow": "weird"}`, 1)
	editor := New(writeConfig(t, broken))
	editor.SetValidator(validate)

	_, err := editor.AddOutbounds([]map[string]any{realityNode("DE-1", "192.0.2.10", true)}, nil)
	if err == nil || !strings.Contains(err.Error(), "outbound «hand-made»") || strings.Contains(err.Error(), "outbound[") {
		t.Fatalf("error = %v", err)
	}
}
