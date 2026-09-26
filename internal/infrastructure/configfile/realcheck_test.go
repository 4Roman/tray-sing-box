//go:build windows

package configfile

import (
	"fmt"
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

// Chains against the real check, which passes a detour to a missing
// outbound and a ring (sing-box then does not start): a node chained through
// a refused one is left out with it, a node chained through a renamed one
// follows it, and no saved config has either
func TestRealCheckChains(t *testing.T) {
	validate := realValidator(t)
	path := writeConfig(t, realBaseConfig)
	editor := New(path)
	editor.SetValidator(validate)
	noProblems := func() {
		t.Helper()
		saved, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := validate(saved); err != nil {
			t.Fatalf("the saved config fails sing-box check: %v", err)
		}
		cfg, err := decodeConfig(saved)
		if err != nil {
			t.Fatal(err)
		}
		if problems := dependencyProblems(cfg); len(problems) != 0 {
			t.Fatalf("saved with %v", problems)
		}
	}

	relay := realityNode("relay", "192.0.2.10", true)
	relay["foo_bar"] = 1
	exit := realityNode("exit", "192.0.2.11", true)
	exit["detour"] = "relay"
	result, err := editor.AddOutbounds([]map[string]any{relay, exit, realityNode("good", "192.0.2.12", true)}, nil)
	if err != nil {
		t.Fatalf("AddOutbounds: %v", err)
	}
	if !reflect.DeepEqual(result.Tags, []string{"good"}) || len(result.Skipped) != 2 ||
		!strings.Contains(result.Skipped[0].Reason, `unknown field "foo_bar"`) || !strings.Contains(result.Skipped[1].Reason, "«relay»") {
		t.Fatalf("result = %+v", result)
	}
	noProblems()

	// A node named like the user's selector, and one chained through it
	chained := realityNode("F", "192.0.2.13", true)
	chained["detour"] = "proxy"
	sync, err := editor.SyncOutbounds(nil, []map[string]any{realityNode("proxy", "192.0.2.14", true), chained})
	if err != nil {
		t.Fatalf("SyncOutbounds: %v", err)
	}
	if !reflect.DeepEqual(sync.Tags, []string{"proxy (2)", "F"}) || outboundByTag(t, load(t, path), "F")["detour"] != "proxy (2)" {
		t.Fatalf("sync = %+v", sync)
	}
	noProblems()
}

// The real sing-box answers an unknown option with its position and a
// broken REALITY short_id with a crash that names none: neither costs a
// check per node
func TestRealCheckBoundedIsolation(t *testing.T) {
	validate := realValidator(t)
	calls := 0
	counting := func(raw []byte) error {
		calls++
		return validate(raw)
	}

	editor := New(writeConfig(t, realBaseConfig))
	editor.SetValidator(counting)
	var nodes []map[string]any
	for i := 0; i < 12; i++ {
		n := realityNode(fmt.Sprintf("newer-%d", i), "192.0.2.10", true)
		n["zz_newer"] = true
		nodes = append(nodes, n)
	}
	result, err := editor.AddOutbounds(append(nodes, realityNode("good", "192.0.2.11", true)), nil)
	if err != nil {
		t.Fatalf("AddOutbounds: %v", err)
	}
	if !reflect.DeepEqual(result.Tags, []string{"good"}) || len(result.Skipped) != 12 || calls > 5 {
		t.Fatalf("%d checks: %+v", calls, result)
	}

	calls = 0
	editor = New(writeConfig(t, realBaseConfig))
	editor.SetValidator(counting)
	crashing := realityNode("crashing", "192.0.2.12", true)
	crashing["tls"].(map[string]any)["reality"].(map[string]any)["short_id"] = "00112233445566778899"
	nodes = nil
	for i := 0; i < 20; i++ {
		nodes = append(nodes, realityNode(fmt.Sprintf("good-%d", i), "192.0.2.13", true))
	}
	result, err = editor.AddOutbounds(append(nodes, crashing), nil)
	if err != nil {
		t.Fatalf("AddOutbounds: %v", err)
	}
	if len(result.Tags) != 20 || len(result.Skipped) != 1 || result.Skipped[0].Name != "crashing" || calls > 16 {
		t.Fatalf("%d checks: skipped %+v", calls, result.Skipped)
	}
	t.Logf("crash: %d checks, reason %q", calls, result.Skipped[0].Reason)
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

// sing-box check passes a route.final, a DNS server's detour and an enabled
// NTP client's detour naming a missing outbound — sing-box then does not
// start. The editor refuses what would add one.
func TestRealCheckMissesStartupReferences(t *testing.T) {
	validate := realValidator(t)
	for name, config := range map[string]string{
		"final":      `{"outbounds": [{"type": "direct", "tag": "direct"}], "route": {"final": "gone"}}`,
		"DNS detour": `{"dns": {"servers": [{"type": "https", "tag": "remote", "server": "dns.example.com", "detour": "gone"}]}, "outbounds": [{"type": "direct", "tag": "direct"}]}`,
		"NTP detour": `{"ntp": {"enabled": true, "server": "time.example.com", "detour": "gone"}, "outbounds": [{"type": "direct", "tag": "direct"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := validate([]byte(config)); err != nil {
				t.Fatalf("sing-box check refuses it now (%v): the refusal's «sing-box check этого не замечает» is out of date", err)
			}
			err := New(filepath.Join(t.TempDir(), "config.json")).CreateConfig([]byte(config))
			if err == nil || !strings.Contains(err.Error(), "указывает на «gone», а такого outbound нет") {
				t.Fatalf("CreateConfig: %v", err)
			}
		})
	}
}
