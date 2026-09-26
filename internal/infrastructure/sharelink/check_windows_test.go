package sharelink

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"tray-sing-box/internal/infrastructure/singboxcheck"
)

// Integration with a real sing-box: every sample the parser accepts must pass
// `sing-box check` — a node that passes the parser but not the check fails
// the whole import (one save for all of them). Enabled by pointing
// SINGBOX_REAL_DIR at a directory with sing-box.exe; nothing is written there.
func TestSamplesPassSingBoxCheck(t *testing.T) {
	dir := os.Getenv("SINGBOX_REAL_DIR")
	if dir == "" {
		t.Skip("SINGBOX_REAL_DIR not set")
	}
	if _, err := os.Stat(filepath.Join(dir, "sing-box.exe")); err != nil {
		t.Skipf("sing-box.exe not found in %s", dir)
	}
	check := singboxcheck.NewValidator(dir, t.TempDir())

	// The control: what the parser maps away is really refused by sing-box
	control := []Outbound{{"type": "vless", "tag": "control", "server": "192.0.2.10", "server_port": 443,
		"uuid": testUUID, "flow": "xtls-rprx-vision-udp443"}}
	if err := check(minimalConfig(t, control)); err == nil {
		t.Fatal("sing-box check accepted the control config: the check does not run")
	}

	groups := map[string][]Outbound{}
	var links collector
	for _, c := range acceptedLinks {
		o, err := Parse(c.link)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		links.add(o)
	}
	groups["links"] = links.outbounds
	for name, body := range profileSamples {
		outbounds, _, err := ParseAllReport(body)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		groups[name] = outbounds
	}

	names := make([]string, 0, len(groups))
	for name := range groups {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		outbounds := groups[name]
		t.Run(name, func(t *testing.T) {
			err := check(minimalConfig(t, outbounds))
			if err == nil {
				t.Logf("%d outbound(s) accepted by sing-box check", len(outbounds))
				return
			}
			t.Errorf("sing-box check: %v", err)
			// Which ones: each alone (a node with a detour needs its target)
			for _, o := range outbounds {
				if _, chained := o["detour"]; chained {
					continue
				}
				if err := check(minimalConfig(t, []Outbound{o})); err != nil {
					t.Errorf("%s: %v", o.Tag(), err)
				}
			}
		})
	}
}

// minimalConfig is a config of nothing but the outbounds
func minimalConfig(t *testing.T, outbounds []Outbound) []byte {
	t.Helper()
	data, err := json.MarshalIndent(map[string]any{
		"log":       map[string]any{"level": "error"},
		"outbounds": outbounds,
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return data
}
