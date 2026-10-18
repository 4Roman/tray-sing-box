//go:build windows

package configfile

import (
	"maps"
	"reflect"
	"strings"
	"testing"

	"tray-sing-box/internal/domain"
)

// The config of the latency test instance against the real sing-box check
// (SINGBOX_REAL_DIR, see realValidator): built from realistic configs it must
// be one sing-box accepts — with the clash_api the prober adds — or the test
// instance would not start. check builds the whole instance (box.New: the
// outbounds, the DNS servers, the clash server) without starting it.

// withProbeAPI is the plan's config as the prober runs it
func withProbeAPI(t *testing.T, plan *domain.ProbePlan) []byte {
	t.Helper()
	cfg := maps.Clone(plan.Config)
	cfg["experimental"] = map[string]any{"clash_api": map[string]any{
		"external_controller": "127.0.0.1:9090",
		"secret":              strings.Repeat("5e", 32),
	}}
	body, err := marshalIndent(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

const realTUNConfig = `{
  "log": {"level": "info", "output": "box.log", "timestamp": true},
  "dns": {
    "servers": [
      {"type": "https", "tag": "remote", "server": "1.1.1.1", "detour": "proxy"},
      {"type": "udp", "tag": "local-dns", "server": "223.5.5.5"},
      {"type": "fakeip", "tag": "fake", "inet4_range": "198.18.0.0/15"}
    ],
    "rules": [
      {"rule_set": "geosite-ru", "server": "local-dns"},
      {"query_type": ["A", "AAAA"], "server": "fake"}
    ],
    "final": "remote",
    "strategy": "ipv4_only"
  },
  "inbounds": [
    {"type": "tun", "tag": "tun-in", "address": ["172.19.0.1/30"], "auto_route": true, "strict_route": true},
    {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080}
  ],
  "outbounds": [
    {"type": "selector", "tag": "proxy", "outbounds": ["auto", "de-reality", "nl-chain", "ss-stls"], "default": "auto"},
    {"type": "urltest", "tag": "auto", "outbounds": ["de-reality", "fi-hy2"], "interval": "5m"},
    {"type": "vless", "tag": "de-reality", "server": "de.example.com", "server_port": 443, "domain_resolver": "local-dns",
     "uuid": "11111111-2222-4333-8444-555555555555", "flow": "xtls-rprx-vision",
     "tls": {"enabled": true, "server_name": "www.example.com", "utls": {"enabled": true, "fingerprint": "chrome"},
             "reality": {"enabled": true, "public_key": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", "short_id": "6ba85179"}}},
    {"type": "hysteria2", "tag": "fi-hy2", "server": "192.0.2.20", "server_port": 443, "password": "hy2-password",
     "tls": {"enabled": true, "server_name": "fi.example.com", "alpn": ["h3"]}},
    {"type": "trojan", "tag": "relay-1", "server": "192.0.2.30", "server_port": 443, "password": "trojan-password",
     "tls": {"enabled": true, "server_name": "relay.example.com"}},
    {"type": "vless", "tag": "nl-chain", "server": "192.0.2.40", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555556",
     "detour": "relay-1", "transport": {"type": "ws", "path": "/ws", "headers": {"Host": "cdn.example.com"}},
     "tls": {"enabled": true, "server_name": "cdn.example.com"}},
    {"type": "shadowtls", "tag": "stls", "server": "192.0.2.50", "server_port": 443, "version": 3, "password": "stls-password",
     "tls": {"enabled": true, "server_name": "www.microsoft.com"}},
    {"type": "shadowsocks", "tag": "ss-stls", "method": "2022-blake3-aes-128-gcm", "password": "AAECAwQFBgcICQoLDA0ODw==", "detour": "stls"},
    {"type": "direct", "tag": "direct"},
    {"type": "block", "tag": "block"}
  ],
  "route": {
    "rules": [
      {"action": "sniff"},
      {"protocol": "dns", "action": "hijack-dns"},
      {"rule_set": "geosite-ru", "outbound": "direct"}
    ],
    "rule_set": [
      {"type": "remote", "tag": "geosite-ru", "format": "binary", "url": "https://example.com/geosite-ru.srs", "download_detour": "proxy"}
    ],
    "final": "proxy",
    "auto_detect_interface": true,
    "default_domain_resolver": "local-dns"
  },
  "experimental": {
    "cache_file": {"enabled": true},
    "clash_api": {"external_controller": "127.0.0.1:9090", "secret": "user-secret-0123456789abcdef"}
  }
}`

const realEndpointConfig = `{
  "certificate": {"store": "system"},
  "dns": {
    "servers": [
      {"type": "tls", "tag": "dot", "server": "dns.google", "domain_resolver": "boot", "detour": "chain-group"},
      {"type": "udp", "tag": "boot", "server": "8.8.8.8"},
      {"type": "local", "tag": "sys"}
    ],
    "final": "dot"
  },
  "endpoints": [
    {"type": "wireguard", "tag": "wg-ep", "address": ["10.0.0.2/32"], "private_key": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
     "peers": [{"address": "192.0.2.60", "port": 51820, "public_key": "HxwdHhsaGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQA=", "allowed_ips": ["0.0.0.0/0"]}]}
  ],
  "inbounds": [{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2081}],
  "outbounds": [
    {"type": "selector", "tag": "chain-group", "outbounds": ["hop-a", "hop-b"]},
    {"type": "vless", "tag": "hop-a", "server": "192.0.2.70", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555557",
     "tls": {"enabled": true, "server_name": "hop-a.example.com", "utls": {"enabled": true, "fingerprint": "chrome"}}},
    {"type": "vmess", "tag": "hop-b", "server": "hop-b.example.com", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555558",
     "security": "auto", "domain_resolver": {"server": "boot", "strategy": "ipv4_only"}},
    {"type": "trojan", "tag": "via-group", "server": "192.0.2.80", "server_port": 443, "password": "trojan-password-2",
     "detour": "chain-group", "tls": {"enabled": true, "server_name": "via.example.com"}},
    {"type": "vless", "tag": "via-wg", "server": "192.0.2.90", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555559",
     "detour": "wg-ep"},
    {"type": "socks", "tag": "info", "server": "127.0.0.1", "server_port": 1080},
    {"type": "http", "tag": "dpi-bypass", "server": "127.0.0.1", "server_port": 3128},
    {"type": "vless", "tag": "via-dpi", "server": "192.0.2.100", "server_port": 443, "uuid": "11111111-2222-4333-8444-55555555555a",
     "detour": "dpi-bypass", "tls": {"enabled": true, "server_name": "dpi.example.com"}},
    {"type": "direct", "tag": "direct"}
  ],
  "route": {"final": "chain-group", "default_domain_resolver": {"server": "boot"}}
}`

func TestProbeConfigPassesRealCheck(t *testing.T) {
	validate := realValidator(t)
	cases := []struct {
		name, config       string
		testable           []string
		outbounds, servers []string
	}{
		{
			name: "TUN, rules, rule set, fakeip, a chain, groups, shadowtls", config: realTUNConfig,
			testable:  []string{"de-reality", "fi-hy2", "relay-1", "nl-chain", "ss-stls"},
			outbounds: []string{"proxy", "auto", "de-reality", "fi-hy2", "relay-1", "nl-chain", "stls", "ss-stls"},
			servers:   []string{"remote", "local-dns"},
		},
		{
			name: "certificate, an endpoint, DNS through a group, the DPI chain", config: realEndpointConfig,
			testable:  []string{"hop-a", "hop-b", "via-group", "dpi-bypass", "via-dpi"},
			outbounds: []string{"chain-group", "hop-a", "hop-b", "via-group", "dpi-bypass", "via-dpi"},
			servers:   []string{"dot", "boot"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The source itself passes: what the test instance refuses is
			// then the plan's doing
			if err := validate([]byte(tc.config)); err != nil {
				t.Fatalf("the source config does not pass sing-box check: %v", err)
			}
			plan := probePlan(probeConfig(t, tc.config))
			var testable []string
			for _, c := range plan.Candidates {
				if c.Testable {
					testable = append(testable, c.Tag)
				}
			}
			if !reflect.DeepEqual(testable, tc.testable) {
				t.Errorf("testable = %v, want %v", testable, tc.testable)
			}
			outbounds, servers := probeTags(t, plan)
			if !reflect.DeepEqual(outbounds, tc.outbounds) || !reflect.DeepEqual(servers, tc.servers) {
				t.Errorf("probe config carries %v / %v, want %v / %v", outbounds, servers, tc.outbounds, tc.servers)
			}
			if err := validate(withProbeAPI(t, plan)); err != nil {
				t.Fatalf("the probe config does not pass sing-box check: %v", err)
			}
		})
	}
}

// An outbound sing-box cannot create makes the test instance fail as a
// whole; Exclude reads sing-box's own answer, leaves it and what dials
// through it out, and the rest passes
func TestProbeExcludeRealCheck(t *testing.T) {
	validate := realValidator(t)
	const config = `{
	  "outbounds": [
	    {"type": "vless", "tag": "good", "server": "192.0.2.10", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555555",
	     "tls": {"enabled": true, "server_name": "good.example.com"}},
	    {"type": "vless", "tag": "no-utls", "server": "192.0.2.11", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555556",
	     "flow": "xtls-rprx-vision",
	     "tls": {"enabled": true, "server_name": "www.example.com",
	             "reality": {"enabled": true, "public_key": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", "short_id": "6ba85179"}}},
	    {"type": "trojan", "tag": "through-it", "server": "192.0.2.12", "server_port": 443, "password": "trojan-password",
	     "detour": "no-utls", "tls": {"enabled": true, "server_name": "t.example.com"}},
	    {"type": "direct", "tag": "direct"}
	  ]
	}`
	plan := probePlan(probeConfig(t, config))
	err := validate(withProbeAPI(t, plan))
	if err == nil {
		t.Fatal("sing-box check passed a REALITY node without uTLS: the test needs another broken node")
	}
	next, ok := plan.Exclude(plan.Redact(err.Error()))
	if !ok {
		t.Fatalf("Exclude did not find the outbound in sing-box's answer: %v", err)
	}
	if c := candidateByTag(t, next, "no-utls"); c.Testable || !strings.HasPrefix(c.Note, "не проверяется: sing-box не смог его запустить отдельно: ") ||
		len(c.Note) <= len("не проверяется: sing-box не смог его запустить отдельно: ") {
		t.Errorf("the outbound sing-box refused: %+v", c)
	}
	if c := candidateByTag(t, next, "through-it"); c.Testable || c.Note != "не проверяется: зависит от «no-utls»" {
		t.Errorf("the outbound through it: %+v", c)
	}
	if c := candidateByTag(t, next, "good"); !c.Testable || !c.Eligible {
		t.Errorf("the good outbound: %+v", c)
	}
	if err := validate(withProbeAPI(t, next)); err != nil {
		t.Errorf("after the exclusion the probe config still does not pass: %v", err)
	}
	t.Logf("note: %s", candidateByTag(t, next, "no-utls").Note)
}
