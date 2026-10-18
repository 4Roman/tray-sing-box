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

// The main selector as the DNS detour, one member of it sing-box cannot
// create on its own (the VPN does not start: the user checks which servers
// still work): after Exclude the other members stay testable — the DNS
// server is carried with the group copied without that member and without
// it as the default — and the test instance passes the real check
func TestProbeGlobalDNSGroupRealCheck(t *testing.T) {
	validate := realValidator(t)
	const config = `{
	  "dns": {
	    "servers": [
	      {"type": "https", "tag": "remote", "server": "1.1.1.1", "detour": "proxy"},
	      {"type": "udp", "tag": "local-dns", "server": "223.5.5.5"}
	    ],
	    "final": "remote"
	  },
	  "outbounds": [
	    {"type": "selector", "tag": "proxy", "outbounds": ["good", "broken", "other"], "default": "broken"},
	    {"type": "vless", "tag": "good", "server": "good.example.com", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555555",
	     "tls": {"enabled": true, "server_name": "good.example.com"}},
	    {"type": "vless", "tag": "broken", "server": "192.0.2.11", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555556",
	     "flow": "xtls-rprx-vision",
	     "tls": {"enabled": true, "server_name": "www.example.com",
	             "reality": {"enabled": true, "public_key": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", "short_id": "6ba85179"}}},
	    {"type": "trojan", "tag": "other", "server": "192.0.2.12", "server_port": 443, "password": "trojan-password",
	     "tls": {"enabled": true, "server_name": "other.example.com"}},
	    {"type": "direct", "tag": "direct"}
	  ],
	  "route": {"final": "proxy", "default_domain_resolver": "local-dns"}
	}`
	if err := validate([]byte(config)); err == nil || !strings.Contains(err.Error(), "uTLS is required by reality client") {
		t.Fatalf("the source config: %v, want sing-box to refuse the REALITY node without uTLS", err)
	}
	plan := probePlan(probeConfig(t, config))
	err := validate(withProbeAPI(t, plan))
	if err == nil {
		t.Fatal("sing-box check passed the probe config with the broken node")
	}
	next, ok := plan.Exclude(plan.Redact(err.Error()))
	if !ok {
		t.Fatalf("Exclude did not find the outbound in sing-box's answer: %v", err)
	}
	if c := candidateByTag(t, next, "broken"); c.Testable {
		t.Errorf("broken: %+v", c)
	}
	for _, tag := range []string{"good", "other"} {
		if c := candidateByTag(t, next, tag); !c.Testable || !c.Eligible || c.Note != "" {
			t.Errorf("%s: %+v, want testable", tag, c)
		}
	}
	outbounds, servers := probeTags(t, next)
	if !reflect.DeepEqual(outbounds, []string{"proxy", "good", "other"}) || !reflect.DeepEqual(servers, []string{"remote", "local-dns"}) {
		t.Errorf("probe config carries %v / %v", outbounds, servers)
	}
	if err := validate(withProbeAPI(t, next)); err != nil {
		t.Errorf("after the exclusion the probe config does not pass: %v", err)
	}
}

// A config that resolves server names through the DNS rules: the rules the
// test instance copies make sing-box judge it the way it judges config.json
// — refused without ENABLE_DEPRECATED_OUTBOUND_DNS_RULE_ITEM and
// ENABLE_DEPRECATED_MISSING_DOMAIN_RESOLVER (SingBoxEnv passes the user's
// switches to both), accepted with them
func TestProbeLegacyResolutionRealCheck(t *testing.T) {
	validate := realValidator(t)
	const config = `{
	  "dns": {
	    "servers": [
	      {"type": "https", "tag": "remote", "server": "1.1.1.1", "detour": "proxy"},
	      {"type": "udp", "tag": "local", "server": "223.5.5.5"}
	    ],
	    "rules": [{"outbound": "any", "server": "local"}],
	    "final": "remote"
	  },
	  "outbounds": [
	    {"type": "selector", "tag": "proxy", "outbounds": ["a", "b"]},
	    {"type": "vless", "tag": "a", "server": "a.example.com", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555555",
	     "tls": {"enabled": true, "server_name": "a.example.com"}},
	    {"type": "trojan", "tag": "b", "server": "b.example.com", "server_port": 443, "password": "trojan-password",
	     "tls": {"enabled": true, "server_name": "b.example.com"}}
	  ],
	  "route": {"final": "proxy"}
	}`
	plan := probePlan(probeConfig(t, config))
	for _, tag := range []string{"a", "b"} {
		if c := candidateByTag(t, plan, tag); !c.Testable || !c.Eligible {
			t.Errorf("%s: %+v", tag, c)
		}
	}
	if rules := probeRules(plan); len(rules) != 1 {
		t.Fatalf("probe DNS rules %v, want the outbound rule", rules)
	}
	if _, servers := probeTags(t, plan); !reflect.DeepEqual(servers, []string{"remote", "local"}) {
		t.Errorf("probe DNS servers %v", servers)
	}
	probe := withProbeAPI(t, plan)
	for _, tc := range []struct {
		rule, resolver string
		pass           bool
	}{
		{"false", "false", false},
		{"true", "false", false},
		{"false", "true", false},
		{"true", "true", true},
	} {
		t.Run("OUTBOUND_DNS_RULE_ITEM="+tc.rule+",MISSING_DOMAIN_RESOLVER="+tc.resolver, func(t *testing.T) {
			t.Setenv("ENABLE_DEPRECATED_OUTBOUND_DNS_RULE_ITEM", tc.rule)
			t.Setenv("ENABLE_DEPRECATED_MISSING_DOMAIN_RESOLVER", tc.resolver)
			source, test := validate([]byte(config)), validate(probe)
			if (source == nil) != tc.pass || (test == nil) != tc.pass {
				t.Errorf("config.json: %v; the test instance: %v; want both to pass: %v", source, test, tc.pass)
			}
		})
	}
}
