package configfile

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"tray-sing-box/internal/domain"
)

// probeConfig decodes a config the way the editor does (numbers kept as
// json.Number)
func probeConfig(t *testing.T, text string) map[string]any {
	t.Helper()
	cfg, err := decodeConfig([]byte(text))
	if err != nil {
		t.Fatalf("%v\n%s", err, text)
	}
	return cfg
}

// probeTags are the tags of the outbounds and of the DNS servers of the
// test instance's config, in order
func probeTags(t *testing.T, plan *domain.ProbePlan) (outbounds, servers []string) {
	t.Helper()
	list, ok := plan.Config["outbounds"].([]any)
	if !ok {
		t.Fatalf("no outbounds list in the probe config: %v", plan.Config)
	}
	for _, item := range list {
		outbounds = append(outbounds, foldedString(item.(map[string]any), "tag"))
	}
	if dns, ok := plan.Config["dns"].(map[string]any); ok {
		list, _ := dns["servers"].([]any)
		for _, item := range list {
			servers = append(servers, foldedString(item.(map[string]any), "tag"))
		}
	}
	return outbounds, servers
}

func candidateByTag(t *testing.T, plan *domain.ProbePlan, tag string) domain.LatencyCandidate {
	t.Helper()
	for _, c := range plan.Candidates {
		if c.Tag == tag {
			return c
		}
	}
	t.Fatalf("no candidate %q in %+v", tag, plan.Candidates)
	return domain.LatencyCandidate{}
}

const uuidA = "11111111-2222-4333-8444-555555555555"

// classifyConfig has an outbound for every row of the classification
const classifyConfig = `{
  "dns": {
    "servers": [
      {"type": "udp", "tag": "plain-dns", "server": "192.0.2.53"},
      {"type": "tailscale", "tag": "ts-dns", "endpoint": "ts-ep"}
    ],
    "final": "plain-dns"
  },
  "endpoints": [
    {"type": "wireguard", "tag": "wg-ep", "address": ["10.0.0.2/32"], "private_key": "wg-private-key-value"}
  ],
  "outbounds": [
    {"type": "selector", "tag": "proxy", "outbounds": ["plain", "chained"]},
    {"type": "urltest", "tag": "auto", "outbounds": ["plain"]},
    {"type": "direct", "tag": "direct"},
    {"type": "block", "tag": "block"},
    {"type": "dns", "tag": "dns-out"},
    {"type": "shadowtls", "tag": "stls", "server": "192.0.2.9", "server_port": 443, "version": 3, "password": "stls-password"},
    {"type": "shadowsocks", "tag": "behind-stls", "method": "aes-128-gcm", "password": "ss-password", "detour": "stls"},
    {"type": "tor", "tag": "tor1", "executable_path": "C:\\tor\\tor.exe"},
    {"type": "vless", "tag": "via-tor", "server": "192.0.2.2", "server_port": 443, "uuid": "` + uuidA + `", "detour": "tor1"},
    {"type": "vless", "tag": "via-wg", "server": "192.0.2.3", "server_port": 443, "uuid": "` + uuidA + `", "detour": "wg-ep"},
    {"type": "vless", "tag": "via-missing", "server": "192.0.2.4", "server_port": 443, "uuid": "` + uuidA + `", "detour": "nowhere"},
    {"type": "hysteria2", "tag": "hy-realm", "server": "192.0.2.5", "server_port": 443, "password": "hy-password",
     "realm": {"server_url": "https://realm.example.com", "realm_id": "r1"}},
    {"type": "vless", "tag": "via-realm", "server": "192.0.2.6", "server_port": 443, "uuid": "` + uuidA + `", "detour": "hy-realm"},
    {"type": "vless", "tag": "via-ts-dns", "server": "node.example.com", "server_port": 443, "uuid": "` + uuidA + `", "domain_resolver": "ts-dns"},
    {"type": "vless", "tag": "via-netns", "server": "192.0.2.7", "server_port": 443, "uuid": "` + uuidA + `", "netns": "ns1"},
    {"type": "http", "tag": "dpi-bypass", "server": "127.0.0.1", "server_port": 3128},
    {"type": "socks", "tag": "info", "server": "127.0.0.1", "server_port": 1080},
    {"type": "socks", "tag": "zero", "server": "0.0.0.0", "server_port": 1080},
    {"type": "vless", "tag": "relay", "server": "192.0.2.10", "server_port": 443, "uuid": "` + uuidA + `"},
    {"type": "vless", "tag": "chained", "server": "192.0.2.11", "server_port": 443, "uuid": "` + uuidA + `", "detour": "relay"},
    {"type": "vless", "tag": "via-dpi", "server": "192.0.2.12", "server_port": 443, "uuid": "` + uuidA + `", "detour": "dpi-bypass"},
    {"type": "vless", "tag": "plain", "server": "192.0.2.13", "server_port": 443, "uuid": "` + uuidA + `"},
    {"Type": "vless", "type": "vmess", "tag": "two-types", "server": "192.0.2.14", "server_port": 443},
    {"type": "VLESS", "tag": "odd-case", "server": "192.0.2.15", "server_port": 443},
    {"type": "vless", "server": "192.0.2.16", "server_port": 443, "uuid": "` + uuidA + `"}
  ],
  "route": {"final": "proxy"}
}`

// Every outbound lands in the first row of the classification that applies
// to it; what is not testable never reaches the test instance unless a
// testable one dials through it
func TestProbeClassification(t *testing.T) {
	plan := probePlan(probeConfig(t, classifyConfig))

	want := []domain.LatencyCandidate{
		{Tag: "proxy", Type: "selector", Note: noteSelector},
		{Tag: "auto", Type: "urltest", Note: noteURLTest},
		{Tag: "direct", Type: "direct"},
		{Tag: "block", Type: "block"},
		{Tag: "dns-out", Type: "dns"},
		{Tag: "stls", Type: "shadowtls", Note: noteRelayOnly},
		{Tag: "behind-stls", Type: "shadowsocks", Testable: true, Eligible: true},
		{Tag: "tor1", Type: "tor", Note: "тип «tor» не проверяется"},
		{Tag: "via-tor", Type: "vless", Note: "не проверяется: зависит от «tor1»"},
		{Tag: "via-wg", Type: "vless", Note: "не проверяется: зависит от «wg-ep»"},
		{Tag: "via-missing", Type: "vless", Note: "не проверяется: зависит от «nowhere»"},
		{Tag: "hy-realm", Type: "hysteria2", Note: "не проверяется: зависит от «realm»"},
		{Tag: "via-realm", Type: "vless", Note: "не проверяется: зависит от «hy-realm»"},
		{Tag: "via-ts-dns", Type: "vless", Note: "не проверяется: зависит от «ts-dns»"},
		{Tag: "via-netns", Type: "vless", Note: "не проверяется: зависит от «ns1»"},
		{Tag: "dpi-bypass", Type: "http", Testable: true, Note: noteDPI},
		{Tag: "info", Type: "socks", Note: noteLocal},
		{Tag: "zero", Type: "socks", Note: noteLocal},
		{Tag: "relay", Type: "vless", Testable: true, Note: noteRelay},
		{Tag: "chained", Type: "vless", Testable: true, Eligible: true},
		{Tag: "via-dpi", Type: "vless", Testable: true, Eligible: true, Note: noteViaDPI},
		{Tag: "plain", Type: "vless", Testable: true, Eligible: true},
		{Tag: "two-types", Type: "vmess", Note: "тип «vless,vmess» не проверяется"},
		{Tag: "odd-case", Type: "VLESS", Note: "тип «VLESS» не проверяется"},
	}
	if !reflect.DeepEqual(plan.Candidates, want) {
		for i := range max(len(want), len(plan.Candidates)) {
			var got, exp domain.LatencyCandidate
			if i < len(plan.Candidates) {
				got = plan.Candidates[i]
			}
			if i < len(want) {
				exp = want[i]
			}
			if got != exp {
				t.Errorf("candidate %d:\n got %+v\nwant %+v", i, got, exp)
			}
		}
	}

	// The testable ones with what they dial through, in the config's order;
	// the groups, the tor outbound, the local servers and the nodes that
	// cannot be tested stay out
	outbounds, servers := probeTags(t, plan)
	wantOut := []string{"stls", "behind-stls", "dpi-bypass", "relay", "chained", "via-dpi", "plain"}
	if !reflect.DeepEqual(outbounds, wantOut) {
		t.Errorf("probe outbounds = %v, want %v", outbounds, wantOut)
	}
	if !reflect.DeepEqual(servers, []string{"plain-dns"}) {
		t.Errorf("probe DNS servers = %v, want [plain-dns]", servers)
	}
}

// The closure follows every reference sing-box resolves when it starts, to a
// fixed point, in every spelling sing-box reads as it. The outbounds reached
// are ones the test instance carries only for another's sake (local
// proxies, relays, groups): nothing else brings them in.
func TestProbeClosure(t *testing.T) {
	node := func(tag, extra string) string {
		return `{"type": "vless", "tag": "` + tag + `", "server": "192.0.2.1", "server_port": 443, "uuid": "` + uuidA + `"` + extra + `}`
	}
	local := func(tag, extra string) string {
		return `{"type": "socks", "tag": "` + tag + `", "server": "127.0.0.1", "server_port": 1080` + extra + `}`
	}
	cases := []struct {
		name               string
		config             string
		candidate          string
		outbounds, servers []string
	}{
		{
			name: "detour chain, folded keys",
			config: `{"outbounds": [` + node("a", `, "Detour": "b"`) + `, ` + local("b", `, "DETOUR": "c"`) + `,
				{"type": "shadowtls", "tag": "c", "server": "192.0.2.9", "server_port": 443, "password": "stls-password"}, ` +
				local("unused", "") + `]}`,
			candidate: "a", outbounds: []string{"a", "b", "c"},
		},
		{
			name: "a group as the detour takes its members",
			config: `{"outbounds": [` + node("a", `, "detour": "g"`) + `,
				{"type": "selector", "tag": "g", "Outbounds": ["b", "c"]}, ` + local("b", "") + `, ` + local("c", "") + `, ` +
				local("unused", "") + `]}`,
			candidate: "a", outbounds: []string{"a", "g", "b", "c"},
		},
		{
			name: "domain_resolver by tag and as an object; a DNS server's detour and resolver",
			config: `{
			  "dns": {"servers": [
			    {"type": "udp", "tag": "unused-dns", "server": "192.0.2.50"},
			    {"type": "https", "tag": "r1", "server": "dns.example.com", "Detour": "b", "domain_resolver": {"Server": "r2"}},
			    {"type": "udp", "tag": "r2", "server": "192.0.2.52"},
			    {"type": "udp", "tag": "r3", "server": "192.0.2.53"},
			    {"type": "udp", "tag": "boot", "server": "192.0.2.54"}
			  ], "final": "boot"},
			  "outbounds": [` + node("a", `, "DOMAIN_RESOLVER": "r1"`) + `, ` + local("b", "") + `,
			    ` + node("c", `, "domain_resolver": {"server": "r3", "strategy": "ipv4_only"}`) + `]}`,
			candidate: "a", outbounds: []string{"a", "b", "c"}, servers: []string{"r1", "r2", "r3", "boot"},
		},
		{
			name: "route.default_domain_resolver",
			config: `{
			  "dns": {"servers": [
			    {"type": "udp", "tag": "first", "server": "192.0.2.50"},
			    {"type": "udp", "tag": "resolver", "server": "192.0.2.51"},
			    {"type": "udp", "tag": "unused-dns", "server": "192.0.2.52"}
			  ], "final": "first"},
			  "outbounds": [` + node("a", "") + `],
			  "route": {"Default_Domain_Resolver": {"server": "resolver", "strategy": "prefer_ipv4"}}}`,
			candidate: "a", outbounds: []string{"a"}, servers: []string{"first", "resolver"},
		},
		{
			name: "dns.final, its detour through a group",
			config: `{
			  "dns": {"Servers": [
			    {"type": "udp", "tag": "local-dns", "server": "192.0.2.50"},
			    {"type": "https", "tag": "remote", "server": "1.1.1.1", "detour": "proxy"}
			  ], "Final": "remote"},
			  "outbounds": [{"type": "selector", "tag": "proxy", "outbounds": ["b", "direct"]}, ` + node("a", "") + `, ` +
				local("b", "") + `, {"type": "direct", "tag": "direct"}]}`,
			candidate: "a", outbounds: []string{"proxy", "a", "b", "direct"}, servers: []string{"remote"},
		},
		{
			name: "a single DNS server is always there (rule 5)",
			config: `{"dns": {"servers": [{"type": "https", "tag": "only", "server": "1.1.1.1"}]},
			  "outbounds": [` + node("a", "") + `]}`,
			candidate: "a", outbounds: []string{"a"}, servers: []string{"only"},
		},
		{
			name: "without dns.final the first server is the default",
			config: `{"dns": {"servers": [
			    {"type": "https", "tag": "first", "server": "1.1.1.1"},
			    {"type": "udp", "tag": "second", "server": "192.0.2.50"}
			  ]},
			  "outbounds": [` + node("a", "") + `]}`,
			candidate: "a", outbounds: []string{"a"}, servers: []string{"first"},
		},
		{
			name: "a server of the format before 1.12 and its address_resolver",
			config: `{"dns": {"servers": [
			    {"tag": "boot", "address": "192.0.2.50"},
			    {"tag": "legacy", "address": "tls://dns.example.com", "Address_Resolver": "legacy-boot"},
			    {"tag": "legacy-boot", "address": "192.0.2.51"}
			  ], "final": "boot"},
			  "outbounds": [` + node("a", `, "domain_resolver": "legacy"`) + `]}`,
			candidate: "a", outbounds: []string{"a"}, servers: []string{"boot", "legacy", "legacy-boot"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan := probePlan(probeConfig(t, tc.config))
			if c := candidateByTag(t, plan, tc.candidate); !c.Testable || !c.Eligible || c.Note != "" {
				t.Fatalf("candidate %+v, want testable and eligible", c)
			}
			outbounds, servers := probeTags(t, plan)
			if !reflect.DeepEqual(outbounds, tc.outbounds) {
				t.Errorf("outbounds = %v, want %v", outbounds, tc.outbounds)
			}
			if !reflect.DeepEqual(servers, tc.servers) {
				t.Errorf("DNS servers = %v, want %v", servers, tc.servers)
			}
		})
	}
}

// What the closure cannot carry makes everything that reaches it untestable,
// named in the note — also when every outbound reaches it through the DNS
func TestProbeClosureProblems(t *testing.T) {
	node := func(tag, extra string) string {
		return `{"type": "vless", "tag": "` + tag + `", "server": "192.0.2.1", "server_port": 443, "uuid": "` + uuidA + `"` + extra + `}`
	}
	cases := []struct {
		name, config, note string
	}{
		{"missing DNS server", `{"outbounds": [` + node("a", `, "Domain_Resolver": "nowhere"`) + `]}`, "nowhere"},
		{"DNS server of a service", `{"dns": {"servers": [{"type": "resolved", "tag": "sd", "service": "resolved-svc"}]},
			"outbounds": [` + node("a", "") + `]}`, "sd"},
		{"DNS server of an endpoint as dns.final", `{"dns": {"servers": [
			{"type": "udp", "tag": "u", "server": "192.0.2.50"}, {"type": "openvpn", "tag": "ov", "endpoint": "x"}], "final": "ov"},
			"outbounds": [` + node("a", "") + `]}`, "ov"},
		{"DNS server of a type sing-box may add later", `{"dns": {"servers": [{"type": "doq-next", "tag": "new"}]},
			"outbounds": [` + node("a", "") + `]}`, "new"},
		{"DNS server in a network namespace", `{"dns": {"servers": [{"type": "udp", "tag": "nsd", "server": "192.0.2.50", "Netns": "ns"}]},
			"outbounds": [` + node("a", "") + `]}`, "nsd"},
		{"DNS detour through an outbound outside the allow-list", `{"dns": {"servers": [
			{"type": "https", "tag": "remote", "server": "1.1.1.1", "detour": "tor1"}]},
			"outbounds": [{"type": "tor", "tag": "tor1"}, ` + node("a", "") + `]}`, "tor1"},
		{"a group member that is an endpoint", `{"endpoints": [{"type": "wireguard", "tag": "wg"}],
			"outbounds": [` + node("a", `, "detour": "g"`) + `, {"type": "selector", "tag": "g", "outbounds": ["wg"]}]}`, "wg"},
		{"a dependency with a realm", `{"outbounds": [` + node("a", `, "detour": "h"`) + `,
			{"type": "hysteria2", "tag": "h", "server": "192.0.2.5", "server_port": 443, "Realm": {"server_url": "https://r"}}]}`, "h"},
		{"a dependency with a network namespace", `{"outbounds": [` + node("a", `, "detour": "n"`) + `, ` + node("n", `, "NetNs": "ns"`) + `]}`, "n"},
		{"default_domain_resolver missing", `{"outbounds": [` + node("a", "") + `], "route": {"default_domain_resolver": "gone"}}`, "gone"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan := probePlan(probeConfig(t, tc.config))
			c := candidateByTag(t, plan, "a")
			if want := "не проверяется: зависит от «" + tc.note + "»"; c.Testable || c.Eligible || c.Note != want {
				t.Errorf("candidate %+v, want the note %q", c, want)
			}
			outbounds, servers := probeTags(t, plan)
			if len(outbounds) != 0 || len(servers) != 0 {
				t.Errorf("probe config carries %v / %v, want nothing", outbounds, servers)
			}
			// Nothing testable, nothing of the DNS either (dns.final would
			// name a server left out)
			if dns, ok := plan.Config["dns"]; ok {
				t.Errorf("probe config carries the dns section %v", dns)
			}
		})
	}
}

// probeVerbatimConfig has a part of every section the test instance takes
// from config.json
const probeVerbatimConfig = `{
  "log": {"level": "debug", "output": "box.log", "timestamp": true},
  "dns": {
    "servers": [
      {"type": "https", "tag": "remote", "server": "1.1.1.1", "path": "/dns-query", "detour": "a",
       "headers": {"X-Test": "1"}, "domain_resolver": {"server": "boot", "strategy": "ipv4_only"}},
      {"type": "udp", "tag": "boot", "server": "192.0.2.53", "server_port": 5353},
      {"type": "fakeip", "tag": "fake", "inet4_range": "198.18.0.0/15"}
    ],
    "rules": [{"query_type": ["A"], "server": "fake"}],
    "Rules": [{"domain_suffix": [".ru"], "server": "boot"}],
    "final": "remote",
    "strategy": "prefer_ipv4",
    "cache_capacity": 4096,
    "client_subnet": "192.0.2.0/24"
  },
  "certificate": {"store": "mozilla", "certificate": ["-----BEGIN CERTIFICATE-----", "MIIB", "-----END CERTIFICATE-----"]},
  "inbounds": [{"type": "tun", "tag": "tun-in", "address": ["172.19.0.1/30"], "auto_route": true, "strict_route": true}],
  "endpoints": [{"type": "wireguard", "tag": "wg"}],
  "outbounds": [
    {"type": "vless", "tag": "a", "server": "node.example.com", "server_port": 443, "uuid": "` + uuidA + `",
     "flow": "xtls-rprx-vision", "connect_timeout": "5s", "tcp_fast_open": false, "domain_resolver": "boot",
     "tls": {"enabled": true, "server_name": "www.example.com", "utls": {"enabled": true, "fingerprint": "chrome"},
             "reality": {"enabled": true, "public_key": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", "short_id": "6ba85179"}},
     "multiplex": {"enabled": true, "max_streams": 8, "padding": true}},
    {"type": "hysteria2", "tag": "b", "server": "192.0.2.20", "server_ports": ["20000:30000"], "hop_interval": "30s",
     "up_mbps": 50, "down_mbps": 200.5, "password": "hy-password", "obfs": {"type": "salamander", "password": "obfs-password"},
     "tls": {"enabled": true, "server_name": "hy.example.com", "alpn": ["h3"]}}
  ],
  "route": {
    "rules": [{"action": "sniff"}, {"rule_set": "geosite-ru", "outbound": "direct"}],
    "rule_set": [{"type": "remote", "tag": "geosite-ru", "format": "binary", "url": "https://example.com/ru.srs"}],
    "final": "a",
    "auto_detect_interface": false,
    "default_interface": "Ethernet",
    "default_domain_resolver": {"server": "boot", "rewrite_ttl": 60},
    "find_process": true
  },
  "ntp": {"enabled": true, "server": "time.example.com"},
  "http_clients": [{"tag": "dl"}],
  "services": [{"type": "resolved", "tag": "svc"}],
  "certificate_providers": [{"type": "acme", "tag": "acme"}],
  "network_namespaces": [{"tag": "ns"}],
  "experimental": {
    "cache_file": {"enabled": true, "path": "cache.db"},
    "clash_api": {"external_controller": "127.0.0.1:9090", "secret": "user-clash-secret-0123456789"},
    "debug": {"listen": "127.0.0.1:6060"}
  }
}`

// The objects of the test instance are config.json's own, copied deeply:
// sing-box sees the same options in both, and nothing the prober changes in
// its copy reaches the config
func TestProbeConfigCopiesVerbatim(t *testing.T) {
	cfg := probeConfig(t, probeVerbatimConfig)
	before := canonical(cfg)
	plan := probePlan(cfg)

	original := func(section string, tag string) any {
		var list []any
		if section == "servers" {
			list = cfg["dns"].(map[string]any)["servers"].([]any)
		} else {
			list = cfg[section].([]any)
		}
		for _, item := range list {
			if foldedString(item.(map[string]any), "tag") == tag {
				return item
			}
		}
		t.Fatalf("no %s %q", section, tag)
		return nil
	}
	for _, item := range plan.Config["outbounds"].([]any) {
		o := item.(map[string]any)
		if want := original("outbounds", foldedString(o, "tag")); !reflect.DeepEqual(o, want) {
			t.Errorf("outbound copied as\n%v\nwant\n%v", o, want)
		}
	}
	dns := plan.Config["dns"].(map[string]any)
	for _, item := range dns["servers"].([]any) {
		s := item.(map[string]any)
		if want := original("servers", foldedString(s, "tag")); !reflect.DeepEqual(s, want) {
			t.Errorf("DNS server copied as\n%v\nwant\n%v", s, want)
		}
	}
	if outbounds, servers := probeTags(t, plan); !reflect.DeepEqual(outbounds, []string{"a", "b"}) || !reflect.DeepEqual(servers, []string{"remote", "boot"}) {
		t.Errorf("probe config carries %v / %v", outbounds, servers)
	}

	// The DNS options but the rules (in any spelling) and the servers not needed
	userDNS := cfg["dns"].(map[string]any)
	for _, key := range []string{"final", "strategy", "cache_capacity", "client_subnet"} {
		if !reflect.DeepEqual(dns[key], userDNS[key]) {
			t.Errorf("dns.%s = %v, want %v", key, dns[key], userDNS[key])
		}
	}
	if len(dns) != 5 {
		t.Errorf("dns section of the test instance = %v, want its servers and four options", dns)
	}
	if !reflect.DeepEqual(plan.Config["certificate"], cfg["certificate"]) {
		t.Errorf("certificate = %v, want %v", plan.Config["certificate"], cfg["certificate"])
	}
	userRoute := cfg["route"].(map[string]any)
	wantRoute := map[string]any{
		"auto_detect_interface":   true,
		"default_interface":       userRoute["default_interface"],
		"default_domain_resolver": userRoute["default_domain_resolver"],
	}
	if !reflect.DeepEqual(plan.Config["route"], wantRoute) {
		t.Errorf("route = %v, want %v", plan.Config["route"], wantRoute)
	}

	// Changing the copy changes neither the config nor the plans Exclude
	// builds from it; nor does changing the config afterwards
	a := plan.Config["outbounds"].([]any)[0].(map[string]any)
	a["server"] = "elsewhere.example.com"
	a["tls"].(map[string]any)["server_name"] = "elsewhere.example.com"
	dns["servers"].([]any)[0].(map[string]any)["detour"] = "b"
	plan.Config["certificate"].(map[string]any)["certificate"].([]any)[1] = "changed"
	plan.Config["route"].(map[string]any)["default_domain_resolver"].(map[string]any)["server"] = "remote"
	if canonical(cfg) != before {
		t.Error("changing the probe config changed the config it was built from")
	}
	cfg["outbounds"].([]any)[0].(map[string]any)["server_port"] = "changed"
	next, ok := plan.Exclude("FATAL[0000] initialize outbound[1]: refused")
	if !ok {
		t.Fatal("Exclude refused")
	}
	rebuilt := next.Config["outbounds"].([]any)
	if len(rebuilt) != 1 || !reflect.DeepEqual(rebuilt[0], probeConfig(t, probeVerbatimConfig)["outbounds"].([]any)[0]) {
		t.Errorf("the plan Exclude built does not carry config.json's own outbound: %v", rebuilt)
	}
}

// Whatever the test instance does not need never reaches it: no inbound,
// rule, rule set, cache file, log file, service, endpoint or experimental
// option of the user's, in any spelling
func TestProbeConfigNeverCopies(t *testing.T) {
	text := strings.Replace(probeVerbatimConfig, `"ntp":`, `"Inbounds": [{"type": "mixed", "tag": "m", "listen_port": 2080}], "ntp":`, 1)
	plan := probePlan(probeConfig(t, text))

	keys := make([]string, 0, len(plan.Config))
	for k := range plan.Config {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	if want := []string{"certificate", "dns", "log", "outbounds", "route"}; !reflect.DeepEqual(keys, want) {
		t.Errorf("sections of the test instance = %v, want %v", keys, want)
	}
	if !reflect.DeepEqual(plan.Config["log"], map[string]any{"level": "warn"}) {
		t.Errorf("log = %v, want only the level", plan.Config["log"])
	}
	forbidden := map[string]bool{
		"inbounds": true, "endpoints": true, "rules": true, "rule_set": true, "experimental": true,
		"clash_api": true, "cache_file": true, "external_controller": true, "output": true, "ntp": true,
		"services": true, "http_clients": true, "certificate_providers": true, "network_namespaces": true,
		"find_process": true,
	}
	var walk func(v any, path string)
	walk = func(v any, path string) {
		switch x := v.(type) {
		case map[string]any:
			for k, child := range x {
				if forbidden[foldKey(k)] {
					t.Errorf("%s.%s reached the test instance", path, k)
				}
				walk(child, path+"."+k)
			}
		case []any:
			for _, child := range x {
				walk(child, path)
			}
		}
	}
	walk(plan.Config, "config")
	if strings.Contains(canonical(plan.Config), "user-clash-secret") {
		t.Error("the user's clash API secret reached the test instance")
	}
}

// Building the plan reads config.json and writes nothing: no backup, no
// history entry, the file byte for byte as it was
func TestEditorProbePlanOnlyReads(t *testing.T) {
	path := writeConfig(t, probeVerbatimConfig)
	editor := New(path)
	editor.SetValidator(func([]byte) error {
		t.Error("the validator ran: a plan is no save")
		return nil
	})

	plan, err := editor.ProbePlan()
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Candidates) != 2 {
		t.Errorf("candidates = %+v", plan.Candidates)
	}
	if rt, err := editor.RoutingTarget(); err != nil || rt.Kind != domain.RoutingNode || rt.Tag != "a" {
		t.Errorf("RoutingTarget = %+v, %v", rt, err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != probeVerbatimConfig {
		t.Error("config.json changed")
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() != "config.json" {
			t.Errorf("%s appeared next to config.json", entry.Name())
		}
	}

	missing := New(filepath.Join(t.TempDir(), "config.json"))
	if _, err := missing.ProbePlan(); !errors.Is(err, domain.ErrConfigMissing) {
		t.Errorf("ProbePlan without config.json: %v", err)
	}
	if _, err := missing.RoutingTarget(); !errors.Is(err, domain.ErrConfigMissing) {
		t.Errorf("RoutingTarget without config.json: %v", err)
	}
}

// Redact takes out every credential of the config — of a node the test
// instance does not carry too — and the secrets the prober adds
func TestProbeRedact(t *testing.T) {
	plan := probePlan(probeConfig(t, classifyConfig))
	const apiSecret = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	text := "dial 192.0.2.13: uuid " + uuidA + ", ss-password, stls-password; clash secret " + apiSecret + " end"
	got := plan.Redact(text, apiSecret)
	for _, secret := range []string{uuidA, "ss-password", "stls-password", apiSecret} {
		if strings.Contains(got, secret) {
			t.Errorf("%q kept in %q", secret, got)
		}
	}
	if want := "dial 192.0.2.13: uuid (скрыто), (скрыто), (скрыто); clash secret (скрыто) end"; got != want {
		t.Errorf("Redact = %q, want %q", got, want)
	}
	// What the test instance does not carry (a node with a realm, an
	// endpoint) still has its credential taken out: a text may come from an
	// earlier test instance
	if got := plan.Redact("hy-password wg-private-key-value"); got != "(скрыто) (скрыто)" {
		t.Errorf("Redact = %q", got)
	}
	if got := plan.Redact("nothing secret here"); got != "nothing secret here" {
		t.Errorf("Redact changed an ordinary text: %q", got)
	}
}

// An outbound sing-box could not create on its own is left out with
// sing-box's reason, and so is every candidate that depends on it; the
// others stay. Exclusions add up.
func TestProbeExclude(t *testing.T) {
	cfg := probeConfig(t, `{
	  "outbounds": [
	    {"type": "vless", "tag": "a", "server": "192.0.2.1", "server_port": 443, "uuid": "`+uuidA+`"},
	    {"type": "vless", "tag": "relay", "server": "192.0.2.2", "server_port": 443, "uuid": "`+uuidA+`"},
	    {"type": "vless", "tag": "chained", "server": "192.0.2.3", "server_port": 443, "uuid": "`+uuidA+`", "detour": "relay"},
	    {"type": "selector", "tag": "proxy", "outbounds": ["a", "chained"]},
	    {"type": "vless", "tag": "d", "server": "192.0.2.4", "server_port": 443, "uuid": "`+uuidA+`"}
	  ]
	}`)
	plan := probePlan(cfg)
	if outbounds, _ := probeTags(t, plan); !reflect.DeepEqual(outbounds, []string{"a", "relay", "chained", "d"}) {
		t.Fatalf("probe outbounds = %v", outbounds)
	}

	output := "WARN[0000] something first\nFATAL[0000] create service: initialize outbound[1]: parse uuid " + uuidA + ": invalid\n"
	next, ok := plan.Exclude(output)
	if !ok {
		t.Fatal("Exclude refused an output naming an outbound")
	}
	if c := candidateByTag(t, next, "relay"); c.Testable || c.Note != "не проверяется: sing-box не смог его запустить отдельно: parse uuid (скрыто): invalid" {
		t.Errorf("the excluded outbound: %+v", c)
	}
	if c := candidateByTag(t, next, "chained"); c.Testable || c.Note != "не проверяется: зависит от «relay»" {
		t.Errorf("the outbound through it: %+v", c)
	}
	for _, tag := range []string{"a", "d"} {
		if c := candidateByTag(t, next, tag); !c.Testable || !c.Eligible || c.Note != "" {
			t.Errorf("an outbound independent of it: %+v", c)
		}
	}
	if outbounds, _ := probeTags(t, next); !reflect.DeepEqual(outbounds, []string{"a", "d"}) {
		t.Errorf("probe outbounds after the exclusion = %v", outbounds)
	}
	if c := candidateByTag(t, plan, "relay"); !c.Testable {
		t.Error("Exclude changed the plan it was called on")
	}

	// sing-box's decode error names the position the same way; the
	// exclusions of the earlier plan stay
	last, ok := next.Exclude(`decode config at stdin: outbounds[1].foo: json: unknown field "foo"`)
	if !ok {
		t.Fatal("Exclude refused a decode error naming an outbound")
	}
	if c := candidateByTag(t, last, "d"); c.Testable || c.Note != `не проверяется: sing-box не смог его запустить отдельно: foo: json: unknown field "foo"` {
		t.Errorf("the second excluded outbound: %+v", c)
	}
	if c := candidateByTag(t, last, "relay"); c.Testable {
		t.Error("the first exclusion was forgotten")
	}
	if outbounds, _ := probeTags(t, last); !reflect.DeepEqual(outbounds, []string{"a"}) {
		t.Errorf("probe outbounds after two exclusions = %v", outbounds)
	}
	// Each plan keeps its own exclusions: another one from the same plan
	// does not take the first along
	other, ok := next.Exclude("FATAL[0000] initialize outbound[0]: refused")
	if !ok {
		t.Fatal("Exclude refused")
	}
	if c := candidateByTag(t, other, "d"); !c.Testable {
		t.Errorf("an exclusion made from the same plan leaked into another: %+v", c)
	}

	for _, output := range []string{
		"FATAL[0000] start service: external controller listen error: listen tcp 127.0.0.1:1: bind",
		"FATAL[0000] create service: initialize outbound[4]: past the end",
		"FATAL[0000] create service: initialize inbound[0]: no outbound named here",
	} {
		if _, ok := next.Exclude(output); ok {
			t.Errorf("Exclude took %q", output)
		}
	}
}

// Where the traffic goes first, and the proxies a switch would repoint
func TestRoutingTarget(t *testing.T) {
	const outbounds = `"outbounds": [
	  {"type": "selector", "tag": "proxy", "outbounds": ["a", "b"]},
	  {"type": "urltest", "tag": "auto", "outbounds": ["a", "b"]},
	  {"type": "vless", "tag": "a"},
	  {"type": "vless", "tag": "b"},
	  {"type": "shadowtls", "tag": "stls"},
	  {"type": "direct", "tag": "direct"},
	  {"type": "block", "tag": "block"}
	]`
	cases := []struct {
		name, route string
		want        domain.RoutingTarget
	}{
		{"node as final", `{"final": "a"}`, domain.RoutingTarget{Kind: domain.RoutingNode, Tag: "a", ProxyRefs: []string{"a"}}},
		{"selector as final", `{"rules": [{"rule_set": "ru", "outbound": "direct"}], "final": "proxy"}`,
			domain.RoutingTarget{Kind: domain.RoutingSelector, Tag: "proxy"}},
		{"urltest by a rule", `{"rules": [{"action": "sniff"}, {"domain": ["x"], "outbound": "auto"}], "final": "direct"}`,
			domain.RoutingTarget{Kind: domain.RoutingURLTest, Tag: "auto"}},
		{"split between two servers", `{"rules": [{"domain": ["x"], "outbound": "a"}, {"domain": ["y"], "outbound": "a"}], "final": "b"}`,
			domain.RoutingTarget{Kind: domain.RoutingNode, Tag: "a", ProxyRefs: []string{"a", "b"}}},
		{"the first rule decides, groups are no proxies", `{"rules": [{"domain": ["x"], "outbound": "proxy"}], "final": "b"}`,
			domain.RoutingTarget{Kind: domain.RoutingSelector, Tag: "proxy", ProxyRefs: []string{"b"}}},
		{"direct, block and a relay are none", `{"rules": [{"outbound": "block"}, {"outbound": "stls"}], "final": "direct"}`,
			domain.RoutingTarget{}},
		{"folded keys", `{"Rules": [{"Outbound": "b"}], "FINAL": "a"}`,
			domain.RoutingTarget{Kind: domain.RoutingNode, Tag: "b", ProxyRefs: []string{"b", "a"}}},
		{"without final the first outbound is the default", `{"rules": [{"outbound": "direct"}]}`,
			domain.RoutingTarget{Kind: domain.RoutingSelector, Tag: "proxy"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := routingTarget(probeConfig(t, `{`+outbounds+`, "route": `+tc.route+`}`))
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("routingTarget = %+v, want %+v", got, tc.want)
			}
		})
	}
	// No route at all: the first outbound takes everything
	got := routingTarget(probeConfig(t, `{"outbounds": [{"type": "vless", "tag": "a"}, {"type": "direct", "tag": "direct"}]}`))
	if want := (domain.RoutingTarget{Kind: domain.RoutingNode, Tag: "a", ProxyRefs: []string{"a"}}); !reflect.DeepEqual(got, want) {
		t.Errorf("routingTarget without route = %+v, want %+v", got, want)
	}
}
