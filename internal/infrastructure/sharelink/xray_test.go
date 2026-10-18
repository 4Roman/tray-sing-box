package sharelink

import (
	"encoding/json"
	"errors"
	"maps"
	"strings"
	"testing"

	"tray-sing-box/internal/domain"
)

// xrayTemplate is the rest of a 3x-ui JSON subscription config (its
// default.json): what the import ignores
const xrayTemplate = `"dns": {"tag": "dns_out", "queryStrategy": "UseIP", "servers": [{"address": "8.8.8.8", "skipFallback": false}]},
  "inbounds": [{"listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": {"auth": "noauth", "udp": true, "userLevel": 8}, "tag": "mixed"}],
  "log": {"loglevel": "warning"},
  "routing": {"domainStrategy": "AsIs", "rules": [{"type": "field", "network": "tcp,udp", "outboundTag": "proxy"}]},
  "stats": {}`

// xrayDefaultOutbounds are the outbounds 3x-ui appends to every node
const xrayDefaultOutbounds = `{"tag": "direct", "protocol": "freedom", "settings": {"redirect": "", "noises": []}},
    {"tag": "block", "protocol": "blackhole", "settings": {"response": {"type": "http"}}}`

// xray3xui is a JSON subscription as 3x-ui's internal/sub/json_service.go
// builds it today: an array of whole configs, the node tagged "proxy" in
// each and named by "remarks"; VLESS and VMess in the flat settings form,
// Trojan and Shadowsocks in "servers"; sockopt removed; TLS and REALITY
// reduced to the client's keys (tlsData, realityData); the info node a
// SOCKS outbound to 127.0.0.1:1080 (genDummySocksConfig)
const xray3xui = `[
{"remarks": "🇩🇪 DE-alice", ` + xrayTemplate + `,
  "outbounds": [
    {"protocol": "vless", "tag": "proxy",
     "settings": {"address": "203.0.113.10", "port": 443, "id": "` + testUUID + `", "encryption": "none", "level": 8, "flow": "xtls-rprx-vision"},
     "mux": {"enabled": true, "concurrency": -1, "xudpConcurrency": 16, "xudpProxyUDP443": "reject"},
     "streamSettings": {"network": "tcp", "security": "reality",
       "realitySettings": {"show": false, "publicKey": "` + testPBK + `", "fingerprint": "chrome", "mldsa65Verify": "",
                           "spiderX": "/Xq3hM1kd8YpG2aB", "shortId": "6ba85179", "serverName": "www.example.com"},
       "tcpSettings": {"header": {"type": "none"}}}},
    ` + xrayDefaultOutbounds + `]},
{"remarks": "NL-ws", ` + xrayTemplate + `,
  "outbounds": [
    {"protocol": "vmess", "tag": "proxy",
     "settings": {"address": "cdn.example.com", "port": 443, "id": "` + testUUID + `", "security": "auto", "level": 8},
     "streamSettings": {"network": "ws", "security": "tls",
       "tlsSettings": {"serverName": "nl.example.com", "alpn": ["h2", "http/1.1"], "fingerprint": "chrome"},
       "wsSettings": {"path": "/ws?ed=2048", "host": "", "headers": {"X-Client": "app"}, "heartbeatPeriod": 0}}},
    ` + xrayDefaultOutbounds + `]},
{"remarks": "FI-grpc", ` + xrayTemplate + `,
  "outbounds": [
    {"protocol": "trojan", "tag": "proxy",
     "settings": {"servers": [{"address": "203.0.113.30", "port": 8443, "password": "trojan-pw", "level": 8}]},
     "streamSettings": {"network": "grpc", "security": "tls",
       "tlsSettings": {"serverName": "fi.example.com", "alpn": ["h2"], "fingerprint": "firefox", "pinnedPeerCertSha256": "ab12cd"},
       "grpcSettings": {"serviceName": "svc", "authority": "", "multiMode": true}}},
    ` + xrayDefaultOutbounds + `]},
{"remarks": "SE-ss2022", ` + xrayTemplate + `,
  "outbounds": [
    {"protocol": "shadowsocks", "tag": "proxy",
     "settings": {"servers": [{"address": "203.0.113.40", "port": 8388, "password": "MDEyMzQ1Njc4OWFiY2RlZg==:ZmVkY2JhOTg3NjU0MzIxMA==",
                               "level": 8, "method": "2022-blake3-aes-128-gcm"}]},
     "streamSettings": {"network": "tcp", "security": "none", "tcpSettings": {"header": {"type": "none"}}}},
    ` + xrayDefaultOutbounds + `]},
{"remarks": "PL-xhttp", ` + xrayTemplate + `,
  "outbounds": [
    {"protocol": "vless", "tag": "proxy",
     "settings": {"address": "203.0.113.50", "port": 443, "id": "` + testUUID + `", "encryption": "none", "level": 8},
     "streamSettings": {"network": "xhttp", "security": "reality",
       "realitySettings": {"show": false, "publicKey": "` + testPBK + `", "fingerprint": "chrome", "shortId": "ab", "serverName": "www.example.com"},
       "xhttpSettings": {"path": "/xh", "host": "", "mode": "auto"}}},
    ` + xrayDefaultOutbounds + `]},
{"remarks": "JP-hy2", ` + xrayTemplate + `,
  "outbounds": [
    {"protocol": "hysteria", "tag": "proxy", "settings": {"version": 2, "address": "203.0.113.60", "port": 443},
     "streamSettings": {"network": "hysteria", "security": "tls", "hysteriaSettings": {"version": 2, "auth": "` + testSecret + `"},
       "tlsSettings": {"serverName": "jp.example.com"}}},
    ` + xrayDefaultOutbounds + `]},
{"remarks": "⏳ 12 дней · 30 GB", ` + xrayTemplate + `,
  "outbounds": [
    {"protocol": "socks", "tag": "proxy", "settings": {"servers": [{"address": "127.0.0.1", "port": 1080}]}},
    ` + xrayDefaultOutbounds + `]},
{"remarks": "🇩🇪 DE-alice", ` + xrayTemplate + `,
  "outbounds": [
    {"protocol": "vless", "tag": "proxy",
     "settings": {"address": "203.0.113.11", "port": 443, "id": "` + testUUID + `", "encryption": "none", "level": 8},
     "streamSettings": {"network": "httpupgrade", "security": "tls",
       "tlsSettings": {"serverName": "de2.example.com", "fingerprint": ""},
       "httpupgradeSettings": {"path": "/hu", "host": "up.example.com", "headers": {}}}},
    ` + xrayDefaultOutbounds + `]}
]`

// xray3xuiFragment is the same as 3x-ui v2.5 built it with the JSON
// subscription's fragmentation on (sub/subJsonService.go and the default of
// web/html/xui/settings.html): VLESS in vnext, the node dialing through the
// "fragment" freedom
const xray3xuiFragment = `[
{"remarks": "NL-bob", ` + xrayTemplate + `,
  "outbounds": [
    {"protocol": "vless", "tag": "proxy",
     "settings": {"vnext": [{"address": "203.0.113.20", "port": 443,
       "users": [{"id": "` + testUUID + `", "flow": "xtls-rprx-vision", "encryption": "none", "level": 8, "email": "bob"}]}]},
     "streamSettings": {"network": "tcp", "security": "reality",
       "realitySettings": {"show": false, "publicKey": "` + testPBK + `", "fingerprint": "chrome", "spiderX": "/", "shortId": "6ba85179", "serverName": "www.example.com"},
       "tcpSettings": {"header": {"type": "none"}},
       "sockopt": {"dialerProxy": "fragment", "tcpKeepAliveIdle": 100, "tcpMptcp": true, "penetrate": true}}},
    {"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "AsIs", "redirect": "", "noises": []}},
    {"tag": "block", "protocol": "blackhole", "settings": {"response": {"type": "http"}}},
    {"tag": "fragment", "protocol": "freedom",
     "settings": {"domainStrategy": "AsIs", "fragment": {"packets": "tlshello", "length": "100-200", "interval": "10-20"}},
     "streamSettings": {"sockopt": {"tcpKeepAliveIdle": 100, "tcpMptcp": true, "penetrate": true}}},
    {"tag": "noises", "protocol": "freedom", "settings": {"domainStrategy": "AsIs", "noises": [{"type": "rand", "packet": "10-20", "delay": "10-16"}]}}
  ]},
{"remarks": "NL-old-vmess", ` + xrayTemplate + `,
  "outbounds": [
    {"protocol": "vmess", "tag": "proxy",
     "settings": {"vnext": [{"address": "203.0.113.21", "port": 80, "users": [{"id": "` + testUUID + `", "alterId": 0, "security": "none", "level": 8}]}]},
     "streamSettings": {"network": "tcp", "security": "none",
       "tcpSettings": {"header": {"type": "http", "request": {"path": ["/index"], "headers": {"Host": ["a.example.com", "b.example.com"]}}}}}},
    ` + xrayDefaultOutbounds + `]}
]`

// xrayConfig is one Xray client config of the user's own: chains through
// dialerProxy, the outbound kinds a link has no form for, and what sing-box
// cannot do as Xray does it
const xrayConfig = `{
  "remarks": "My VPN",
  "log": {"loglevel": "warning"},
  "outbounds": [
    {"protocol": "vless", "tag": "proxy",
     "settings": {"vnext": [{"address": "203.0.113.70", "port": 443, "users": [{"id": "` + testUUID + `", "encryption": "none"}]}]},
     "streamSettings": {"network": "ws", "security": "tls", "tlsSettings": {"serverName": "front.example.com"},
       "wsSettings": {"path": "/front", "headers": {"host": "ws.example.com"}},
       "sockopt": {"dialerProxy": "relay"}}},
    {"protocol": "trojan", "tag": "relay",
     "settings": {"address": "203.0.113.71", "port": 443, "password": "relay-pw"},
     "streamSettings": {"security": "tls", "tlsSettings": {"serverName": "relay.example.com", "fingerprint": "unsafe"}}},
    {"protocol": "vmess", "tag": "via-direct",
     "settings": {"address": "2001:db8::72", "port": 8080, "id": "` + testUUID + `", "security": "zero"},
     "streamSettings": {"network": "raw", "sockopt": {"dialerProxy": "direct"}}},
    {"protocol": "socks", "tag": "socks-out", "settings": {"address": "203.0.113.73", "port": 1080, "user": "u", "pass": "p@ss"}, "proxySettings": null},
    {"protocol": "socks", "tag": "socks-user", "settings": {"servers": [{"address": "203.0.113.75", "port": 1080, "users": [{"user": "YTpi"}]}]},
     "streamSettings": {"finalmask": {"udp": [{"type": "salamander", "settings": {"password": "` + testSecret + `"}}]}}},
    {"protocol": "http", "tag": "https-out",
     "settings": {"servers": [{"address": "proxy.example.com", "port": 443, "users": [{"user": "u", "pass": "p"}]}], "headers": {"X-Token": "t"}},
     "streamSettings": {"security": "tls", "tlsSettings": {"serverName": "proxy.example.com", "alpn": "h2,http/1.1"}}},
    {"protocol": "shadowsocks", "tag": "ss-alias", "settings": {"address": "203.0.113.74", "port": 8388, "method": "AEAD_CHACHA20_POLY1305", "password": "pw"}},
    {"protocol": "vless", "tag": "ring-a", "settings": {"address": "203.0.113.80", "port": 443, "id": "` + testUUID + `"},
     "streamSettings": {"security": "tls", "sockopt": {"dialerProxy": "ring-b"}}},
    {"protocol": "vless", "tag": "ring-b", "settings": {"address": "203.0.113.81", "port": 443, "id": "` + testUUID + `"},
     "streamSettings": {"security": "tls", "sockopt": {"dialerProxy": "ring-a"}}},
    {"protocol": "trojan", "tag": "via-missing", "settings": {"address": "203.0.113.82", "port": 443, "password": "` + testSecret + `"},
     "streamSettings": {"sockopt": {"dialerProxy": "nowhere"}}},
    {"protocol": "trojan", "tag": "via-block", "settings": {"address": "203.0.113.83", "port": 443, "password": "` + testSecret + `"},
     "streamSettings": {"sockopt": {"dialerProxy": "block"}}},
    {"protocol": "trojan", "tag": "via-redirect", "settings": {"address": "203.0.113.84", "port": 443, "password": "` + testSecret + `"},
     "streamSettings": {"sockopt": {"dialerProxy": "redirector"}}},
    {"protocol": "trojan", "tag": "via-mask", "settings": {"address": "203.0.113.85", "port": 443, "password": "` + testSecret + `"},
     "streamSettings": {"sockopt": {"dialerProxy": "masked"}}},
    {"protocol": "vless", "tag": "proxy-settings", "settings": {"address": "203.0.113.86", "port": 443, "id": "` + testUUID + `"},
     "proxySettings": {"tag": "relay", "transportLayer": true}},
    {"protocol": "vless", "tag": "stream-address", "settings": {"address": "203.0.113.87", "port": 443, "id": "` + testUUID + `"},
     "streamSettings": {"address": "198.51.100.1", "port": 443}},
    {"protocol": "vless", "tag": "srv", "settings": {"address": "srv.example.com", "port": 443, "id": "` + testUUID + `"},
     "streamSettings": {"security": "tls", "sockopt": {"addressPortStrategy": "SrvPortAndAddress"}}},
    {"protocol": "vmess", "tag": "kcp", "settings": {"address": "203.0.113.88", "port": 443, "id": "` + testUUID + `"},
     "streamSettings": {"network": "kcp", "kcpSettings": {"seed": "` + testSecret + `"}}},
    {"protocol": "wireguard", "tag": "wg", "settings": {"secretKey": "` + testSecret + `", "peers": [{"endpoint": "203.0.113.89:51820"}]}},
    {"protocol": "masque", "tag": "masque-out", "settings": {"address": "203.0.113.90", "port": 443}},
    {"protocol": "socks", "tag": "socks-tls", "settings": {"address": "203.0.113.91", "port": 1080, "user": "u", "pass": "` + testSecret + `"},
     "streamSettings": {"security": "tls"}},
    {"protocol": "http", "tag": "http-ws", "settings": {"address": "203.0.113.92", "port": 80},
     "streamSettings": {"network": "ws"}},
    {"protocol": "vless", "tag": "custom-ca", "settings": {"address": "203.0.113.93", "port": 443, "id": "` + testUUID + `"},
     "streamSettings": {"security": "tls", "tlsSettings": {"certificates": [{"usage": "verify", "certificateFile": "/etc/` + testSecret + `.pem"}]}}},
    {"protocol": "vless", "tag": "reverse", "settings": {"address": "203.0.113.94", "port": 443, "id": "` + testUUID + `", "reverse": {"tag": "r"}},
     "streamSettings": {"security": "tls"}},
    {"protocol": "vless", "tag": "env-address", "settings": {"address": "env:` + testSecret + `", "port": 443, "id": "` + testUUID + `"}},
    {"protocol": "trojan", "tag": "pin-insecure", "settings": {"address": "203.0.113.95", "port": 443, "password": "` + testSecret + `"},
     "streamSettings": {"security": "tls", "tlsSettings": {"allowInsecure": true, "pinnedPeerCertSha256": "` + testSecret + `"}}},
    {"protocol": "vless", "tag": "no-port", "settings": {"address": "203.0.113.96", "id": "` + testUUID + `"}},
    {"protocol": "trojan", "tag": "no-password", "settings": {"servers": [{"address": "203.0.113.97", "port": 443}]}},
    {"protocol": "trojan", "tag": "trojan-flow", "settings": {"servers": [{"address": "203.0.113.98", "port": 443, "password": "` + testSecret + `", "flow": "xtls-rprx-direct"}]},
     "streamSettings": {"security": "xtls"}},
    {"protocol": "vless", "tag": "broken", "settings": {"address": 5}},
    {"protocol": "freedom", "tag": "direct", "settings": {"domainStrategy": "UseIPv4", "noises": [{"type": "rand", "packet": "10-20", "delay": "10-16"}]}},
    {"protocol": "freedom", "tag": "redirector", "settings": {"redirect": "198.51.100.2:443"}},
    {"protocol": "freedom", "tag": "masked", "streamSettings": {"finalmask": {"tcp": [{"type": "sudoku", "settings": {"password": "` + testSecret + `"}}]}}},
    {"protocol": "blackhole", "tag": "block"}
  ],
  "routing": {"rules": [{"type": "field", "outboundTag": "proxy", "network": "tcp,udp"}]}
}`

// xraySamples are the Xray profiles whose nodes must pass `sing-box check`
var xraySamples = map[string]string{
	"xray 3x-ui":          xray3xui,
	"xray 3x-ui fragment": xray3xuiFragment,
	"xray config":         xrayConfig,
}

// The Xray samples join the profiles check_windows_test.go runs through the
// real sing-box check
func init() {
	maps.Copy(profileSamples, xraySamples)
}

// parseXray parses a profile that must import; the outbounds by tag (in
// order: tags) and the reasons by the skipped node's name
func parseXray(t *testing.T, body string) (byTag map[string]Outbound, tags []string, reasons map[string]string) {
	t.Helper()
	outbounds, skipped, err := ParseAllReport(body)
	if err != nil {
		t.Fatalf("ParseAllReport: %v", err)
	}
	byTag = map[string]Outbound{}
	for _, o := range outbounds {
		byTag[o.Tag()] = o
		tags = append(tags, o.Tag())
	}
	return byTag, tags, skipReasons(t, skipped)
}

// skipReasons maps the names of the skipped nodes to their reasons; a name
// skipped twice fails the test
func skipReasons(t *testing.T, skipped []domain.SkippedNode) map[string]string {
	t.Helper()
	reasons := map[string]string{}
	for _, sk := range skipped {
		if _, twice := reasons[sk.Name]; twice {
			t.Errorf("%q skipped twice", sk.Name)
		}
		reasons[sk.Name] = sk.Reason
	}
	return reasons
}

// checkReasons: every skipped node is expected, its reason says what it
// should
func checkReasons(t *testing.T, reasons, want map[string]string) {
	t.Helper()
	for name, reason := range reasons {
		if w, ok := want[name]; !ok || !strings.Contains(reason, w) {
			t.Errorf("skipped %q: %q, want it to say %q", name, reason, w)
		}
	}
	for name := range want {
		if _, ok := reasons[name]; !ok {
			t.Errorf("%q not skipped", name)
		}
	}
}

// 3x-ui's JSON subscription: every node named by its remarks (a repeated one
// suffixed), each translated as its share link would be
func TestXray3xuiSubscription(t *testing.T) {
	byTag, tags, reasons := parseXray(t, xray3xui)
	want := []string{"🇩🇪 DE-alice", "NL-ws", "FI-grpc", "SE-ss2022", "⏳ 12 дней · 30 GB", "🇩🇪 DE-alice (2)"}
	if strings.Join(tags, "|") != strings.Join(want, "|") {
		t.Fatalf("imported %q", tags)
	}
	checkOutbound(t, byTag["🇩🇪 DE-alice"], `{"type":"vless","server":"203.0.113.10","server_port":443,"uuid":"`+testUUID+`",
	  "flow":"xtls-rprx-vision","transport":null,"detour":null,
	  "tls":{"enabled":true,"server_name":"www.example.com","utls":{"enabled":true,"fingerprint":"chrome"},
	         "reality":{"enabled":true,"public_key":"`+testPBK+`","short_id":"6ba85179"}}}`)
	// The WebSocket's Host is the TLS server name when the host is empty, as
	// Xray sends it; its other headers go along; no h2 offered to an upgrade
	checkOutbound(t, byTag["NL-ws"], `{"type":"vmess","server":"cdn.example.com","security":"auto","alter_id":0,
	  "tls":{"enabled":true,"server_name":"nl.example.com","alpn":null},
	  "transport":{"type":"ws","path":"/ws","max_early_data":2048,"headers":{"Host":"nl.example.com","X-Client":"app"}}}`)
	checkOutbound(t, byTag["FI-grpc"], `{"type":"trojan","server":"203.0.113.30","server_port":8443,"password":"trojan-pw",
	  "tls":{"server_name":"fi.example.com","alpn":["h2"],"utls":{"fingerprint":"firefox"},"insecure":null},
	  "transport":{"type":"grpc","service_name":"svc"}}`)
	checkOutbound(t, byTag["SE-ss2022"], `{"type":"shadowsocks","server":"203.0.113.40","server_port":8388,
	  "method":"2022-blake3-aes-128-gcm","password":"MDEyMzQ1Njc4OWFiY2RlZg==:ZmVkY2JhOTg3NjU0MzIxMA==","plugin":null}`)
	// The info node is imported as the SOCKS proxy it is; the subscription
	// sync leaves it out (domain: withoutInfoNodes)
	checkOutbound(t, byTag["⏳ 12 дней · 30 GB"], `{"type":"socks","server":"127.0.0.1","server_port":1080,"username":null}`)
	checkOutbound(t, byTag["🇩🇪 DE-alice (2)"], `{"type":"vless","server":"203.0.113.11",
	  "tls":{"server_name":"de2.example.com","utls":{"fingerprint":"chrome"}},
	  "transport":{"type":"httpupgrade","path":"/hu","host":"up.example.com","headers":null}}`)

	checkReasons(t, reasons, map[string]string{
		"PL-xhttp": "транспорт XHTTP не поддерживается sing-box",
		"JP-hy2":   "hysteria2://",
	})

	// The same subscription served in base64
	if outbounds, skipped, err := ParseAllReport(b64(xray3xui)); err != nil || len(outbounds) != len(want) || len(skipped) != 2 {
		t.Errorf("base64: %d outbounds, %+v, %v", len(outbounds), skipped, err)
	}
}

// 3x-ui's balancer document (buildBalancerConfig): the members are copies of
// the other documents' nodes retagged "bal-<id>-<protocol>[-N]", the remarks
// the balancer's. Each node is imported once, under its own remarks, wherever
// the balancer stands in the array; a member that is no copy keeps its tag.
func TestXray3xuiBalancer(t *testing.T) {
	node := func(tag, server string) string {
		return `{"protocol": "vless", "tag": "` + tag + `",
		  "settings": {"address": "` + server + `", "port": 443, "id": "` + testUUID + `", "encryption": "none", "level": 8},
		  "streamSettings": {"network": "grpc", "security": "tls", "tlsSettings": {"serverName": "g.example.com"},
		    "grpcSettings": {"serviceName": "svc"}}}`
	}
	balancer := `{"remarks": "Auto", "outbounds": [` + node("bal-1-vless", "203.0.113.3") + `, ` + node("bal-1-vless-2", "203.0.113.1") + `,
	  ` + node("bal-1-vless-3", "203.0.113.2") + `, ` + xrayDefaultOutbounds + `],
	  "routing": {"rules": [{"type": "field", "network": "tcp,udp", "balancerTag": "balancer"}],
	    "balancers": [{"tag": "balancer", "selector": ["bal-1-"], "strategy": {"type": "random"}}]}}`
	single := func(remarks, server string) string {
		return `{"remarks": "` + remarks + `", "outbounds": [` + node("proxy", server) + `, ` + xrayDefaultOutbounds + `]}`
	}
	byTag, tags, reasons := parseXray(t, "["+balancer+","+single("A", "203.0.113.1")+","+single("B", "203.0.113.2")+"]")
	if strings.Join(tags, "|") != "A|B|bal-1-vless" || len(reasons) != 0 {
		t.Fatalf("imported %q, skipped %v", tags, reasons)
	}
	checkOutbound(t, byTag["bal-1-vless"], `{"server":"203.0.113.3"}`)
}

// 3x-ui v2.5 with fragmentation on: the node dials through the "fragment"
// freedom, which is the direct connection with Xray's fragmentation. Over
// TLS sing-box fragments the ClientHello too ("tlshello" ->
// tls.record_fragment, pieces sent apart -> tls.fragment); over REALITY,
// QUIC or without TLS it has nothing alike, and the node is imported without
// (Xray's tlshello leaves a connection without TLS alone). Either of Xray's
// spellings of the fragmentation, and the node's own finalmask, the way
// current 3x-ui writes it (TestXrayNodeFragment), come to the same.
func TestXrayFragmentDialer(t *testing.T) {
	byTag, tags, reasons := parseXray(t, xray3xuiFragment)
	if strings.Join(tags, "|") != "NL-bob|NL-old-vmess" || len(reasons) != 0 {
		t.Fatalf("imported %q, skipped %v", tags, reasons)
	}
	checkOutbound(t, byTag["NL-bob"], `{"type":"vless","server":"203.0.113.20","uuid":"`+testUUID+`","flow":"xtls-rprx-vision","detour":null,
	  "tls":{"reality":{"enabled":true},"fragment":null,"record_fragment":null}}`)
	checkOutbound(t, byTag["NL-old-vmess"], `{"type":"vmess","server":"203.0.113.21","server_port":80,"security":"auto","tls":null,
	  "transport":{"type":"http","method":"GET","path":"/index","host":["a.example.com","b.example.com"]}}`)

	viaDirect := strings.Replace(xray3xuiFragment, `"dialerProxy": "fragment"`, `"dialerProxy": "direct"`, 1)
	byTag, _, reasons = parseXray(t, viaDirect)
	if len(reasons) != 0 || byTag["NL-bob"] == nil {
		t.Fatalf("imported %v, skipped %v", byTag, reasons)
	}
	checkOutbound(t, byTag["NL-bob"], `{"type":"vless","server":"203.0.113.20","uuid":"`+testUUID+`","flow":"xtls-rprx-vision","detour":null}`)

	// One node and the freedom it dials through
	viaFreedom := func(node, freedom string) string {
		return `{"outbounds": [` + node + `, {"protocol": "freedom", "tag": "frag", ` + freedom + `}]}`
	}
	const tlsWS = `{"protocol": "vless", "tag": "n", "settings": {"address": "203.0.113.20", "port": 443, "id": "` + testUUID + `"},
	  "streamSettings": {"network": "ws", "security": "tls", "tlsSettings": {"serverName": "nl.example.com"}, "wsSettings": {"path": "/ws"},
	    "sockopt": {"dialerProxy": "frag"}}}`
	const ss = `{"protocol": "shadowsocks", "tag": "n", "settings": {"servers": [{"address": "203.0.113.21", "port": 8388,
	  "method": "chacha20-ietf-poly1305", "password": "pw"}]}, "streamSettings": {"sockopt": {"dialerProxy": "frag"}}}`
	const vmessWS = `{"protocol": "vmess", "tag": "n", "settings": {"address": "203.0.113.22", "port": 80, "id": "` + testUUID + `"},
	  "streamSettings": {"network": "ws", "wsSettings": {"path": "/ws"}, "sockopt": {"dialerProxy": "frag"}}}`
	const quic = `{"protocol": "vless", "tag": "n", "settings": {"address": "203.0.113.23", "port": 443, "id": "` + testUUID + `"},
	  "streamSettings": {"network": "quic", "security": "tls", "tlsSettings": {"serverName": "q.example.com"}, "sockopt": {"dialerProxy": "frag"}}}`
	freedomFragment := func(fragment string) string { return `"settings": {"fragment": ` + fragment + `}` }
	maskFragment := func(settings string) string {
		return `"streamSettings": {"finalmask": {"tcp": [{"type": "Fragment", "settings": ` + settings + `}]}}`
	}
	cases := []struct {
		name, node, freedom, want string
	}{
		// Pauses between the records: each one is a TCP segment of its own
		{"tlshello with an interval", tlsWS, freedomFragment(`{"packets": "tlshello", "length": "100-200", "interval": "10-20"}`),
			`{"detour":null,"tls":{"server_name":"nl.example.com","record_fragment":true,"fragment":true}}`},
		{"the mask's spelling", tlsWS, maskFragment(`{"packets": "tlshello", "length": "100-200", "delay": "10-20"}`),
			`{"detour":null,"tls":{"record_fragment":true,"fragment":true}}`},
		// Without a pause Xray sends the records in one write
		{"tlshello without an interval", tlsWS, freedomFragment(`{"packets": "tlshello", "length": "100-200", "interval": 0}`),
			`{"tls":{"record_fragment":true,"fragment":null}}`},
		{"the mask's single delay of 0", tlsWS, maskFragment(`{"packets": "tlshello", "length": "100-200", "delay": "0"}`),
			`{"tls":{"record_fragment":true,"fragment":null}}`},
		{"the mask's delays", tlsWS, maskFragment(`{"packets": "tlshello", "lengths": ["10-20", "100-200"], "delays": [0, 0]}`),
			`{"tls":{"record_fragment":true,"fragment":true}}`},
		// TCP segmentation of the first packets
		{"packets 1-3", tlsWS, freedomFragment(`{"packets": "1-3", "length": "1-5", "interval": "1"}`),
			`{"tls":{"record_fragment":null,"fragment":true}}`},
		{"every packet", tlsWS, maskFragment(`{"length": "1-5"}`),
			`{"tls":{"record_fragment":null,"fragment":true}}`},
		{"packets past the hello", tlsWS, freedomFragment(`{"packets": "2-5", "length": "1-5", "interval": "1"}`),
			`{"detour":null,"tls":{"record_fragment":null,"fragment":null}}`},
		// Nothing for sing-box to fragment: the plain node
		{"no TLS: Shadowsocks", ss, freedomFragment(`{"packets": "tlshello", "length": "100-200", "interval": "10-20"}`),
			`{"type":"shadowsocks","detour":null,"tls":null,"network":null}`},
		{"no TLS: VMess over ws", vmessWS, maskFragment(`{"packets": "tlshello", "length": "100-200", "delay": "10-20"}`),
			`{"type":"vmess","detour":null,"tls":null,"transport":{"type":"ws"}}`},
		{"QUIC", quic, freedomFragment(`{"packets": "1-1", "length": "1-5", "interval": "1"}`),
			`{"detour":null,"tls":{"fragment":null,"record_fragment":null},"transport":{"type":"quic"}}`},
		// The udp layer of the freedom's finalmask: nothing for a node over
		// TCP, UDP off for one that sends UDP itself
		{"udp masks, TCP node", tlsWS, `"streamSettings": {"finalmask": {"udp": [{"type": "noise", "settings": {"noise": []}}]}}`,
			`{"type":"vless","detour":null,"tls":{"fragment":null}}`},
		{"udp masks, Shadowsocks", ss, `"streamSettings": {"finalmask": {"udp": [{"type": "noise"}], "tcp": [{"type": "fragment"}]}}`,
			`{"type":"shadowsocks","detour":null,"network":"tcp"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			byTag, _, reasons := parseXray(t, viaFreedom(c.node, c.freedom))
			if len(reasons) != 0 || byTag["n"] == nil {
				t.Fatalf("imported %v, skipped %v", byTag, reasons)
			}
			checkOutbound(t, byTag["n"], c.want)
		})
	}

	refused := []struct {
		name, node, freedom, reason string
	}{
		{"udp masks, QUIC node", quic, `"streamSettings": {"finalmask": {"udp": [{"type": "Noise"}]}}`, "через «frag» с маскировкой finalmask «noise»"},
		{"another tcp mask", tlsWS, `"streamSettings": {"finalmask": {"tcp": [{"type": "fragment"}, {"type": "sudoku", "settings": {"password": "` + testSecret + `"}}]}}`,
			"через «frag» с параметром finalmask «sudoku»"},
		{"fragment Xray cannot read", tlsWS, freedomFragment(`{"packets": "tls-hello", "length": "100-200", "interval": "10-20"}`),
			"через «frag», а его запись повреждена"},
		{"a range Xray cannot read", tlsWS, maskFragment(`{"packets": "tlshello", "delay": "10-` + testSecret + `"}`),
			"через «frag», а его запись повреждена"},
		{"redirect with a fragment", tlsWS, `"settings": {"redirect": "198.51.100.2:443", "fragment": {"packets": "tlshello"}}`,
			"через «frag» с параметром redirect"},
	}
	for _, c := range refused {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := ParseAllReport(viaFreedom(c.node, c.freedom))
			if err == nil || !strings.Contains(err.Error(), c.reason) || strings.Contains(err.Error(), testSecret) {
				t.Errorf("error %v, want it to say %q", err, c.reason)
			}
		})
	}
}

// Current 3x-ui writes the JSON subscription's fragmentation into every
// node's own finalmask (applyGlobalFinalMask): the node comes out as the one
// dialing through the fragment freedom of 3x-ui v2.5 does
func TestXrayNodeFragment(t *testing.T) {
	const fragment = `{"packets": "tlshello", "length": "100-200", "interval": "10-20"}`
	const mask = `{"tcp": [{"type": "fragment", "settings": {"packets": "tlshello", "length": "100-200", "delay": "10-20"}}],
	  "udp": [{"type": "udphop", "settings": {"mode": "intervalRemote", "remotePorts": "20000-30000"}}]}`
	stream := map[string]string{
		"reality": `"network": "tcp", "security": "reality",
		  "realitySettings": {"publicKey": "` + testPBK + `", "fingerprint": "chrome", "shortId": "6ba85179", "serverName": "www.example.com"}`,
		"tls": `"network": "ws", "security": "tls", "tlsSettings": {"serverName": "nl.example.com", "alpn": ["h2", "http/1.1"]},
		  "wsSettings": {"path": "/ws"}`,
	}
	node := func(remarks, stream, extra string) string {
		return `{"remarks": "` + remarks + `", "outbounds": [{"protocol": "vless", "tag": "proxy",
		  "settings": {"address": "203.0.113.20", "port": 443, "id": "` + testUUID + `", "encryption": "none"},
		  "streamSettings": {` + stream + extra + `}}, ` + xrayDefaultOutbounds + `,
		  {"tag": "fragment", "protocol": "freedom", "settings": {"fragment": ` + fragment + `}}]}`
	}
	for name, st := range stream {
		t.Run(name, func(t *testing.T) {
			own, _, reasons := parseXray(t, "["+node("A", st, `, "finalmask": `+mask)+"]")
			if len(reasons) != 0 {
				t.Fatalf("skipped %v", reasons)
			}
			dialer, _, reasons := parseXray(t, "["+node("A", st, `, "sockopt": {"dialerProxy": "fragment"}`)+"]")
			if len(reasons) != 0 {
				t.Fatalf("skipped %v", reasons)
			}
			if a, b := xrayContent(own["A"]), xrayContent(dialer["A"]); a != b {
				t.Errorf("the node's own fragmentation:\n%s\nthrough the freedom:\n%s", a, b)
			}
			if name == "tls" {
				checkOutbound(t, own["A"], `{"tls":{"record_fragment":true,"fragment":true,"alpn":null},"transport":{"type":"ws"}}`)
			} else {
				checkOutbound(t, own["A"], `{"tls":{"reality":{"enabled":true},"record_fragment":null,"fragment":null}}`)
			}
		})
	}
}

// A config of the user's own: a dialer chain becomes a detour, the outbounds
// a link has no form for are built or refused, and what sing-box would not
// run as Xray does is left out with the reason
func TestXrayConfig(t *testing.T) {
	byTag, tags, reasons := parseXray(t, xrayConfig)
	want := []string{"My VPN", "relay", "via-direct", "socks-out", "socks-user", "https-out", "ss-alias"}
	if strings.Join(tags, "|") != strings.Join(want, "|") {
		t.Fatalf("imported %q", tags)
	}
	// The first proxy is named by the remarks, its dialer is its detour; the
	// Host header from "headers" (in any case) wins over the server name
	checkOutbound(t, byTag["My VPN"], `{"type":"vless","server":"203.0.113.70","detour":"relay",
	  "tls":{"server_name":"front.example.com"},"transport":{"type":"ws","path":"/front","headers":{"Host":"ws.example.com"}}}`)
	checkOutbound(t, byTag["relay"], `{"type":"trojan","server":"203.0.113.71","password":"relay-pw","detour":null,
	  "tls":{"enabled":true,"server_name":"relay.example.com","utls":null}}`)
	// A plain freedom as the dialer is no detour; Xray runs a VMess cipher it
	// does not know as auto
	checkOutbound(t, byTag["via-direct"], `{"type":"vmess","server":"2001:db8::72","server_port":8080,"security":"auto","detour":null,"transport":null}`)
	checkOutbound(t, byTag["socks-out"], `{"type":"socks","server":"203.0.113.73","server_port":1080,"username":"u","password":"p@ss","version":null}`)
	// A user name alone is a user name, not v2rayN's base64 of user:password;
	// a UDP mask leaves UDP off, as on an ss:// link
	checkOutbound(t, byTag["socks-user"], `{"type":"socks","username":"YTpi","password":null,"network":"tcp"}`)
	checkOutbound(t, byTag["socks-out"], `{"network":null}`)
	// No link for an HTTP proxy: built, offering HTTP/1.1 only (sing-box's
	// speaks no HTTP/2)
	checkOutbound(t, byTag["https-out"], `{"type":"http","server":"proxy.example.com","server_port":443,"username":"u","password":"p",
	  "headers":{"X-Token":"t"},"tls":{"enabled":true,"server_name":"proxy.example.com","alpn":["http/1.1"]}}`)
	checkOutbound(t, byTag["ss-alias"], `{"type":"shadowsocks","method":"chacha20-ietf-poly1305","password":"pw"}`)

	checkReasons(t, reasons, map[string]string{
		"ring-a":         "кольцо",
		"ring-b":         "кольцо",
		"via-missing":    "через «nowhere», которого нет",
		"via-block":      "через «block», которого нет",
		"via-redirect":   "через «redirector» с параметром redirect",
		"via-mask":       "через «masked» с параметром finalmask",
		"proxy-settings": "proxySettings",
		"stream-address": "streamSettings.address",
		"srv":            "addressPortStrategy",
		"kcp":            "mKCP",
		"wg":             "WireGuard",
		"masque-out":     "протокол «masque» не поддерживается",
		"socks-tls":      "режим защиты «tls» для SOCKS",
		"http-ws":        "транспорт «ws» для HTTP-прокси",
		"custom-ca":      "certificates",
		"reverse":        "reverse",
		"env-address":    "неверный адрес сервера",
		"pin-insecure":   "закрепление сертификата (pcs)",
		"no-port":        "неверный порт",
		"no-password":    "не указан пароль",
		"trojan-flow":    "flow «xtls-rprx-direct» для Trojan",
		"broken":         "запись outbound повреждена",
	})
}

// The tags of a configuration name each other only within it: two nodes of
// 3x-ui's array dialing through a "relay" each get their own relay. A node
// without a tag (Xray's may have none) chains like any other.
func TestXrayChainsPerConfig(t *testing.T) {
	config := func(remarks, server, relay string) string {
		return `{"remarks": "` + remarks + `", "outbounds": [
		  {"protocol": "vless", "settings": {"address": "` + server + `", "port": 443, "id": "` + testUUID + `"},
		   "streamSettings": {"security": "tls", "sockopt": {"dialerProxy": "relay"}}},
		  {"protocol": "trojan", "tag": "relay", "settings": {"address": "` + relay + `", "port": 443, "password": "pw"}}]}`
	}
	byTag, tags, reasons := parseXray(t, "["+config("A", "203.0.113.1", "198.51.100.1")+","+config("B", "203.0.113.2", "198.51.100.2")+"]")
	if strings.Join(tags, "|") != "A|relay|B|relay (2)" || len(reasons) != 0 {
		t.Fatalf("imported %q, skipped %v", tags, reasons)
	}
	checkOutbound(t, byTag["A"], `{"detour":"relay"}`)
	checkOutbound(t, byTag["B"], `{"server":"203.0.113.2","detour":"relay (2)"}`)
	checkOutbound(t, byTag["relay (2)"], `{"server":"198.51.100.2"}`)

	// A bare array of outbounds is one configuration; no remarks, no tag:
	// the link parser's name
	byTag, tags, reasons = parseXray(t, `[
	  {"protocol": "vless", "settings": {"address": "203.0.113.3", "port": 443, "id": "`+testUUID+`"}, "streamSettings": {"sockopt": {"dialerProxy": "relay"}}},
	  {"protocol": "trojan", "tag": "relay", "settings": {"address": "198.51.100.3", "port": 443, "password": "pw"}}]`)
	if strings.Join(tags, "|") != "vless-203.0.113.3-443|relay" || len(reasons) != 0 {
		t.Fatalf("imported %q, skipped %v", tags, reasons)
	}
	checkOutbound(t, byTag["vless-203.0.113.3-443"], `{"detour":"relay"}`)
}

// The outbounds are read as Xray reads them (encoding/json): keys in any
// case, the last of two spellings of one key, "method" over "network",
// rawSettings over tcpSettings, REALITY's "password" over "publicKey", a
// string list as one comma-separated string; the flat settings over vnext
func TestXrayKeysReadAsXrayReadsThem(t *testing.T) {
	byTag, tags, reasons := parseXray(t, `[
	  {"Protocol": "VLESS", "Tag": "folded",
	   "Settings": {"Address": "203.0.113.1", "Port": 443, "ID": "`+testUUID+`", "Flow": "XTLS-RPRX-VISION"},
	   "StreamSettings": {"network": "kcp", "Network": "WS", "Security": "TLS",
	     "TLSSettings": {"ServerName": "a.example.com"}, "WSSettings": {"Path": "/p"}}},
	  {"protocol": "vmess", "tag": "method", "settings": {"address": "203.0.113.2", "port": 443, "id": "`+testUUID+`"},
	   "streamSettings": {"network": "ws", "method": "grpc", "security": "tls", "tlsSettings": {"alpn": "h2,http/1.1"},
	     "grpcSettings": {"serviceName": "g"}}},
	  {"protocol": "vless", "tag": "flat-wins",
	   "settings": {"address": "203.0.113.3", "port": 443, "id": "`+testUUID+`",
	     "vnext": [{"address": "198.51.100.9", "port": 8443, "users": [{"id": "`+testUUID+`", "flow": "xtls-rprx-direct"}]}]},
	   "streamSettings": {"security": "tls"}},
	  {"protocol": "trojan", "tag": "raw-wins", "settings": {"address": "203.0.113.4", "port": 80, "password": "pw"},
	   "streamSettings": {"network": "raw", "rawSettings": {"header": {"type": "none"}},
	     "tcpSettings": {"header": {"type": "http", "request": {"path": ["/"]}}}}},
	  {"protocol": "vless", "tag": "password-wins", "settings": {"address": "203.0.113.5", "port": 443, "id": "`+testUUID+`"},
	   "streamSettings": {"security": "reality",
	     "realitySettings": {"serverName": "www.example.com", "publicKey": "`+testSecret+`", "password": "`+testPBK+`", "shortId": "ab"}}},
	  {"protocol": "freedom", "tag": "direct"}
	]`)
	if strings.Join(tags, "|") != "folded|method|flat-wins|raw-wins|password-wins" || len(reasons) != 0 {
		t.Fatalf("imported %q, skipped %v", tags, reasons)
	}
	checkOutbound(t, byTag["folded"], `{"type":"vless","server":"203.0.113.1","flow":"xtls-rprx-vision",
	  "tls":{"server_name":"a.example.com"},"transport":{"type":"ws","path":"/p","headers":{"Host":"a.example.com"}}}`)
	checkOutbound(t, byTag["method"], `{"type":"vmess","tls":{"alpn":["h2","http/1.1"]},"transport":{"type":"grpc","service_name":"g"}}`)
	checkOutbound(t, byTag["flat-wins"], `{"server":"203.0.113.3","server_port":443,"flow":null}`)
	checkOutbound(t, byTag["raw-wins"], `{"type":"trojan","transport":null}`)
	checkOutbound(t, byTag["password-wins"], `{"tls":{"reality":{"public_key":"`+testPBK+`","short_id":"ab"}}}`)
}

// ECH of 3x-ui's JSON subscription (putClientTLSVerification copies
// echConfigList): the config list, or the record looked up in DNS — never
// dropped, the hidden server name would go in the clear
func TestXrayECH(t *testing.T) {
	node := func(tag, ech string) string {
		return `{"protocol": "vless", "tag": "` + tag + `", "settings": {"address": "203.0.113.5", "port": 443, "id": "` + testUUID + `"},
		  "streamSettings": {"network": "ws", "security": "tls", "wsSettings": {"path": "/ws"},
		    "tlsSettings": {"serverName": "hidden.example.com", "echConfigList": "` + ech + `"}}}`
	}
	byTag, _, reasons := parseXray(t, `{"outbounds": [`+node("list", testECH)+`, `+node("dns", "cloudflare-ech.com+udp://1.1.1.1")+`,
	  `+node("broken", testSecret)+`]}`)
	checkOutbound(t, byTag["list"], `{"tls":{"server_name":"hidden.example.com",
	  "ech":{"enabled":true,"config":["-----BEGIN ECH CONFIGS-----","`+testECH+`","-----END ECH CONFIGS-----"]}}}`)
	checkOutbound(t, byTag["dns"], `{"tls":{"ech":{"enabled":true,"query_server_name":"cloudflare-ech.com"}}}`)
	checkReasons(t, reasons, map[string]string{"broken": "конфигурация ECH повреждена"})
}

// Xray sends grpcSettings.authority as gRPC's :authority, sing-box the TLS
// server name: a node is kept only where the two are the same
func TestXrayGRPCAuthority(t *testing.T) {
	node := func(tag, authority string) string {
		return `{"protocol": "trojan", "tag": "` + tag + `", "settings": {"address": "203.0.113.30", "port": 443, "password": "pw"},
		  "streamSettings": {"network": "grpc", "security": "tls", "tlsSettings": {"serverName": "front.example.com"},
		    "grpcSettings": {"serviceName": "svc", "authority": "` + authority + `"}}}`
	}
	byTag, tags, reasons := parseXray(t, `{"outbounds": [`+node("empty", "")+`, `+node("same", "FRONT.example.com")+`, `+node("other", "real.example.net")+`]}`)
	if strings.Join(tags, "|") != "empty|same" {
		t.Errorf("imported %q", tags)
	}
	checkOutbound(t, byTag["same"], `{"tls":{"server_name":"front.example.com"},"transport":{"type":"grpc","service_name":"svc"}}`)
	checkReasons(t, reasons, map[string]string{"other": "имя для gRPC (authority) отличается от имени сервера"})
}

// Xray's h2 transport is HTTP/2: over TLS (or REALITY) sing-box's http
// transport speaks it, without TLS that one speaks HTTP/1.1 — refused, as
// a Clash profile's h2 without TLS is
func TestXrayH2NeedsTLS(t *testing.T) {
	node := func(tag, network, security string) string {
		return `{"protocol": "vless", "tag": "` + tag + `", "settings": {"address": "203.0.113.5", "port": 443, "id": "` + testUUID + `"},
		  "streamSettings": {"network": "` + network + `", ` + security + `"httpSettings": {"host": ["a.example.com"], "path": "/h2"}}}`
	}
	byTag, _, reasons := parseXray(t, `{"outbounds": [`+node("tls", "h2", `"security": "tls", "tlsSettings": {"serverName": "a.example.com"}, `)+`,
	  `+node("reality", "http", `"security": "reality", "realitySettings": {"serverName": "www.example.com", "publicKey": "`+testPBK+`"}, `)+`,
	  `+node("plain", "h2", "")+`, `+node("none", "http", `"security": "none", `)+`]}`)
	checkOutbound(t, byTag["tls"], `{"tls":{"server_name":"a.example.com"},"transport":{"type":"http","host":["a.example.com"],"path":"/h2"}}`)
	checkOutbound(t, byTag["reality"], `{"tls":{"reality":{"enabled":true}},"transport":{"type":"http"}}`)
	checkReasons(t, reasons, map[string]string{
		"plain": "транспорт h2 без TLS не поддерживается sing-box",
		"none":  "транспорт h2 без TLS не поддерживается sing-box",
	})
}

// Without a server name TLS checks the address, as in Xray — a link would
// take the WebSocket's host for it
func TestXrayServerNameIsTheAddress(t *testing.T) {
	byTag, _, reasons := parseXray(t, `{"outbounds": [{"protocol": "vless", "tag": "cdn",
	  "settings": {"address": "203.0.113.5", "port": 443, "id": "`+testUUID+`"},
	  "streamSettings": {"network": "ws", "security": "tls", "wsSettings": {"host": "front.example.com", "path": "/ws"}}}]}`)
	if len(reasons) != 0 {
		t.Fatalf("skipped %v", reasons)
	}
	checkOutbound(t, byTag["cdn"], `{"tls":{"server_name":"203.0.113.5"},"transport":{"headers":{"Host":"front.example.com"}}}`)
}

// A reason names the node and what was refused, never a credential; a
// provider's text in a name stays on one line
func TestXrayReasonsQuoteNoSecret(t *testing.T) {
	fake := "x»\n\nВнимание! Подписка истекла.\n\n«y"
	quoted, _ := json.Marshal(fake)
	broken := `[{"remarks": ` + string(quoted) + `, "outbounds": [{"protocol": "vless", "tag": "proxy",
	  "settings": {"address": "203.0.113.1", "port": 443, "id": "` + testSecret + `", "encryption": "mlkem768x25519plus.native.0rtt.` + testSecret + `"}}]},
	  {"outbounds": [{"protocol": "trojan", "tag": 5}]}]`
	var all []domain.SkippedNode
	for _, body := range append([]string{broken}, xray3xui, xray3xuiFragment, xrayConfig) {
		_, skipped, err := ParseAllReport(body)
		if err != nil && (strings.Contains(err.Error(), testSecret) || strings.Contains(err.Error(), testUUID)) {
			t.Errorf("error quotes the profile: %v", err)
		}
		all = append(all, skipped...)
	}
	// Remarks on more than one line name no node: its tag does
	if all[0].Name != "proxy" || !strings.Contains(all[0].Reason, "mlkem768x25519plus") || all[1].Name != "узел 2" {
		t.Errorf("skipped %+v", all[:2])
	}
	for _, sk := range all {
		if !russian(sk.Reason) || !plainName(sk.Name) || !plainName(sk.Reason) || strings.Contains(sk.Reason, "Внимание") ||
			strings.Contains(sk.Reason, testSecret) || strings.Contains(sk.Reason, testUUID) || strings.Contains(sk.Name, testSecret) {
			t.Errorf("skipped %q: %q", sk.Name, sk.Reason)
		}
	}
}

// What profile() took for Xray before and refused: now read
func TestXrayProfilesAreRead(t *testing.T) {
	xray := `{"outbounds": [{"protocol": "vless", "tag": "proxy", "settings": {"vnext": [{"address": "192.0.2.10", "port": 443,
	  "users": [{"id": "` + testUUID + `", "encryption": "none"}]}]}}, {"protocol": "freedom", "tag": "direct"}]}`
	outbounds, skipped, err := ParseAllReport(xray)
	if err != nil || len(outbounds) != 1 || outbounds[0].Tag() != "proxy" || len(skipped) != 0 {
		t.Errorf("got %v, %+v, %v", outbounds, skipped, err)
	}
	_, _, err = ParseAllReport(`[{"remarks": "DE", "outbounds": [{"protocol": "vless", "settings": {}}]}]`)
	if err == nil || !strings.Contains(err.Error(), "«DE» — не указан адрес сервера") {
		t.Errorf("error %v", err)
	}
	_, _, err = ParseAllReport(`{"outbounds": [{"protocol": "freedom", "tag": "direct"}, {"protocol": "blackhole", "tag": "block"}]}`)
	if !errors.Is(err, errEmptyProfile) {
		t.Errorf("error %v, want %v", err, errEmptyProfile)
	}
}
