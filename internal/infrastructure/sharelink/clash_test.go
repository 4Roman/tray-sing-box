package sharelink

import (
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"tray-sing-box/internal/domain"
)

// clashProxyList is a Clash profile of nothing but the given proxy entries
// (block YAML, each starting with "  - ")
func clashProxyList(entries ...string) string {
	return "proxies:\n" + strings.Join(entries, "\n")
}

// clash3xui is a profile as 3x-ui's SubClashService writes it (goccy/go-yaml:
// keys sorted, lists not indented, ambiguous scalars single-quoted): the info
// node first, then one entry per inbound, and the select group with the
// MATCH rule. The ss-over-ws entry is what 3x-ui writes for Shadowsocks on an
// Xray transport; mihomo ignores the transport.
const clash3xui = `proxies:
- name: '⏳ 12.4GB / 30 days left'
  port: 1080
  server: 127.0.0.1
  type: socks5
- client-fingerprint: chrome
  flow: xtls-rprx-vision
  name: DE-reality
  network: tcp
  port: 443
  reality-opts:
    public-key: ` + testPBK + `
    short-id: '2351e1'
    support-x25519mlkem768: true
  server: 192.0.2.10
  servername: www.example.com
  tls: true
  type: vless
  udp: true
  uuid: ` + testUUID + `
- alpn:
  - h2
  - http/1.1
  client-fingerprint: firefox
  name: NL-ws
  network: ws
  port: 443
  server: cdn.example.com
  servername: cdn.example.com
  tls: true
  type: vless
  udp: true
  uuid: ` + testUUID + `
  ws-opts:
    headers:
      Host: cdn.example.com
    path: /ws?ed=2048
- alterId: 0
  cipher: auto
  grpc-opts:
    grpc-service-name: grpcsvc
  name: FI-vmess-grpc
  network: grpc
  port: 443
  server: 192.0.2.20
  servername: example.com
  tls: true
  type: vmess
  udp: true
  uuid: ` + testUUID + `
- name: SE-trojan
  network: tcp
  password: pw-trojan
  port: 443
  server: 192.0.2.30
  servername: example.com
  sni: example.com
  tls: true
  type: trojan
  udp: true
- cipher: 2022-blake3-aes-128-gcm
  name: PL-ss
  network: tcp
  password: MDEyMzQ1Njc4OWFiY2RlZg==:ZmVkY2JhOTg3NjU0MzIxMA==
  port: 8388
  server: 192.0.2.40
  tls: false
  type: ss
  udp: true
- alpn:
  - h3
  name: US-hy2
  obfs: salamander
  obfs-password: obfs-pw
  password: hy2-pw
  port: 443
  ports: 20000-30000
  server: 192.0.2.50
  sni: hy.example.com
  type: hysteria2
  udp: true
- alpn:
  - h3
  congestion-controller: bbr
  name: JP-tuic
  password: tuic-pw
  port: 443
  reduce-rtt: false
  server: 192.0.2.60
  sni: tuic.example.com
  type: tuic
  udp-relay-mode: native
  uuid: ` + testUUID + `
- name: HU-upgrade
  network: httpupgrade
  http-upgrade-opts:
    headers:
      Host: hu.example.com
    path: /hu
  port: 443
  server: 192.0.2.12
  servername: hu.example.com
  tls: true
  type: vless
  udp: true
  uuid: ` + testUUID + `
- client-fingerprint: chrome
  name: XH-xhttp
  network: xhttp
  port: 443
  server: 192.0.2.11
  servername: www.example.com
  tls: true
  type: vless
  udp: true
  uuid: ` + testUUID + `
  xhttp-opts:
    mode: auto
    path: /xh
- ip: 10.0.0.2
  name: WG
  port: 51820
  private-key: ` + testSecret + `
  public-key: x
  server: 192.0.2.90
  type: wireguard
  udp: true
- cipher: chacha20-ietf-poly1305
  name: SS-ws
  network: ws
  password: ` + testSecret + `
  port: 443
  server: cdn.example.com
  servername: cdn.example.com
  tls: true
  type: ss
  udp: true
  ws-opts:
    path: /` + testSecret + `
proxy-groups:
- name: PROXY
  proxies:
  - DE-reality
  - NL-ws
  - DIRECT
  type: select
rules:
- MATCH,PROXY
`

func TestClash3xuiProfile(t *testing.T) {
	outbounds, skipped, err := ParseAllReport(clash3xui)
	if err != nil {
		t.Fatalf("ParseAllReport: %v", err)
	}
	byTag := map[string]Outbound{}
	var tags []string
	for _, o := range outbounds {
		byTag[o.Tag()] = o
		tags = append(tags, o.Tag())
	}
	if strings.Join(tags, ",") != "⏳ 12.4GB / 30 days left,DE-reality,NL-ws,FI-vmess-grpc,SE-trojan,PL-ss,US-hy2,JP-tuic,HU-upgrade" {
		t.Fatalf("imported %q", tags)
	}
	// The info node stays a node here: the subscription drops it, a
	// clipboard import keeps it, as for links
	checkOutbound(t, byTag["⏳ 12.4GB / 30 days left"], `{"type":"socks","server":"127.0.0.1","server_port":1080}`)
	checkOutbound(t, byTag["DE-reality"], `{"type":"vless","server":"192.0.2.10","server_port":443,"uuid":"`+testUUID+`",
	  "flow":"xtls-rprx-vision","transport":null,"tls":{"enabled":true,"server_name":"www.example.com",
	  "utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,"public_key":"`+testPBK+`","short_id":"2351e1"}}}`)
	checkOutbound(t, byTag["NL-ws"], `{"tls":{"server_name":"cdn.example.com","alpn":null,"utls":{"fingerprint":"firefox"}},
	  "transport":{"type":"ws","path":"/ws","headers":{"Host":"cdn.example.com"},"max_early_data":2048,"early_data_header_name":"Sec-WebSocket-Protocol"}}`)
	checkOutbound(t, byTag["FI-vmess-grpc"], `{"type":"vmess","security":"auto","alter_id":0,"tls":{"server_name":"example.com"},
	  "transport":{"type":"grpc","service_name":"grpcsvc"}}`)
	checkOutbound(t, byTag["SE-trojan"], `{"type":"trojan","password":"pw-trojan","tls":{"enabled":true,"server_name":"example.com"},"transport":null}`)
	checkOutbound(t, byTag["PL-ss"], `{"type":"shadowsocks","method":"2022-blake3-aes-128-gcm",
	  "password":"MDEyMzQ1Njc4OWFiY2RlZg==:ZmVkY2JhOTg3NjU0MzIxMA==","plugin":null}`)
	checkOutbound(t, byTag["US-hy2"], `{"type":"hysteria2","password":"hy2-pw","server_port":443,"server_ports":["20000:30000"],
	  "obfs":{"type":"salamander","password":"obfs-pw"},"tls":{"server_name":"hy.example.com","alpn":["h3"],"utls":null}}`)
	checkOutbound(t, byTag["JP-tuic"], `{"type":"tuic","uuid":"`+testUUID+`","password":"tuic-pw","congestion_control":"bbr",
	  "udp_relay_mode":"native","tls":{"server_name":"tuic.example.com","alpn":["h3"]}}`)
	checkOutbound(t, byTag["HU-upgrade"], `{"transport":{"type":"httpupgrade","path":"/hu","host":"hu.example.com"},"tls":{"server_name":"hu.example.com"}}`)

	reasons := map[string]string{}
	for _, sk := range skipped {
		reasons[sk.Name] = sk.Reason
		if !russian(sk.Reason) || strings.Contains(sk.Reason, testSecret) {
			t.Errorf("reason %q", sk.Reason)
		}
	}
	if len(skipped) != 3 || !strings.Contains(reasons["XH-xhttp"], "XHTTP") || !strings.Contains(reasons["WG"], "WireGuard") ||
		!strings.Contains(reasons["SS-ws"], "транспорт «ws» для Shadowsocks") {
		t.Fatalf("skipped = %+v", skipped)
	}
}

// clashCase is a proxy entry that must be converted; want is a JSON subset
// of the outbound (null: the key must be absent)
type clashCase struct {
	name, entry, want string
}

// acceptedClash: what each entry means in mihomo, as the links say it.
// Shapes after mihomo's docs/config.yaml and 3x-ui's generator.
var acceptedClash = []clashCase{
	{"vless REALITY with an unquoted short-id", `
  - name: R
    type: vless
    server: 192.0.2.10
    port: 443
    uuid: ` + testUUID + `
    tls: true
    flow: xtls-rprx-vision-udp443
    servername: www.example.com
    reality-opts:
      public-key: ` + testPBK + `
      short-id: 2351e1`,
		`{"type":"vless","tag":"R","flow":"xtls-rprx-vision","tls":{"server_name":"www.example.com",
		  "utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,"short_id":"2351e1"}}}`},
	{"vless without tls is plain", `
  - name: plain
    type: vless
    server: 192.0.2.10
    port: 80
    uuid: ` + testUUID + `
    servername: ignored.example.com`,
		`{"tls":null,"transport":null}`},
	{"vless ws: the Host header is the server name, early data with its header", `
  - name: ws
    type: vless
    server: 192.0.2.11
    port: 443
    uuid: ` + testUUID + `
    tls: true
    network: ws
    alpn: [h2, http/1.1]
    ws-opts:
      path: /ws
      headers:
        Host: cdn.example.com
        User-Agent: x
      max-early-data: 2048
      early-data-header-name: Sec-WebSocket-Protocol`,
		`{"tls":{"server_name":"cdn.example.com","alpn":null,"utls":{"fingerprint":"chrome"}},
		  "transport":{"type":"ws","path":"/ws","headers":{"Host":"cdn.example.com","User-Agent":null},
		  "max_early_data":2048,"early_data_header_name":"Sec-WebSocket-Protocol"}}`},
	{"ws early data without a header name is left out", `
  - name: ws-ed
    type: vless
    server: 192.0.2.11
    port: 443
    uuid: ` + testUUID + `
    tls: true
    servername: example.com
    client-fingerprint: none
    network: ws
    ws-opts:
      path: /ws
      max-early-data: 2048`,
		`{"tls":{"server_name":"example.com","utls":null},"transport":{"type":"ws","path":"/ws","max_early_data":null,"early_data_header_name":null}}`},
	{"ws with v2ray-http-upgrade is HTTPUpgrade", `
  - name: hu
    type: vless
    server: 192.0.2.12
    port: 80
    uuid: ` + testUUID + `
    network: ws
    ws-opts:
      path: /hu
      headers: {host: example.com}
      v2ray-http-upgrade: true`,
		`{"tls":null,"transport":{"type":"httpupgrade","path":"/hu","host":"example.com"}}`},
	{"vmess grpc with alterId and skip-cert-verify", `
  - name: vm-grpc
    type: vmess
    server: 192.0.2.20
    port: 443
    uuid: ` + testUUID + `
    alterId: 64
    cipher: auto
    network: grpc
    tls: true
    servername: example.com
    skip-cert-verify: true
    grpc-opts:
      grpc-service-name: svc`,
		`{"type":"vmess","tag":"vm-grpc","alter_id":64,"security":"auto","tls":{"server_name":"example.com","insecure":true},
		  "transport":{"type":"grpc","service_name":"svc"}}`},
	{"vmess ws early data travels in the path of the JSON form", `
  - name: vm-ws
    type: vmess
    server: 192.0.2.20
    port: 80
    uuid: ` + testUUID + `
    alterId: 0
    cipher: chacha20-poly1305
    network: ws
    ws-opts:
      path: /vm
      headers:
        Host: v.example.com
      max-early-data: 2048
      early-data-header-name: X-Early-Data`,
		`{"security":"chacha20-poly1305","tls":null,"transport":{"type":"ws","path":"/vm","headers":{"Host":"v.example.com"},
		  "max_early_data":2048,"early_data_header_name":"X-Early-Data"}}`},
	{"vmess h2: the server, not the h2 host, is the server name", `
  - name: vm-h2
    type: vmess
    server: 192.0.2.20
    port: 443
    uuid: ` + testUUID + `
    alterId: 0
    cipher: auto
    network: h2
    tls: true
    h2-opts:
      host:
        - a.example.com
        - b.example.com
      path: /h2`,
		`{"tls":{"server_name":"192.0.2.20"},"transport":{"type":"http","host":["a.example.com","b.example.com"],"path":"/h2"}}`},
	// mihomo offers h2 alone over gRPC and h2 (a host's alpn that Marzban
	// writes on every node does not reach them): sing-box offers h2 there
	// only when tls.alpn is empty
	{"vless grpc: h2 whatever alpn says", `
  - name: vl-grpc-alpn
    type: vless
    server: 192.0.2.10
    port: 443
    uuid: ` + testUUID + `
    tls: true
    servername: my.example.com
    alpn: [http/1.1]
    network: grpc
    grpc-opts:
      grpc-service-name: svc`,
		`{"tls":{"server_name":"my.example.com","alpn":null},"transport":{"type":"grpc","service_name":"svc"}}`},
	{"vmess h2: h2 whatever alpn says", `
  - name: vm-h2-alpn
    type: vmess
    server: 192.0.2.20
    port: 443
    uuid: ` + testUUID + `
    alterId: 0
    cipher: auto
    tls: true
    alpn: [http/1.1]
    network: h2
    h2-opts:
      path: /h2`,
		`{"tls":{"alpn":null},"transport":{"type":"http","path":"/h2"}}`},
	{"trojan grpc: h2 whatever alpn says", `
  - name: tr-grpc-alpn
    server: 192.0.2.30
    port: 443
    type: trojan
    password: example
    alpn: [http/1.1]
    network: grpc`,
		`{"tls":{"alpn":null},"transport":{"type":"grpc"}}`},
	{"vless over TCP keeps its alpn", `
  - name: vl-tcp-alpn
    type: vless
    server: 192.0.2.10
    port: 443
    uuid: ` + testUUID + `
    tls: true
    alpn: [http/1.1]`,
		`{"tls":{"alpn":["http/1.1"]},"transport":null}`},
	{"vmess http: TCP with the HTTP header", `
  - name: vm-http
    type: vmess
    server: 192.0.2.20
    port: 80
    uuid: ` + testUUID + `
    alterId: 0
    cipher: auto
    network: http
    http-opts:
      method: GET
      path:
        - /
        - /video
      headers:
        Host: [h.example.com]
        Connection:
          - keep-alive`,
		`{"tls":null,"transport":{"type":"http","method":"GET","path":"/","host":["h.example.com"]}}`},
	{"vmess before ws-opts: ws-path and ws-headers", `
  - name: vm-old
    type: vmess
    server: 192.0.2.20
    port: 80
    uuid: ` + testUUID + `
    alterId: 0
    cipher: auto
    network: ws
    ws-path: /old
    ws-headers:
      Host: old.example.com`,
		`{"transport":{"type":"ws","path":"/old","headers":{"Host":"old.example.com"}}}`},
	{"trojan grpc", `
  - name: tr-grpc
    server: 192.0.2.30
    port: 443
    type: trojan
    password: example
    network: grpc
    sni: example.com
    udp: true
    grpc-opts:
      grpc-service-name: example`,
		`{"type":"trojan","tag":"tr-grpc","password":"example","tls":{"enabled":true,"server_name":"example.com","utls":{"fingerprint":"chrome"}},
		  "transport":{"type":"grpc","service_name":"example"}}`},
	{"trojan ws: its sni or the server, never the Host header", `
  - name: tr-ws
    server: 192.0.2.30
    port: 443
    type: trojan
    password: example
    network: ws
    ws-opts:
      headers:
        Host: cdn.example.com`,
		`{"tls":{"server_name":"192.0.2.30"},"transport":{"type":"ws","headers":{"Host":"cdn.example.com"}}}`},
	// The Host header mihomo sends when the entry names none: trojan's
	// server name, the server for vless and vmess — not sing-box's
	// server:port, nor the TLS server name it and Xray fall back to
	{"trojan ws without a Host header: its sni is the Host", `
  - name: tr-ws-sni
    server: 104.16.1.1
    port: 443
    type: trojan
    password: example
    sni: my.example.com
    network: ws
    ws-opts:
      path: /ws`,
		`{"tls":{"server_name":"my.example.com"},"transport":{"type":"ws","path":"/ws","headers":{"Host":"my.example.com"}}}`},
	{"trojan HTTPUpgrade without a host: the server, its sni", `
  - name: tr-hu
    server: 192.0.2.30
    port: 443
    type: trojan
    password: example
    network: ws
    ws-opts:
      v2ray-http-upgrade: true`,
		`{"tls":{"server_name":"192.0.2.30"},"transport":{"type":"httpupgrade","host":"192.0.2.30"}}`},
	{"vless ws over TLS without a Host header: the server, not the server name", `
  - name: vl-ws-server
    type: vless
    server: cdn.example.net
    port: 443
    uuid: ` + testUUID + `
    tls: true
    servername: my.example.com
    network: ws
    ws-opts:
      path: /ws`,
		`{"tls":{"server_name":"my.example.com"},"transport":{"type":"ws","path":"/ws","headers":{"Host":"cdn.example.net"}}}`},
	{"vless HTTPUpgrade over TLS without a host: the server, not the server name", `
  - name: vl-hu-server
    type: vless
    server: 192.0.2.12
    port: 443
    uuid: ` + testUUID + `
    tls: true
    servername: hu.example.com
    network: ws
    ws-opts:
      path: /hu
      v2ray-http-upgrade: true`,
		`{"tls":{"server_name":"hu.example.com"},"transport":{"type":"httpupgrade","path":"/hu","host":"192.0.2.12"}}`},
	// mihomo sends a random host there: nothing the server can check
	{"vless ws without TLS and a Host header: sing-box's own", `
  - name: vl-ws-plain
    type: vless
    server: 192.0.2.11
    port: 80
    uuid: ` + testUUID + `
    network: ws`,
		`{"tls":null,"transport":{"type":"ws","headers":null}}`},
	{"vmess ws without TLS and a Host header: the server", `
  - name: vm-ws-plain
    type: vmess
    server: 192.0.2.20
    port: 8080
    uuid: ` + testUUID + `
    alterId: 0
    cipher: auto
    network: ws
    ws-opts:
      path: /vm`,
		`{"tls":null,"transport":{"type":"ws","path":"/vm","headers":{"Host":"192.0.2.20"}}}`},
	// The key the other protocol reads is what the generator meant
	{"trojan with servername only", `
  - name: tr-servername
    server: 192.0.2.30
    port: 443
    type: trojan
    password: example
    servername: t.example.com`,
		`{"tls":{"server_name":"t.example.com"}}`},
	{"vless with sni only", `
  - name: vless-sni
    type: vless
    server: 192.0.2.10
    port: 443
    uuid: ` + testUUID + `
    tls: true
    sni: v.example.com`,
		`{"tls":{"server_name":"v.example.com"}}`},
	{"trojan with tls false (3x-ui's plain trojan)", `
  - name: tr-plain
    server: 192.0.2.30
    port: 80
    type: trojan
    password: example
    tls: false`,
		`{"type":"trojan","tls":null}`},
	{"trojan REALITY", `
  - name: tr-reality
    server: 192.0.2.30
    port: 443
    type: trojan
    password: example
    sni: www.example.com
    client-fingerprint: safari
    reality-opts:
      public-key: ` + testPBK + `
      short-id: 6ba85179`,
		`{"tls":{"server_name":"www.example.com","utls":{"fingerprint":"safari"},"reality":{"public_key":"` + testPBK + `","short_id":"6ba85179"}}}`},
	{"ss with an unquoted all-digit password", `
  - name: ss-digits
    type: ss
    server: 192.0.2.40
    port: 8388
    cipher: aes-256-gcm
    password: 0123`,
		`{"type":"shadowsocks","method":"aes-256-gcm","password":"0123","udp_over_tcp":null}`},
	// UDP inside the TCP connection: mihomo's version 1 when none is given
	// (sing-box's own default is 2)
	{"ss udp-over-tcp", `
  - name: ss-uot
    type: ss
    server: 192.0.2.12
    port: 8388
    cipher: 2022-blake3-aes-128-gcm
    password: MDEyMzQ1Njc4OWFiY2RlZg==
    udp: true
    udp-over-tcp: true`,
		`{"type":"shadowsocks","udp_over_tcp":{"enabled":true,"version":1}}`},
	{"ss udp-over-tcp version 2", `
  - name: ss-uot2
    type: ss
    server: 192.0.2.12
    port: 8388
    cipher: aes-128-gcm
    password: pw
    plugin: obfs
    plugin-opts: {mode: http}
    udp-over-tcp: true
    udp-over-tcp-version: "2"`,
		`{"type":"shadowsocks","plugin":"obfs-local","udp_over_tcp":{"enabled":true,"version":2}}`},
	{"ss udp-over-tcp off", `
  - name: ss-uot-off
    type: ss
    server: 192.0.2.12
    port: 8388
    cipher: aes-128-gcm
    password: pw
    udp-over-tcp: false
    udp-over-tcp-version: 2`,
		`{"type":"shadowsocks","udp_over_tcp":null}`},
	{"ss obfs: mihomo's default host", `
  - name: ss-obfs
    type: ss
    server: 192.0.2.40
    port: 443
    cipher: chacha20-ietf-poly1305
    password: password
    plugin: obfs
    plugin-opts:
      mode: tls`,
		`{"plugin":"obfs-local","plugin_opts":"obfs=tls;obfs-host=bing.com"}`},
	{"ss v2ray-plugin with mux off", `
  - name: ss-v2ray
    type: ss
    server: 192.0.2.40
    port: 443
    cipher: chacha20-ietf-poly1305
    password: password
    plugin: v2ray-plugin
    plugin-opts:
      mode: websocket
      tls: true
      host: example.com
      path: /v2
      mux: false`,
		`{"plugin":"v2ray-plugin","plugin_opts":"mode=websocket;host=example.com;path=/v2;tls;mux=0"}`},
	{"ss v2ray-plugin defaults: bing.com, mux on", `
  - name: ss-v2ray-default
    type: ss
    server: 192.0.2.40
    port: 80
    cipher: chacha20-ietf-poly1305
    password: password
    plugin: v2ray-plugin
    plugin-opts:
      mode: websocket`,
		`{"plugin":"v2ray-plugin","plugin_opts":"mode=websocket;host=bing.com;mux=1"}`},
	{"hysteria2 with hopping ports in mihomo's '/' form", `
  - name: hy2
    type: hysteria2
    server: 192.0.2.50
    port: 443
    ports: 20000-30000/40000
    hop-interval: 15
    password: pw
    sni: hy.example.com
    obfs: gecko
    obfs-password: obfs-pw
    obfs-min-packet-size: 512
    alpn: [h3]`,
		`{"type":"hysteria2","server_port":443,"server_ports":["20000:30000","40000:40000"],"hop_interval":"15s",
		  "obfs":{"type":"gecko","password":"obfs-pw"},"tls":{"server_name":"hy.example.com","alpn":["h3"]}}`},
	{"hysteria2 with ports and no port", `
  - name: hy2-ports
    type: hysteria2
    server: 192.0.2.50
    ports: 20000-30000
    password: pw
    alpn: h3`,
		`{"server_port":20000,"server_ports":["20000:30000"],"tls":{"server_name":"192.0.2.50","alpn":["h3"]}}`},
	{"hysteria v1", `
  - name: hy1
    type: hysteria
    server: 192.0.2.70
    port: 443
    auth-str: yourpassword
    obfs: obfs_str
    protocol: udp
    up: "30 Mbps"
    down: 200
    sni: hy1.example.com`,
		`{"type":"hysteria","up_mbps":30,"down_mbps":200,"auth_str":"yourpassword","obfs":"obfs_str","tls":{"server_name":"hy1.example.com"}}`},
	{"hysteria v1: bytes per second, Stash's speed, base64 auth", `
  - name: hy1-units
    type: hysteria
    server: 192.0.2.70
    port: 443
    auth: c2VjcmV0
    auth-str: ignored
    up: 10 MBps
    down: 1 Mbps
    down-speed: 100`,
		`{"up_mbps":80,"down_mbps":100,"auth_str":"secret"}`},
	{"tuic", `
  - name: tuic
    server: tuic.example.com
    port: 10443
    type: tuic
    uuid: ` + testUUID + `
    password: PASSWORD_1
    disable-sni: true
    reduce-rtt: true
    udp-relay-mode: quic
    congestion-controller: new_reno`,
		`{"type":"tuic","server":"tuic.example.com","uuid":"` + testUUID + `","password":"PASSWORD_1","udp_relay_mode":"quic",
		  "congestion_control":"new_reno","tls":{"server_name":"tuic.example.com","disable_sni":true,"alpn":["h3"],"insecure":null}}`},
	{"tuic dials ip, the server stays the server name", `
  - name: tuic-ip
    server: tuic.example.com
    ip: 192.0.2.61
    port: 10443
    type: tuic
    uuid: ` + testUUID + `
    password: pw`,
		`{"server":"192.0.2.61","tls":{"server_name":"tuic.example.com"}}`},
	{"anytls", `
  - name: anytls
    type: anytls
    server: 192.0.2.62
    port: 443
    password: "<your password>"
    sni: a.example.com
    client-fingerprint: firefox
    skip-cert-verify: true
    udp: true`,
		`{"type":"anytls","password":"<your password>","tls":{"server_name":"a.example.com","insecure":true,"utls":{"fingerprint":"firefox"}}}`},
	{"socks5", `
  - name: socks
    type: socks5
    server: 192.0.2.80
    port: 1080
    username: user
    password: pass`,
		`{"type":"socks","server":"192.0.2.80","server_port":1080,"username":"user","password":"pass"}`},
	{"socks5 without a user name has no credentials", `
  - name: socks-anon
    type: socks5
    server: 192.0.2.80
    port: 1080
    password: pass`,
		`{"username":null,"password":null}`},
	// mihomo's decoder: keys case-insensitively, '_' for '-'; numbers and
	// booleans as strings; an IPv6 address bare or bracketed
	{"keys and values as mihomo's decoder reads them", `
  - Name: K
    TYPE: vless
    Server: "[2001:db8::1]"
    PORT: "443"
    UUID: ` + testUUID + `
    TLS: 1
    Network: ws
    Ws_Opts:
      Path: /k
    Skip_Cert_Verify: "true"
    SERVERNAME: k.example.com`,
		`{"type":"vless","tag":"K","server":"2001:db8::1","server_port":443,"tls":{"server_name":"k.example.com","insecure":true},
		  "transport":{"type":"ws","path":"/k","headers":{"Host":"[2001:db8::1]"}}}`},
	// A pin alone is dropped as on the links (the chain is checked), a
	// name-cert-verify for the server name is the ordinary check
	{"pin alone and name-cert-verify of the server name", `
  - name: pinned
    type: vless
    server: 192.0.2.10
    port: 443
    uuid: ` + testUUID + `
    tls: true
    servername: example.com
    fingerprint: AB:CD:EF
    name-cert-verify: example.com`,
		`{"tls":{"server_name":"example.com","insecure":null}}`},
	// YAML merge keys: the entry's own keys win
	{"merge keys", `
  - &base
    name: base
    type: trojan
    server: 192.0.2.30
    port: 443
    password: base-pw
    sni: base.example.com
  - <<: *base
    name: merged
    sni: merged.example.com`,
		`{"tag":"merged","password":"base-pw","tls":{"server_name":"merged.example.com"}}`},
}

func TestClashAccepted(t *testing.T) {
	for _, c := range acceptedClash {
		t.Run(c.name, func(t *testing.T) {
			outbounds, skipped, err := ParseAllReport(clashProxyList(c.entry))
			if err != nil || len(skipped) != 0 {
				t.Fatalf("ParseAllReport: %v, skipped %+v", err, skipped)
			}
			checkOutbound(t, outbounds[len(outbounds)-1], c.want)
		})
	}
}

// clashRefusal is an entry that must be left out, the reason naming why
type clashRefusal struct {
	name, entry, reason string
}

var refusedClash = []clashRefusal{
	{"xhttp", `
  - name: xhttp
    type: vless
    server: 192.0.2.11
    port: 443
    uuid: ` + testUUID + `
    tls: true
    network: xhttp
    xhttp-opts: {path: /` + testSecret + `}`, "XHTTP"},
	{"mkcp", `
  - name: mkcp
    type: vmess
    server: 192.0.2.20
    port: 443
    uuid: ` + testUUID + `
    alterId: 0
    cipher: auto
    network: mkcp
    mkcp-opts: {seed: ` + testSecret + `}`, "mKCP"},
	{"vless-encryption", `
  - name: vless-encryption
    type: vless
    server: 192.0.2.10
    port: 443
    uuid: ` + testUUID + `
    encryption: "mlkem768x25519plus.native.0rtt.` + testSecret + `"`, "mlkem768x25519plus"},
	{"reality-no-tls", `
  - name: reality-no-tls
    type: vless
    server: 192.0.2.10
    port: 443
    uuid: ` + testUUID + `
    reality-opts:
      public-key: ` + testPBK, "REALITY (reality-opts) указан без tls: true"},
	{"bad-pbk", `
  - name: bad-pbk
    type: vless
    server: 192.0.2.10
    port: 443
    uuid: ` + testUUID + `
    tls: true
    reality-opts:
      public-key: ` + testSecret, "публичный ключ REALITY"},
	{"shadow-tls", `
  - name: shadow-tls
    type: vless
    server: 192.0.2.10
    port: 443
    uuid: ` + testUUID + `
    tls: true
    shadow-tls-opts:
      version: 3
      password: ` + testSecret, "ShadowTLS (shadow-tls-opts)"},
	{"restls", `
  - name: restls
    type: anytls
    server: 192.0.2.62
    port: 443
    password: pw
    restls-opts: {password: ` + testSecret + `, version-hint: tls13}`, "Restls (restls-opts)"},
	{"client-cert", `
  - name: client-cert
    type: trojan
    server: 192.0.2.30
    port: 443
    password: pw
    certificate: ./client.crt
    private-key: ./` + testSecret + `.key`, "клиентский сертификат"},
	{"ech", `
  - name: ech
    type: hysteria2
    server: 192.0.2.50
    port: 443
    password: pw
    ech-opts:
      enable: true
      config: ` + testSecret, "ECH (ech-opts)"},
	{"pin-insecure", `
  - name: pin-insecure
    type: vless
    server: 192.0.2.10
    port: 443
    uuid: ` + testUUID + `
    tls: true
    skip-cert-verify: true
    fingerprint: ` + testSecret, "закрепление сертификата"},
	{"pin-list-insecure", `
  - name: pin-list-insecure
    type: trojan
    server: 192.0.2.30
    port: 443
    password: pw
    skip-cert-verify: true
    pin-sha256: [` + testSecret + `]`, "закрепление сертификата"},
	{"name-cert-other", `
  - name: name-cert-other
    type: tuic
    server: 192.0.2.60
    port: 443
    uuid: ` + testUUID + `
    password: pw
    sni: decoy.example
    name-cert-verify: real.example`, "по другому имени"},
	{"h2c", `
  - name: h2c
    type: vmess
    server: 192.0.2.20
    port: 80
    uuid: ` + testUUID + `
    alterId: 0
    cipher: auto
    network: h2`, "h2 без TLS"},
	{"http-header-tls", `
  - name: http-header-tls
    type: vless
    server: 192.0.2.10
    port: 443
    uuid: ` + testUUID + `
    tls: true
    network: http`, "HTTP-маскировкой"},
	{"grpc-custom-path", `
  - name: grpc-custom-path
    type: vless
    server: 192.0.2.10
    port: 443
    uuid: ` + testUUID + `
    tls: true
    network: grpc
    grpc-opts: {grpc-service-name: /a/b}`, "собственный путь gRPC"},
	{"flow-direct", `
  - name: flow-direct
    type: vless
    server: 192.0.2.10
    port: 443
    uuid: ` + testUUID + `
    tls: true
    flow: xtls-rprx-direct`, "flow «xtls-rprx-direct»"},
	{"vmess-cipher", `
  - name: vmess-cipher
    type: vmess
    server: 192.0.2.20
    port: 443
    uuid: ` + testUUID + `
    alterId: 0
    cipher: aes-128-ctr`, "шифрование VMess «aes-128-ctr»"},
	{"trojan-ss-opts", `
  - name: trojan-ss-opts
    type: trojan
    server: 192.0.2.30
    port: 443
    password: pw
    ss-opts:
      enabled: true
      method: aes-128-gcm
      password: ` + testSecret, "ss-opts"},
	{"ss-shadow-tls", `
  - name: ss-shadow-tls
    type: ss
    server: 192.0.2.40
    port: 443
    cipher: chacha20-ietf-poly1305
    password: pw
    plugin: shadow-tls
    plugin-opts:
      host: cloud.example.com
      password: ` + testSecret + `
      version: 2`, "плагин «shadow-tls»"},
	{"ss-kcptun", `
  - name: ss-kcptun
    type: ss
    server: 192.0.2.40
    port: 443
    cipher: chacha20-ietf-poly1305
    password: pw
    plugin: kcptun
    plugin-opts: {key: ` + testSecret + `}`, "плагин «kcptun»"},
	{"ss-v2ray-insecure", `
  - name: ss-v2ray-insecure
    type: ss
    server: 192.0.2.40
    port: 443
    cipher: chacha20-ietf-poly1305
    password: pw
    plugin: v2ray-plugin
    plugin-opts: {mode: websocket, tls: true, skip-cert-verify: true}`, "skip-cert-verify"},
	{"ss-v2ray-quic", `
  - name: ss-v2ray-quic
    type: ss
    server: 192.0.2.40
    port: 443
    cipher: chacha20-ietf-poly1305
    password: pw
    plugin: v2ray-plugin
    plugin-opts: {mode: quic}`, "QUIC"},
	{"ss-v2ray-upgrade", `
  - name: ss-v2ray-upgrade
    type: ss
    server: 192.0.2.40
    port: 443
    cipher: chacha20-ietf-poly1305
    password: pw
    plugin: v2ray-plugin
    plugin-opts: {mode: websocket, v2ray-http-upgrade: true}`, "v2ray-http-upgrade"},
	{"ss-obfs-no-mode", `
  - name: ss-obfs-no-mode
    type: ss
    server: 192.0.2.40
    port: 443
    cipher: chacha20-ietf-poly1305
    password: pw
    plugin: obfs`, "режим obfs"},
	{"ss-tls", `
  - name: ss-tls
    type: ss
    server: 192.0.2.40
    port: 443
    cipher: chacha20-ietf-poly1305
    password: ` + testSecret + `
    tls: true`, "режим защиты «tls» для Shadowsocks"},
	{"ss-cipher", `
  - name: ss-cipher
    type: ss
    server: 192.0.2.40
    port: 443
    cipher: aes-128-ccm
    password: ` + testSecret, "метод шифрования"},
	// mihomo knows versions 1 and 2 and refuses the node otherwise
	{"ss-uot-version", `
  - name: ss-uot-version
    type: ss
    server: 192.0.2.40
    port: 8388
    cipher: aes-256-gcm
    password: ` + testSecret + `
    udp-over-tcp: true
    udp-over-tcp-version: 3`, "udp-over-tcp-version"},
	{"ss-no-password", `
  - name: ss-no-password
    type: ss
    server: 192.0.2.40
    port: 443
    cipher: aes-256-gcm`, "не указан пароль"},
	{"hy2-realm", `
  - name: hy2-realm
    type: hysteria2
    server: 192.0.2.50
    port: 443
    password: pw
    realm-opts:
      enable: true
      token: ` + testSecret, "realm"},
	{"hy2-obfs-nopw", `
  - name: hy2-obfs-nopw
    type: hysteria2
    server: 192.0.2.50
    port: 443
    password: pw
    obfs: salamander`, "obfs-password"},
	{"hy2-bad-ports", `
  - name: hy2-bad-ports
    type: hysteria2
    server: 192.0.2.50
    port: 443
    ports: 30000-20000
    password: pw`, "список портов"},
	{"hy1-faketcp", `
  - name: hy1-faketcp
    type: hysteria
    server: 192.0.2.70
    port: 443
    protocol: faketcp
    up: 10
    down: 10`, "faketcp"},
	{"hy1-no-speed", `
  - name: hy1-no-speed
    type: hysteria
    server: 192.0.2.70
    port: 443
    auth-str: ` + testSecret, "скорость канала"},
	{"hy1-auth", `
  - name: hy1-auth
    type: hysteria
    server: 192.0.2.70
    port: 443
    auth: "` + testSecret + `!"
    up: 10
    down: 10`, "«auth»"},
	{"tuic-v4", `
  - name: tuic-v4
    server: 192.0.2.60
    port: 10443
    type: tuic
    token: ` + testSecret + `
    uuid: ` + testUUID + `
    password: pw`, "TUIC v4"},
	{"tuic-no-password", `
  - name: tuic-no-password
    server: 192.0.2.60
    port: 10443
    type: tuic
    uuid: ` + testUUID, "не указан пароль"},
	{"socks-tls", `
  - name: socks-tls
    type: socks5
    server: 192.0.2.80
    port: 443
    tls: true`, "SOCKS поверх TLS"},
	{"wg", `
  - name: wg
    type: wireguard
    server: 192.0.2.90
    port: 51820
    private-key: ` + testSecret, "WireGuard"},
	{"ssr", `
  - name: ssr
    type: ssr
    server: 192.0.2.91
    port: 443
    cipher: chacha20-ietf
    password: ` + testSecret, "ShadowsocksR"},
	{"http", `
  - name: http
    type: http
    server: 192.0.2.92
    port: 443
    password: ` + testSecret, "HTTP-прокси"},
	{"snell", `
  - name: snell
    type: snell
    server: 192.0.2.93
    port: 44046
    psk: ` + testSecret, "тип «snell»"},
	{"узел 2", `
  - type: trojan
    server: 192.0.2.30
    port: 443
    password: ` + testSecret, "нет имени (name)"},
	{"no-type", `
  - name: no-type
    server: 192.0.2.30
    port: 443`, "не указан тип (type)"},
	{"no-server", `
  - name: no-server
    type: trojan
    port: 443
    password: ` + testSecret, "не указан адрес сервера"},
	{"bad-server", `
  - name: bad-server
    type: trojan
    server: "evil.example/x?security=none#"
    port: 443
    password: ` + testSecret, "неверный адрес сервера"},
	{"bad-port", `
  - name: bad-port
    type: trojan
    server: 192.0.2.30
    port: 70000
    password: ` + testSecret, "неверный порт (port)"},
	{"no-port", `
  - name: no-port
    type: vless
    server: 192.0.2.10
    uuid: ` + testUUID, "не указан порт"},
	{"list-port", `
  - name: list-port
    type: trojan
    server: 192.0.2.30
    port: [443]
    password: ` + testSecret, "поле «port» повреждено"},
	{"bad-opts", `
  - name: bad-opts
    type: vless
    server: 192.0.2.10
    port: 443
    uuid: ` + testUUID + `
    network: ws
    ws-opts: /ws`, "поле «ws-opts» повреждено"},
	{"bad-flag", `
  - name: bad-flag
    type: vless
    server: 192.0.2.10
    port: 443
    uuid: ` + testUUID + `
    tls: maybe`, "поле «tls» повреждено"},
	// mihomo's decoder takes one of them by chance
	{"twice", `
  - name: twice
    type: trojan
    server: 192.0.2.30
    port: 443
    password: ` + testSecret + `
    skip-cert-verify: false
    Skip_Cert_Verify: true`, "«skip-cert-verify» указан в узле дважды"},
	{"no-uuid", `
  - name: no-uuid
    type: vless
    server: 192.0.2.10
    port: 443`, "не указан uuid"},
}

func TestClashRefused(t *testing.T) {
	ok := `
  - name: ok
    type: trojan
    server: 192.0.2.31
    port: 443
    password: pw`
	for _, c := range refusedClash {
		t.Run(c.name, func(t *testing.T) {
			outbounds, skipped, err := ParseAllReport(clashProxyList(ok, c.entry))
			if err != nil {
				t.Fatalf("ParseAllReport: %v", err)
			}
			if len(outbounds) != 1 || outbounds[0].Tag() != "ok" {
				t.Errorf("imported %v", outbounds)
			}
			if len(skipped) != 1 || skipped[0].Name != c.name || !strings.Contains(skipped[0].Reason, c.reason) {
				t.Fatalf("skipped = %+v, want %q: %q", skipped, c.name, c.reason)
			}
			reason := skipped[0].Reason
			if !russian(reason) || strings.Contains(reason, testSecret) || strings.Contains(reason, testUUID) {
				t.Errorf("reason %q", reason)
			}
		})
	}
}

func TestClashProfileShapes(t *testing.T) {
	entry := `
  - name: DE
    type: trojan
    server: 192.0.2.30
    port: 443
    password: pw`
	imported := []string{
		clashProxyList(entry),
		b64(clashProxyList(entry)),
		// JSON is YAML too
		`{"proxies": [{"name": "DE", "type": "trojan", "server": "192.0.2.30", "port": 443, "password": "pw"}]}`,
		// A link in a comment or a name is no node of the profile
		"# from trojan://other@192.0.2.99:443#other\n" + clashProxyList(entry),
		// Clash's plumbing among the proxies
		clashProxyList("  - {name: dns-out, type: dns}\n  - {name: en1, type: direct}", entry),
	}
	for _, text := range imported {
		outbounds, skipped, err := ParseAllReport(text)
		if err != nil || len(outbounds) != 1 || outbounds[0].Tag() != "DE" || len(skipped) != 0 {
			t.Errorf("%.50q: %v, %+v, %v", text, outbounds, skipped, err)
		}
	}

	refused := []struct {
		text string
		want error
	}{
		{"mixed-port: 7890\nproxies:\n  - name: DE\n   type: trojan\n", errClashBroken},
		{"proxies:\nproxy-providers:\n  sub:\n    type: http\n    url: https://example.com/" + testSecret + "\n", errClashProviders},
		{"proxies: []\nrules: [MATCH,DIRECT]\n", errEmptyProfile},
		{clashProxyList("  - {name: dns-out, type: dns}"), errEmptyProfile},
		{"proxies: {name: DE}\n", errClashBroken},
		{"proxies: []\nproxies: []\n", errClashBroken},
	}
	for _, c := range refused {
		_, _, err := ParseAllReport(c.text)
		if !errors.Is(err, c.want) || !russian(err.Error()) || strings.Contains(err.Error(), testSecret) {
			t.Errorf("%.50q: error %v, want %v", c.text, err, c.want)
		}
	}
	// The parser's message may quote the text: only the line is passed on
	for _, text := range []string{
		"proxies:\n  - name: \"" + testSecret + "\n    type: [trojan\n",
		"proxies:\n  - name: x\n    password: *" + testSecret + "\n",
	} {
		_, _, err := ParseAllReport(text)
		if !errors.Is(err, errClashBroken) || strings.Contains(err.Error(), testSecret) {
			t.Errorf("broken YAML: %v", err)
		}
	}

	// No Clash profile: read as before
	if _, _, err := ParseAllReport("proxies are not here"); !errors.Is(err, errNoLinks) {
		t.Errorf("plain text: %v", err)
	}
	if outbounds, err := ParseAll("trojan://pw@192.0.2.30:443#proxies"); err != nil || len(outbounds) != 1 {
		t.Errorf("a link named proxies: %v, %v", outbounds, err)
	}
	if outbounds, err := ParseAll("proxies: 2\ntrojan://pw@192.0.2.30:443#a\ntrojan://pw@192.0.2.31:443#b\n"); err != nil || len(outbounds) != 2 {
		t.Errorf("links under a proxies: line: %v, %v", outbounds, err)
	}
	// Links that YAML reads, as a list or as one text: no node entry (a
	// mapping) among them, so no profile
	for _, text := range []string{
		"proxies:\n- trojan://pw@192.0.2.30:443#a\n- trojan://pw@192.0.2.31:443#b\n",
		"proxies:\n  trojan://pw@192.0.2.30:443#a\n  trojan://pw@192.0.2.31:443#b\n",
		"proxies: trojan://pw@192.0.2.30:443#a trojan://pw@192.0.2.31:443#b\n",
	} {
		if imported, skipped, err := parseQuickly(t, text); err != nil || strings.Join(imported, ",") != "a,b" || len(skipped) != 0 {
			t.Errorf("%q: imported %q, skipped %q, error %v", text, imported, skipped, err)
		}
	}
	// A profile with an entry stays one: a link among its entries is none
	imported, skipped, err := parseQuickly(t, "proxies:\n  - trojan://pw@192.0.2.30:443#a"+entry)
	if err != nil || strings.Join(imported, ",") != "DE" || strings.Join(skipped, ",") != "узел 1: запись узла повреждена" {
		t.Errorf("a link among the entries: imported %q, skipped %q, error %v", imported, skipped, err)
	}
	imported, skipped, err = parseQuickly(t, "# trojan://other@192.0.2.99:443#other\n"+
		"x-de: &de {name: DE, type: trojan, server: 192.0.2.30, port: 443, password: pw}\nproxies:\n  - *de\n")
	if err != nil || strings.Join(imported, ",") != "DE" || len(skipped) != 0 {
		t.Errorf("an aliased entry: imported %q, skipped %q, error %v", imported, skipped, err)
	}
}

// proxy-providers: the nodes of an inline list (payload) are entries of the
// profile, with what the list sets for them applied as mihomo applies it; a
// list to download (http, file) is not followed, and a profile of nothing
// else gets the hint
func TestClashProviders(t *testing.T) {
	entry := func(name, server string) string {
		return "{name: " + name + ", type: trojan, server: " + server + ", port: 443, password: pw}"
	}
	for _, text := range []string{
		"proxy-providers:\n  sub:\n    type: http\n    url: https://example.com/" + testSecret + "\n" +
			"proxy-groups:\n  - {name: PROXY, type: select, use: [sub]}\n",
		"proxy-providers:\n  local: {type: file, path: ./nodes.yaml}\n",
		"proxies: []\nproxy-providers:\n  sub: {type: http, url: https://example.com/x, payload: [" + entry("fallback", "192.0.2.30") + "]}\n",
	} {
		if imported, skipped, err := parseQuickly(t, text); !errors.Is(err, errClashProviders) || strings.Contains(err.Error(), testSecret) {
			t.Errorf("%.40q: imported %q, skipped %q, error %v", text, imported, skipped, err)
		}
	}

	imported, skipped, err := parseQuickly(t, "proxies:\n  - "+entry("C", "192.0.2.30")+"\n"+
		"proxy-providers:\n  sub: {type: http, url: https://example.com/"+testSecret+"}\n"+
		"  own:\n    type: inline\n    payload:\n      - "+entry("A", "192.0.2.31")+"\n      - "+entry("B", "192.0.2.32")+"\n")
	if err != nil || strings.Join(imported, ",") != "C,A,B" || len(skipped) != 1 || !strings.HasPrefix(skipped[0], "sub: ") ||
		!strings.Contains(skipped[0], "proxy-providers") || strings.Contains(skipped[0], testSecret) {
		t.Errorf("inline beside proxies: imported %q, skipped %q, error %v", imported, skipped, err)
	}
	if imported, skipped, err := parseQuickly(t, "proxy-providers:\n  own: {type: inline, payload: ["+entry("A", "192.0.2.31")+"]}\n"); err != nil ||
		strings.Join(imported, ",") != "A" || len(skipped) != 0 {
		t.Errorf("inline only: imported %q, skipped %q, error %v", imported, skipped, err)
	}

	// What the list sets: its dialer-proxy (over the node's own), then the
	// override (its dialer-proxy over the list's), the prefix and suffix of
	// the names; exclude-type leaves nodes out, and so does a repeated name
	outbounds, sk, err := ParseAllReport("proxies:\n  - " + entry("relay", "192.0.2.40") + "\n  - " + entry("relay2", "192.0.2.41") + "\n" +
		"proxy-providers:\n" +
		"  own:\n    type: inline\n    dialer-proxy: relay\n    exclude-type: ss|VMESS\n" +
		"    override: {skip-cert-verify: true, additional-prefix: '[own] ', additional-suffix: ' *'}\n" +
		"    payload:\n" +
		"      - " + entry("A", "192.0.2.42") + "\n" +
		"      - {name: S, type: ss, server: 192.0.2.43, port: 8388, cipher: aes-128-gcm, password: pw}\n" +
		"      - {name: V, type: vmess, server: 192.0.2.44, port: 443, uuid: " + testUUID + ", cipher: auto}\n" +
		"      - " + entry("A", "192.0.2.45") + "\n" +
		"      - {name: B, type: trojan, server: 192.0.2.46, port: 443, password: pw, dialer-proxy: other}\n" +
		"  two: {type: inline, dialer-proxy: relay, override: {dialer-proxy: relay2}, payload: [" + entry("D", "192.0.2.47") + "]}\n")
	if err != nil || len(sk) != 0 || len(outbounds) != 5 {
		t.Fatalf("imported %v, skipped %+v, error %v", outbounds, sk, err)
	}
	byTag := map[string]Outbound{}
	for _, o := range outbounds {
		byTag[o.Tag()] = o
	}
	checkOutbound(t, byTag["[own] A *"], `{"server":"192.0.2.42","detour":"relay","tls":{"insecure":true}}`)
	checkOutbound(t, byTag["[own] B *"], `{"detour":"relay","tls":{"insecure":true}}`)
	checkOutbound(t, byTag["D"], `{"detour":"relay2","tls":{"insecure":null}}`)

	// What the app cannot repeat (mihomo's regular expressions and
	// expressions): the list is left out, with the reason
	imported, skipped, err = parseQuickly(t, "proxies:\n  - "+entry("C", "192.0.2.30")+"\n"+
		"proxy-providers:\n"+
		"  f: {type: inline, filter: 'HK|SG', payload: ["+entry("A", "192.0.2.31")+"]}\n"+
		"  x: {type: inline, override: {proxy-name: [{pattern: A, target: Z}]}, payload: ["+entry("B", "192.0.2.32")+"]}\n"+
		"  bad: {type: inline, payload: {name: E}}\n")
	if err != nil || strings.Join(imported, ",") != "C" || len(skipped) != 3 || !strings.Contains(skipped[0], "(filter)") ||
		!strings.Contains(skipped[1], "(override.proxy-name)") || skipped[2] != "bad: поле «payload» повреждено" {
		t.Errorf("refused lists: imported %q, skipped %q, error %v", imported, skipped, err)
	}
}

// dialer-proxy is a detour: kept when it names another imported node, the
// node left out when it names a group or a node that is not imported
func TestClashDialerProxy(t *testing.T) {
	text := clashProxyList(`
  - name: relay
    type: ss
    server: 192.0.2.40
    port: 8388
    cipher: aes-256-gcm
    password: pw
  - name: chained
    type: trojan
    server: 192.0.2.30
    port: 443
    password: pw
    dialer-proxy: relay
  - name: via-direct
    type: trojan
    server: 192.0.2.31
    port: 443
    password: pw
    dialer-proxy: DIRECT
  - name: via-group
    type: trojan
    server: 192.0.2.32
    port: 443
    password: pw
    dialer-proxy: PROXY
  - name: ring-a
    type: trojan
    server: 192.0.2.33
    port: 443
    password: pw
    dialer-proxy: ring-b
  - name: ring-b
    type: trojan
    server: 192.0.2.34
    port: 443
    password: pw
    dialer-proxy: ring-a`)
	outbounds, skipped, err := ParseAllReport(text)
	if err != nil {
		t.Fatalf("ParseAllReport: %v", err)
	}
	byTag := map[string]Outbound{}
	for _, o := range outbounds {
		byTag[o.Tag()] = o
	}
	if len(outbounds) != 3 || byTag["relay"] == nil {
		t.Fatalf("imported %v", outbounds)
	}
	checkOutbound(t, byTag["chained"], `{"detour":"relay"}`)
	checkOutbound(t, byTag["via-direct"], `{"detour":null}`)
	reasons := map[string]string{}
	for _, sk := range skipped {
		reasons[sk.Name] = sk.Reason
	}
	if len(skipped) != 3 || !strings.Contains(reasons["via-group"], "«PROXY»") ||
		!strings.Contains(reasons["ring-a"], "кольцо") || !strings.Contains(reasons["ring-b"], "кольцо") {
		t.Fatalf("skipped = %+v", skipped)
	}
}

// Values go into the links escaped: a credential with the characters of a
// URL stays itself, and no value adds a parameter to its link (an sni
// spelling out security=none leaves the TLS on)
func TestClashValuesStayValues(t *testing.T) {
	pw := `p@ss:w/r?d#1&x=y+z %41`
	q := strconv.Quote(pw) // a YAML double-quoted scalar too
	text := clashProxyList(
		"  - {name: trojan, type: trojan, server: 192.0.2.30, port: 443, password: "+q+`, sni: "a.example&security=none#x"}`,
		"  - {name: hy2, type: hysteria2, server: 192.0.2.50, port: 443, password: "+q+"}",
		"  - {name: tuic, type: tuic, server: 192.0.2.60, port: 443, uuid: "+testUUID+", password: "+q+"}",
		"  - {name: ss, type: ss, server: 192.0.2.40, port: 8388, cipher: aes-256-gcm, password: "+q+"}",
		"  - {name: anytls, type: anytls, server: 192.0.2.62, port: 443, password: "+q+"}",
		"  - {name: socks, type: socks5, server: 192.0.2.80, port: 1080, username: "+q+", password: "+q+"}",
		"  - {name: hy1, type: hysteria, server: 192.0.2.70, port: 443, auth-str: "+q+", up: 10, down: 10}",
		`  - {name: "DE #1 & co?", type: trojan, server: 192.0.2.31, port: 443, password: pw}`,
	)
	outbounds, skipped, err := ParseAllReport(text)
	if err != nil || len(outbounds) != 8 || len(skipped) != 0 {
		t.Fatalf("got %v, %+v, %v", outbounds, skipped, err)
	}
	for _, o := range outbounds[:6] {
		if o["password"] != pw {
			t.Errorf("%s: password %q", o.Tag(), o["password"])
		}
	}
	checkOutbound(t, outbounds[0], `{"tls":{"enabled":true,"server_name":"a.example&security=none#x"}}`)
	if outbounds[5]["username"] != pw || outbounds[6]["auth_str"] != pw || outbounds[7].Tag() != "DE #1 & co?" {
		t.Errorf("socks %v, hysteria %v, tag %q", outbounds[5], outbounds[6], outbounds[7].Tag())
	}
}

// A value tagged !!binary is base64 to YAML, and mihomo connects with what
// it decodes to: so does the node. One that is no base64, or does not come
// to text, is a malformed field.
func TestClashBinaryValues(t *testing.T) {
	text := clashProxyList(
		"  - {name: !!binary REU=, type: trojan, server: 192.0.2.30, port: 443, password: !!binary aGVsbG8=}",
		// Line breaks are no part of the base64
		"  - name: NL\n    type: trojan\n    server: 192.0.2.31\n    port: !!binary NDQz\n    password: !!binary |\n      aGVs\n      bG8=",
		"  - {!!binary c2VydmVy: 192.0.2.32, name: key, type: trojan, port: 443, password: pw}",
		"  - {name: bad, type: trojan, server: 192.0.2.33, port: 443, password: !!binary not-base64}",
		"  - {name: latin1, type: trojan, server: 192.0.2.34, port: 443, password: !!binary 6Q==}",
		"  - {!<tag:yaml.org,2002:binary> bmFtZQ==: long, type: trojan, server: 192.0.2.35, port: 443, password: !!binary 6Q==}",
		"  - {name: !!binary Rkk=, type: trojan, Type: trojan}",
	)
	imported, skipped, err := parseQuickly(t, text)
	if err != nil || strings.Join(imported, ",") != "DE,NL,key" {
		t.Fatalf("imported %q, skipped %q, error %v", imported, skipped, err)
	}
	want := []string{"bad: поле «password» повреждено", "latin1: поле «password» повреждено", "long: поле «password» повреждено",
		"FI: параметр «type» указан в узле дважды"}
	if strings.Join(skipped, "|") != strings.Join(want, "|") {
		t.Errorf("skipped %q", skipped)
	}
	outbounds, _, _ := ParseAllReport(text)
	for _, o := range outbounds[:2] {
		if o["password"] != "hello" || o["server_port"] != 443 {
			t.Errorf("%s: password %q, port %v", o.Tag(), o["password"], o["server_port"])
		}
	}
	if outbounds[2]["server"] != "192.0.2.32" {
		t.Errorf("server %v", outbounds[2]["server"])
	}
}

// Repeated names get a suffix, as the nodes of any import
func TestClashRepeatedNames(t *testing.T) {
	entry := "  - {name: DE, type: trojan, server: 192.0.2.30, port: 443, password: pw}"
	outbounds, _, err := ParseAllReport(clashProxyList(entry, entry))
	if err != nil || len(outbounds) != 2 || outbounds[0].Tag() != "DE" || outbounds[1].Tag() != "DE (2)" {
		t.Fatalf("got %v, %v", outbounds, err)
	}
}

// parseQuickly is ParseAllReport with the skipped nodes as "name: reason",
// failing the test when it takes long: an expanded alias costs minutes and
// gigabytes
func parseQuickly(t *testing.T, text string) (imported, skipped []string, err error) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		var outbounds []Outbound
		var sk []domain.SkippedNode
		outbounds, sk, err = ParseAllReport(text)
		for _, o := range outbounds {
			imported = append(imported, o.Tag())
		}
		for _, s := range sk {
			skipped = append(skipped, s.Name+": "+s.Reason)
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the aliases were expanded")
	}
	return imported, skipped, err
}

// Anchors: a few lines can stand for a value far larger than the text. Such
// a profile is refused as a whole, as mihomo refuses it, instead of being
// expanded; an alias pointing back into its own anchor is refused instead of
// followed forever
func TestClashAnchors(t *testing.T) {
	// a30 stands for 10^31 scalars
	var b strings.Builder
	b.WriteString("bomb:\n  - &a0 [x, x, x, x, x, x, x, x, x, x]\n")
	for i := 1; i <= 30; i++ {
		prev := "*a" + strconv.Itoa(i-1)
		fmt.Fprintf(&b, "  - &a%d [%s%s]\n", i, strings.Repeat(prev+", ", 9), prev)
	}
	ok := `
  - name: ok
    type: trojan
    server: 192.0.2.32
    port: 443
    password: pw`
	b.WriteString(clashProxyList(`
  - name: bomb
    type: trojan
    server: 192.0.2.30
    port: 443
    password: pw
    ws-opts: {headers: {x: *a30}}
    alpn: *a30`, ok))
	if imported, skipped, err := parseQuickly(t, b.String()); !errors.Is(err, errClashBroken) || imported != nil || skipped != nil {
		t.Fatalf("bomb: imported %q, skipped %q, error %v", imported, skipped, err)
	}

	imported, skipped, err := parseQuickly(t, clashProxyList(`
  - name: cycle
    type: trojan
    server: 192.0.2.31
    port: 443
    password: pw
    extra: &self {inner: *self}`, ok))
	if err != nil || strings.Join(imported, ",") != "ok" || len(skipped) != 1 || skipped[0] != "cycle: запись узла повреждена" {
		t.Fatalf("cycle: imported %q, skipped %q, error %v", imported, skipped, err)
	}
}

// Aliases and merge keys may not make the entries much larger than the
// text: each repetition is translated again (a link, an outbound), and a
// merge copies the fields. Within the 8 MB of a subscription body such a
// profile grows into gigabytes, and the app does not survive running out of
// memory. A profile that merges a common block into its entries is imported.
func TestClashAliasExpansion(t *testing.T) {
	var merged strings.Builder // every entry merges a mapping of 2000 keys
	merged.WriteString("x-base: &b {")
	for i := range 2000 {
		fmt.Fprintf(&merged, "k%d: %d, ", i, i)
	}
	merged.WriteString("type: trojan}\nproxies:\n")
	for range 2000 {
		merged.WriteString("  - <<: *b\n")
	}

	var chain strings.Builder // each level merges the one before it
	chain.WriteString("x0: &l0 {type: trojan}\n")
	for i := 1; i <= 2000; i++ {
		fmt.Fprintf(&chain, "x%d: &l%d {<<: *l%d, k%d: %d}\n", i, i, i-1, i, i)
	}
	chain.WriteString("proxies:\n")
	// One entry of 2000 keys, two million copied by the merges
	chainEntry := chain.String() + "  - {<<: *l2000, name: x, server: 192.0.2.30, port: 443, password: pw}\n"
	for i := 0; i <= 2000; i++ {
		fmt.Fprintf(&chain, "  - *l%d\n", i)
	}
	chainEntries := chain.String()

	password := strings.Repeat("a", 256<<10)
	var repeated strings.Builder // one node of 256 KB, repeated
	repeated.WriteString("proxies:\n  - &n {name: x, type: ss, server: 192.0.2.40, port: 8388, cipher: aes-128-gcm, password: " + password + "}\n")
	repeated.WriteString(strings.Repeat("  - *n\n", 100))

	var field strings.Builder // a password of 256 KB in every node
	field.WriteString("x-pw: &pw " + password + "\nproxies:\n")
	for i := range 100 {
		fmt.Fprintf(&field, "  - {name: n%d, type: ss, server: 192.0.2.40, port: 8388, cipher: aes-128-gcm, password: *pw}\n", i)
	}

	for name, text := range map[string]string{
		"merge": merged.String(), "merge chain": chainEntries, "merged chain": chainEntry,
		"alias": repeated.String(), "aliased field": field.String(),
	} {
		imported, skipped, err := parseQuickly(t, text)
		if !errors.Is(err, errClashBroken) || !russian(err.Error()) || len(imported) != 0 || len(skipped) != 0 {
			t.Errorf("%s: imported %d, skipped %d, error %v", name, len(imported), len(skipped), err)
		}
	}

	// An inline list repeated by aliases: its nodes are charged as each copy
	// of the list is read, before the copies come to gigabytes
	var lists strings.Builder
	lists.WriteString("x-list: &p\n  type: inline\n  override: {additional-prefix: '* '}\n  payload:\n")
	for i := range 200 {
		fmt.Fprintf(&lists, "    - {name: n%d, type: trojan, server: 192.0.2.30, port: 443, password: pw}\n", i)
	}
	lists.WriteString("proxy-providers:\n")
	for i := range 5000 {
		fmt.Fprintf(&lists, "  p%d: *p\n", i)
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	if _, _, err := parseQuickly(t, lists.String()); !errors.Is(err, errClashBroken) {
		t.Errorf("aliased lists: error %v", err)
	}
	if runtime.ReadMemStats(&after); after.TotalAlloc-before.TotalAlloc > 200<<20 {
		t.Errorf("aliased lists: %d MB allocated", (after.TotalAlloc-before.TotalAlloc)>>20)
	}

	var common strings.Builder
	common.WriteString("x-common: &c {type: trojan, port: 443, password: pw, sni: example.com, udp: true, " +
		"skip-cert-verify: false, client-fingerprint: chrome, network: tcp}\nproxies:\n")
	for i := range 3000 {
		fmt.Fprintf(&common, "  - {<<: *c, name: n%d, server: 192.0.2.%d}\n", i, i%250+1)
	}
	imported, skipped, err := parseQuickly(t, common.String())
	if err != nil || len(imported) != 3000 || len(skipped) != 0 {
		t.Fatalf("common block: imported %d, skipped %q, error %v", len(imported), skipped, err)
	}
}
