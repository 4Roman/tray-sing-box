package sharelink

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"unicode"
)

// Test values: documentation addresses, a fake uuid, a REALITY public key
// (any 32 bytes are a valid X25519 public key)
const (
	testUUID = "11111111-2222-4333-8444-555555555555"
	testPBK  = "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0"
	// testSecret marks the credentials of the refused samples: it must never
	// come back in an error or a skip reason
	testSecret = "S3cretMark"
)

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func vmessJSON(payload string) string { return "vmess://" + b64(payload) }

// linkCase is a link that must be converted; want is a JSON subset of the
// outbound (null: the key must be absent)
type linkCase struct {
	name, link, want string
}

var acceptedLinks = []linkCase{
	// REALITY always gets uTLS (sing-box refuses it without), chrome when fp
	// is missing or empty
	{"reality without fp",
		"vless://" + testUUID + "@192.0.2.10:443?type=tcp&security=reality&sni=www.example.com&pbk=" + testPBK + "&sid=6ba85179&flow=xtls-rprx-vision&encryption=none#DE",
		`{"type":"vless","tag":"DE","server":"192.0.2.10","server_port":443,"uuid":"` + testUUID + `","flow":"xtls-rprx-vision","transport":null,
		  "tls":{"enabled":true,"server_name":"www.example.com","utls":{"enabled":true,"fingerprint":"chrome"},
		         "reality":{"enabled":true,"public_key":"` + testPBK + `","short_id":"6ba85179"}}}`},
	{"reality with empty fp",
		"vless://" + testUUID + "@192.0.2.10:443?type=tcp&security=reality&sni=www.example.com&fp=&pbk=" + testPBK + "&sid=6ba85179&flow=xtls-rprx-vision&encryption=none#DE-empty-fp",
		`{"tls":{"utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true}}}`},
	{"reality with fp=unsafe still gets uTLS",
		"vless://" + testUUID + "@192.0.2.10:443?security=reality&sni=www.example.com&fp=unsafe&pbk=" + testPBK + "#DE-unsafe",
		`{"tls":{"utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"short_id":null}}}`},
	{"reality key in padded standard base64 is normalized",
		"vless://" + testUUID + "@192.0.2.10:443?security=reality&sni=www.example.com&pbk=" +
			url.QueryEscape(base64.StdEncoding.EncodeToString(mustDecode(testPBK))) + "&sid=0123456789abcdef#DE-std-key",
		`{"tls":{"reality":{"public_key":"` + testPBK + `","short_id":"0123456789abcdef"}}}`},
	{"reality over grpc",
		"vless://" + testUUID + "@192.0.2.10:443?type=grpc&serviceName=svc&security=reality&sni=www.example.com&fp=firefox&pbk=" + testPBK + "#DE-grpc",
		`{"transport":{"type":"grpc","service_name":"svc"},"tls":{"utls":{"fingerprint":"firefox"}}}`},

	// Fingerprints outside sing-box's list are mapped
	{"fp randomizednoalpn",
		"vless://" + testUUID + "@192.0.2.10:443?type=ws&path=%2Fws&host=example.com&security=tls&sni=example.com&fp=randomizednoalpn#ws-node",
		`{"tls":{"enabled":true,"server_name":"example.com","utls":{"enabled":true,"fingerprint":"randomized"}},
		  "transport":{"type":"ws","path":"/ws","headers":{"Host":"example.com"}}}`},
	{"fp unsafe on TLS means no uTLS",
		"vless://" + testUUID + "@192.0.2.10:443?security=tls&sni=example.com&fp=unsafe#tls-unsafe",
		`{"tls":{"enabled":true,"utls":null}}`},
	{"fp none on TLS means no uTLS",
		"vless://" + testUUID + "@192.0.2.10:443?security=tls&sni=example.com&fp=none#tls-none",
		`{"tls":{"utls":null}}`},
	{"TLS without fp defaults to chrome",
		"vless://" + testUUID + "@192.0.2.10:443?security=tls&sni=example.com#tls-default",
		`{"tls":{"utls":{"enabled":true,"fingerprint":"chrome"}}}`},
	{"fp in Xray's hello form",
		"vless://" + testUUID + "@192.0.2.10:443?security=tls&sni=example.com&fp=HelloIOS_Auto#tls-hello",
		`{"tls":{"utls":{"fingerprint":"ios"}}}`},

	// Transports: raw/tcp stay transport-less, TCP's http header without TLS
	// is sing-box's http transport with GET
	{"type raw",
		"vless://" + testUUID + "@192.0.2.10:443?type=raw&security=tls&sni=example.com#raw",
		`{"transport":null}`},
	{"tcp with the http header, no TLS",
		"vless://" + testUUID + "@192.0.2.10:80?type=tcp&headerType=http&host=a.example.com%2Cb.example.com&path=%2Findex%2C%2Falt&security=none#tcp-http",
		`{"tls":null,"transport":{"type":"http","method":"GET","path":"/index","host":["a.example.com","b.example.com"]}}`},
	{"trojan without TLS and the http header",
		"trojan://pw@192.0.2.30:80?security=none&type=tcp&headerType=http#trojan-tcp-http",
		`{"tls":null,"transport":{"type":"http","method":"GET","path":null,"host":null}}`},
	{"vmess tcp with the http header (the JSON's type field)",
		vmessJSON(`{"v":"2","ps":"vm-tcp-http","add":"192.0.2.20","port":"80","id":"` + testUUID + `","aid":"0","scy":"auto","net":"tcp","type":"http","host":"example.com","path":"/","tls":""}`),
		`{"type":"vmess","tls":null,"transport":{"type":"http","method":"GET","path":"/","host":["example.com"]}}`},

	// ws/httpupgrade early data out of the path
	{"ws early data in the path",
		"vless://" + testUUID + "@192.0.2.10:443?type=ws&path=%2Fws%3Fed%3D2048&host=example.com&security=tls&sni=example.com&fp=chrome#ws-cdn",
		`{"transport":{"type":"ws","path":"/ws","headers":{"Host":"example.com"},"max_early_data":2048,"early_data_header_name":"Sec-WebSocket-Protocol"}}`},
	{"ws early data on the root path",
		"vless://" + testUUID + "@192.0.2.10:443?type=ws&path=%2F%3Fed%3D2560&security=tls#ws-root",
		`{"transport":{"type":"ws","path":"/","max_early_data":2560,"early_data_header_name":"Sec-WebSocket-Protocol"}}`},
	{"ws with an unparsable ed",
		"vless://" + testUUID + "@192.0.2.10:443?type=ws&path=%2Fws%3Fed%3Dabc&security=tls#ws-bad-ed",
		`{"transport":{"type":"ws","path":"/ws","max_early_data":null,"early_data_header_name":null}}`},
	{"ws early data as parameters of the link (NekoBox)",
		"vless://" + testUUID + "@192.0.2.10:443?type=ws&path=%2Fws&ed=2048&security=tls#ws-param-ed",
		`{"transport":{"path":"/ws","max_early_data":2048,"early_data_header_name":"Sec-WebSocket-Protocol"}}`},
	{"ws path query other than ed is dropped",
		"vless://" + testUUID + "@192.0.2.10:443?type=ws&path=%2Fws%3Fed%3D2048%26token%3Dabc&security=tls#ws-token",
		`{"transport":{"path":"/ws","max_early_data":2048}}`},
	{"ws path without a query stays byte for byte",
		"vless://" + testUUID + "@192.0.2.10:443?type=ws&path=%2Fa%2525b&security=tls#ws-escaped",
		`{"transport":{"path":"/a%25b","max_early_data":null}}`},
	{"httpupgrade drops ed",
		"vless://" + testUUID + "@192.0.2.10:443?type=httpupgrade&path=%2Fhu%3Fed%3D2048&host=example.com&security=tls#hu",
		`{"transport":{"type":"httpupgrade","path":"/hu","host":"example.com","max_early_data":null,"early_data_header_name":null}}`},
	{"vmess ws early data in the path",
		vmessJSON(`{"ps":"vm-ws-ed","add":"192.0.2.20","port":443,"id":"` + testUUID + `","aid":0,"net":"ws","host":"example.com","path":"/ws?ed=2048","tls":"tls","sni":"example.com"}`),
		`{"transport":{"type":"ws","path":"/ws","max_early_data":2048},"tls":{"utls":{"fingerprint":"chrome"}}}`},

	// ws/httpupgrade over TLS: no alpn, sing-box then offers http/1.1 (with
	// h2 in the list the server picks h2 and drops the upgrade)
	{"ws over TLS leaves the alpn out",
		"vless://" + testUUID + "@192.0.2.10:443?type=ws&path=%2Fws&host=example.com&security=tls&fp=chrome&alpn=h2%2Chttp%2F1.1&sni=example.com#ws-alpn",
		`{"tls":{"enabled":true,"alpn":null,"utls":{"fingerprint":"chrome"}},"transport":{"type":"ws","path":"/ws"}}`},
	{"httpupgrade over TLS leaves the alpn out",
		"trojan://secret@192.0.2.30:443?type=httpupgrade&path=%2Fhu&host=example.com&alpn=h2%2Chttp%2F1.1&sni=example.com#hu-alpn",
		`{"tls":{"enabled":true,"alpn":null},"transport":{"type":"httpupgrade","path":"/hu"}}`},
	{"vmess ws over TLS leaves the alpn out",
		vmessJSON(`{"ps":"vm-ws-alpn","add":"192.0.2.20","port":443,"id":"` + testUUID + `","net":"ws","path":"/ws","tls":"tls","sni":"example.com","alpn":"h2,http/1.1"}`),
		`{"tls":{"enabled":true,"alpn":null},"transport":{"type":"ws"}}`},
	// Xray's custom gRPC path "/<service>/Tun" is sing-box's service_name
	{"grpc custom path of one segment and Tun",
		"vless://" + testUUID + "@192.0.2.10:443?type=grpc&serviceName=%2Fmysvc%2FTun%7CTunMulti&security=tls&sni=example.com#grpc-path",
		`{"transport":{"type":"grpc","service_name":"mysvc"}}`},
	{"vmess grpc custom path",
		vmessJSON(`{"ps":"vm-grpc-path","add":"192.0.2.20","port":443,"id":"` + testUUID + `","net":"grpc","path":"/vmsvc/Tun","tls":"tls"}`),
		`{"transport":{"type":"grpc","service_name":"vmsvc"}}`},
	{"grpc keeps the alpn",
		"vless://" + testUUID + "@192.0.2.10:443?type=grpc&serviceName=svc&security=tls&alpn=h2&sni=example.com#grpc-alpn",
		`{"tls":{"alpn":["h2"]},"transport":{"type":"grpc"}}`},

	// Xray's finalmask: the client-only fragment is dropped
	{"finalmask with only fragment",
		"vless://" + testUUID + "@192.0.2.10:443?security=tls&sni=example.com&fm=" +
			url.QueryEscape(`{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","length":"100-200","delay":"10-20"}}]}`) + "#fm-fragment",
		`{"fm":null,"tls":{"enabled":true},"transport":null}`},
	{"vmess finalmask with only fragment",
		vmessJSON(`{"ps":"vm-fm","add":"192.0.2.20","port":443,"id":"` + testUUID + `","net":"tcp","tls":"tls","fm":"{\"tcp\":[{\"type\":\"fragment\"}]}"}`),
		`{"fm":null,"tls":{"enabled":true}}`},
	// The udp layer's masks: Xray applies them to UDP only, never to these
	// TCP transports
	{"finalmask udp masks leave a TCP stream alone",
		"trojan://secret@192.0.2.30:443?sni=example.com&fm=" +
			url.QueryEscape(`{"udp":[{"type":"salamander","settings":{"password":"x"}}]}`) + "#fm-udp",
		`{"type":"trojan","tls":{"enabled":true},"transport":null}`},
	{"finalmask of fragment, udp masks and other settings",
		"vless://" + testUUID + "@192.0.2.10:443?type=ws&path=%2Fws&security=tls&sni=example.com&fm=" +
			url.QueryEscape(`{"tcp":[{"type":"fragment"}],"udp":[{"type":"noise"},{"type":"xdns"}],"quicParams":{"congestion":"bbr"}}`) + "#fm-mixed",
		`{"transport":{"type":"ws","path":"/ws"}}`},
	{"vmess finalmask with udp masks",
		vmessJSON(`{"ps":"vm-fm-udp","add":"192.0.2.20","port":443,"id":"` + testUUID + `","net":"ws","path":"/ws","tls":"tls","fm":{"udp":[{"type":"salamander"}]}}`),
		`{"transport":{"type":"ws"}}`},
	// Shadowsocks carries UDP itself: a udp mask leaves UDP off, TCP works
	{"shadowsocks finalmask with udp masks",
		"ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwdw@192.0.2.40:8388?fm=" +
			url.QueryEscape(`{"udp":[{"type":"salamander","settings":{"password":"x"}}]}`) + "#ss-fm-udp",
		`{"type":"shadowsocks","network":"tcp"}`},
	{"shadowsocks finalmask with only fragment",
		"ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwdw@192.0.2.40:8388?fm=" +
			url.QueryEscape(`{"tcp":[{"type":"fragment"}]}`) + "#ss-fm-fragment",
		`{"type":"shadowsocks","network":null}`},

	// sing-box's own QUIC transport (s-ui exports it as type=quic): TLS
	// without uTLS
	{"quic transport",
		"vless://" + testUUID + "@192.0.2.10:443?type=quic&security=tls&sni=example.com#quic",
		`{"transport":{"type":"quic"},"tls":{"enabled":true,"server_name":"example.com","utls":null}}`},
	{"quic with v2rayN's empty settings",
		"vless://" + testUUID + "@192.0.2.10:443?type=quic&quicSecurity=none&key=&headerType=none&security=tls&fp=chrome&sni=example.com#quic-none",
		`{"transport":{"type":"quic"},"tls":{"utls":null}}`},
	{"vmess quic",
		vmessJSON(`{"ps":"vm-quic","add":"192.0.2.20","port":443,"id":"` + testUUID + `","net":"quic","type":"none","host":"none","path":"","tls":"tls","sni":"example.com"}`),
		`{"transport":{"type":"quic"},"tls":{"enabled":true,"utls":null}}`},
	// Its "host" is the QUIC encryption, no server name: the address is
	{"vmess quic without sni",
		vmessJSON(`{"ps":"vm-quic-nosni","add":"192.0.2.20","port":443,"id":"` + testUUID + `","net":"quic","type":"none","host":"none","path":"","tls":"tls"}`),
		`{"transport":{"type":"quic"},"tls":{"server_name":"192.0.2.20"}}`},
	{"vmess ws takes the server name from host",
		vmessJSON(`{"ps":"vm-ws-host","add":"192.0.2.20","port":443,"id":"` + testUUID + `","net":"ws","host":"cdn.example.com","path":"/ws","tls":"tls"}`),
		`{"tls":{"server_name":"cdn.example.com"}}`},

	// flow
	{"flow -udp443",
		"vless://" + testUUID + "@192.0.2.10:443?type=tcp&security=reality&sni=www.example.com&fp=chrome&pbk=" + testPBK + "&sid=6ba85179&flow=xtls-rprx-vision-udp443#udp443",
		`{"flow":"xtls-rprx-vision"}`},
	{"flow in upper case",
		"vless://" + testUUID + "@192.0.2.10:443?security=reality&sni=www.example.com&pbk=" + testPBK + "&flow=XTLS-RPRX-VISION#upper-flow",
		`{"flow":"xtls-rprx-vision"}`},
	{"flow none",
		"vless://" + testUUID + "@192.0.2.10:443?security=tls&flow=none#no-flow",
		`{"flow":null}`},
	{"vless encryption none in any case",
		"vless://" + testUUID + "@192.0.2.10:443?security=tls&encryption=NONE#enc-none",
		`{"type":"vless","encryption":null}`},

	// Hysteria 2: port hopping, default port, never uTLS
	{"hysteria2 multi-port authority",
		"hysteria2://letmein@192.0.2.50:443,20000-30000/?insecure=1&sni=example.com&obfs=salamander&obfs-password=example#hy2-hop",
		`{"type":"hysteria2","server":"192.0.2.50","server_port":443,"server_ports":["443:443","20000:30000"],"hop_interval":null,
		  "password":"letmein","obfs":{"type":"salamander","password":"example"},
		  "tls":{"enabled":true,"server_name":"example.com","insecure":true,"utls":null}}`},
	{"hysteria2 range-only authority",
		"hy2://letmein@192.0.2.50:20000-30000?sni=example.com#hy2-range",
		`{"server_port":20000,"server_ports":["20000:30000"]}`},
	{"hysteria2 bracketed IPv6 with a port list",
		"hysteria2://letmein@[2001:db8::1]:443,20000-30000/?sni=example.com#hy2-v6",
		`{"server":"2001:db8::1","server_port":443,"server_ports":["443:443","20000:30000"]}`},
	{"hysteria2 without a port",
		"hysteria2://letmein@example.com/?sni=example.com#hy2-noport",
		`{"server":"example.com","server_port":443,"server_ports":null}`},
	{"hysteria2 without a port or a slash",
		"hysteria2://letmein@example.com?insecure=1#hy2-noport-2",
		`{"server_port":443}`},
	{"hysteria2 mport and mportHopInt",
		"hysteria2://letmein@example.com:443/?mport=20000-30000&mportHopInt=30#hy2-mport",
		`{"server_port":443,"server_ports":["20000:30000"],"hop_interval":"30s"}`},
	{"hysteria2 mport list, too short a hop interval",
		"hysteria2://letmein@example.com:443/?mport=20000:30000,40000&mportHopInt=3#hy2-mport-list",
		`{"server_ports":["20000:30000","40000:40000"],"hop_interval":null}`},
	{"hysteria2 password with ':' and ','",
		"hysteria2://pa:ss,w-1@192.0.2.50:443,20000-30000/#hy2-pw",
		`{"password":"pa:ss,w-1","server_ports":["443:443","20000:30000"]}`},
	{"hysteria2 never gets uTLS",
		"hysteria2://letmein@192.0.2.50:443?sni=example.com&fp=chrome&alpn=h3#hy2-fp",
		`{"tls":{"utls":null,"alpn":["h3"]}}`},

	// New schemes
	{"tuic",
		"tuic://" + testUUID + ":pass@192.0.2.60:443?congestion_control=bbr&alpn=h3&sni=example.com&udp_relay_mode=native#tuic-node",
		`{"type":"tuic","tag":"tuic-node","server":"192.0.2.60","server_port":443,"uuid":"` + testUUID + `","password":"pass",
		  "congestion_control":"bbr","udp_relay_mode":"native","tls":{"enabled":true,"server_name":"example.com","alpn":["h3"],"utls":null}}`},
	{"tuic defaults",
		"tuic://" + testUUID + ":p%40ss@192.0.2.60:443?congestion_control=new-reno&udp_relay_mode=stream&allow_insecure=1&disable_sni=1#tuic-defaults",
		`{"password":"p@ss","congestion_control":"new_reno","udp_relay_mode":null,
		  "tls":{"server_name":"192.0.2.60","alpn":["h3"],"insecure":true,"disable_sni":true}}`},
	{"anytls without a port",
		"anytls://letmein@example.com/?sni=real.example.com&insecure=1#at",
		`{"type":"anytls","server":"example.com","server_port":443,"password":"letmein",
		  "tls":{"enabled":true,"server_name":"real.example.com","insecure":true,"utls":null}}`},
	{"anytls with an escaped password",
		"anytls://p%40ss%3Aw@192.0.2.61:8964/?insecure=0#at2",
		`{"server_port":8964,"password":"p@ss:w","tls":{"server_name":"192.0.2.61","insecure":null}}`},
	{"hysteria v1",
		"hysteria://192.0.2.70:8443?protocol=udp&auth=123456&peer=sni.example.com&insecure=1&upmbps=100&downmbps=200&alpn=hysteria&obfs=xplus&obfsParam=obfspw#hy1",
		`{"type":"hysteria","server":"192.0.2.70","server_port":8443,"auth_str":"123456","up_mbps":100,"down_mbps":200,"obfs":"obfspw",
		  "tls":{"enabled":true,"server_name":"sni.example.com","insecure":true,"alpn":["hysteria"],"utls":null}}`},
	{"hysteria v1 port hopping",
		"hysteria://192.0.2.70:8443?upmbps=50&downmbps=50&mport=20000-30000#hy1-hop",
		`{"server_ports":["20000:30000"],"obfs":null,"auth_str":null}`},
	{"socks5 with user and password",
		"socks5://user:p%40ss@192.0.2.80:1080#s5",
		`{"type":"socks","server":"192.0.2.80","server_port":1080,"username":"user","password":"p@ss","version":null}`},
	{"socks with base64 userinfo (v2rayN)",
		"socks://" + base64.RawStdEncoding.EncodeToString([]byte("user:pass")) + "@192.0.2.80:1080#s-v2rayn",
		`{"type":"socks","username":"user","password":"pass"}`},
	{"socks4 without auth",
		"socks4://192.0.2.80:1080#s4",
		`{"type":"socks","version":"4","username":null,"password":null}`},
	{"socks legacy base64 body",
		"socks://" + b64("user:pass@192.0.2.80:1080") + "#s-legacy",
		`{"server":"192.0.2.80","server_port":1080,"username":"user","password":"pass"}`},
	// The generators base64-encode the password as it is: a '#', '/', '?'
	// (or '@', ':') in it is the password's, not the end of the authority
	{"socks legacy body with URL delimiters in the password",
		"socks://" + b64("user:2024#p/a?s:s@w@192.0.2.80:1080") + "#s-legacy-pw",
		`{"tag":"s-legacy-pw","server":"192.0.2.80","server_port":1080,"username":"user","password":"2024#p/a?s:s@w"}`},
	{"socks legacy body without credentials",
		"socks://" + b64("192.0.2.80:1080") + "#s-legacy-anon",
		`{"server":"192.0.2.80","server_port":1080,"username":null,"password":null}`},
	// No credentials and an '@' in the name: no password was cut short
	{"socks without credentials, an '@' in the name",
		"socks5://192.0.2.80:1080#me@work",
		`{"tag":"me@work","server":"192.0.2.80","server_port":1080,"username":null}`},
	{"hysteria v1 auth with an '@' in the query",
		"hysteria://192.0.2.70:8443?auth=user@example.com&upmbps=10&downmbps=10#hy1-at",
		`{"server":"192.0.2.70","server_port":8443,"auth_str":"user@example.com"}`},
	// An escaped '&' or '#' belongs to the name: only the raw fragment tells
	// the rest of a query
	{"name with an escaped query pair",
		"trojan://secret@192.0.2.30:443?sni=example.com#Tom%26Jerry%3D1",
		`{"tag":"Tom&Jerry=1"}`},
	{"name with an escaped '#'",
		"trojan://secret@192.0.2.30:443?sni=example.com#DE%231",
		`{"tag":"DE#1"}`},
	{"vmess URL form",
		"vmess://" + testUUID + "@192.0.2.20:443?encryption=auto&type=ws&path=%2Fws&host=example.com&security=tls&sni=example.com&fp=chrome#vm-url",
		`{"type":"vmess","tag":"vm-url","server":"192.0.2.20","server_port":443,"uuid":"` + testUUID + `","security":"auto","alter_id":0,
		  "tls":{"enabled":true,"server_name":"example.com","utls":{"fingerprint":"chrome"}},
		  "transport":{"type":"ws","path":"/ws","headers":{"Host":"example.com"}}}`},
	{"vmess URL form without encryption",
		"vmess://" + testUUID + "@192.0.2.20:8080?type=tcp#vm-url-plain",
		`{"security":"auto","tls":null,"transport":null}`},

	// A certificate pin sing-box cannot carry over, without an insecure flag:
	// the ordinary verification stays (a CA-signed server still connects)
	{"pcs without insecure",
		"vless://" + testUUID + "@203.0.113.5:443?type=tcp&security=tls&fp=chrome&pcs=ab12cd#pcs-verified",
		`{"tls":{"enabled":true,"server_name":"203.0.113.5","insecure":null,"pcs":null}}`},
	{"pcs with insecure=0",
		"trojan://secret@192.0.2.30:443?sni=example.com&allowInsecure=0&pcs=ab12cd#pcs-insecure-0",
		`{"tls":{"server_name":"example.com","insecure":null}}`},
	{"hysteria2 pinSHA256 without insecure",
		"hysteria2://letmein@192.0.2.50:443/?sni=example.com&pinSHA256=AB%3ACD#hy2-pin",
		`{"tls":{"server_name":"example.com","insecure":null}}`},
	{"vcn naming the SNI",
		"vless://" + testUUID + "@192.0.2.10:443?security=tls&sni=example.com&vcn=Example.com#vcn-same",
		`{"tls":{"server_name":"example.com","insecure":null}}`},
	// vcn naming the SNI is the ordinary check (Xray verifies against the
	// system roots for that name): the insecure flag for other clients goes
	{"vcn naming the SNI with insecure",
		"vless://" + testUUID + "@192.0.2.10:443?security=tls&sni=example.com&vcn=example.com&allowInsecure=1#vcn-insecure",
		`{"tls":{"server_name":"example.com","insecure":null}}`},
	{"vmess pcs without insecure",
		vmessJSON(`{"ps":"vm-pcs","add":"192.0.2.20","port":"443","id":"` + testUUID + `","net":"tcp","tls":"tls","sni":"example.com","insecure":"0","pcs":"ab12cd"}`),
		`{"tls":{"server_name":"example.com","insecure":null,"pcs":null}}`},
	{"vmess vcn naming the SNI with insecure",
		vmessJSON(`{"ps":"vm-vcn-insecure","add":"192.0.2.20","port":"443","id":"` + testUUID + `","net":"tcp","tls":"tls","sni":"example.com","insecure":"1","vcn":"example.com"}`),
		`{"tls":{"server_name":"example.com","insecure":null,"vcn":null}}`},

	// Trojan
	{"trojan without security keeps its TLS parameters",
		"trojan://secret@192.0.2.30:443?sni=example.com&allowInsecure=1&fp=chrome&alpn=h2%2Chttp%2F1.1#trojan-classic",
		`{"tls":{"enabled":true,"server_name":"example.com","insecure":true,"alpn":["h2","http/1.1"],"utls":{"enabled":true,"fingerprint":"chrome"}}}`},
	{"trojan security=none is plain trojan",
		"trojan://secret@192.0.2.30:80?security=none&type=ws&path=%2Fws&host=example.com#trojan-plain",
		`{"tls":null,"transport":{"type":"ws","path":"/ws","headers":{"Host":"example.com"}}}`},
	{"trojan peer is the SNI",
		"trojan://secret@192.0.2.30:443?peer=example.com&allowInsecure=1#trojan-peer",
		`{"tls":{"server_name":"example.com","insecure":true}}`},
	{"trojan empty security means TLS",
		"trojan://secret@192.0.2.30:443?security=&sni=example.com#trojan-empty-security",
		`{"tls":{"enabled":true,"server_name":"example.com"}}`},
	{"trojan over REALITY",
		"trojan://secret@192.0.2.30:443?security=reality&sni=www.example.com&pbk=" + testPBK + "&sid=ab#trojan-reality",
		`{"tls":{"reality":{"enabled":true,"short_id":"ab"},"utls":{"fingerprint":"chrome"}}}`},

	// VMess JSON
	{"vmess grpc service name from path",
		"vmess://eyJ2IjoiMiIsInBzIjoidm0tZ3JwYyIsImFkZCI6IjE5Mi4wLjIuMjAiLCJwb3J0IjoiNDQzIiwiaWQiOiIxMTExMTExMS0yMjIyLTQzMzMtODQ0NC01NTU1NTU1NTU1NTUiLCJhaWQiOiIwIiwic2N5IjoiYXV0byIsIm5ldCI6ImdycGMiLCJ0eXBlIjoiZ3VuIiwiaG9zdCI6IiIsInBhdGgiOiJteWdycGMiLCJ0bHMiOiJ0bHMiLCJzbmkiOiJleGFtcGxlLmNvbSIsImZwIjoiY2hyb21lIn0=",
		`{"type":"vmess","tag":"vm-grpc","transport":{"type":"grpc","service_name":"mygrpc"},"tls":{"server_name":"example.com","utls":{"fingerprint":"chrome"}}}`},
	{"vmess insecure and fingerprint",
		vmessJSON(`{"ps":"vm-insecure","add":"192.0.2.20","port":"443","id":"` + testUUID + `","net":"tcp","tls":"tls","insecure":"1","fp":"randomizednoalpn","scy":"zero"}`),
		`{"security":"zero","tls":{"insecure":true,"utls":{"fingerprint":"randomized"}},"transport":null}`},

	// Shadowsocks plugins sing-box has built in
	{"ss obfs-local",
		"ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwdw@192.0.2.40:8388/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dexample.com#ss-obfs",
		`{"type":"shadowsocks","method":"chacha20-ietf-poly1305","password":"pw","plugin":"obfs-local","plugin_opts":"obfs=http;obfs-host=example.com"}`},
	{"ss simple-obfs with an unescaped ';'",
		"ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwdw@192.0.2.40:8388/?plugin=simple-obfs;obfs=tls;obfs-host=example.com#ss-simple",
		`{"plugin":"obfs-local","plugin_opts":"obfs=tls;obfs-host=example.com"}`},
	{"ss v2ray-plugin",
		"ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwdw@192.0.2.40:443/?plugin=v2ray-plugin%3Bmode%3Dwebsocket%3Btls%3Bhost%3Dexample.com%3Bpath%3D%2Fws%3Bmux%3D4%3Bloglevel%3Dnone#ss-v2ray",
		`{"plugin":"v2ray-plugin","plugin_opts":"mode=websocket;tls;host=example.com;path=/ws;mux=4"}`},
	{"ss v2ray-plugin escapes are kept",
		"ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwdw@192.0.2.40:443/?plugin=" + strings.ReplaceAll(`v2ray-plugin;path=/a\;b;host=example.com`, ";", "%3B") + "#ss-escape",
		`{"plugin_opts":"path=/a\\;b;host=example.com"}`},
	{"ss method alias",
		"ss://" + base64.RawURLEncoding.EncodeToString([]byte("CHACHA20-POLY1305:pw")) + "@192.0.2.40:8388#ss-alias",
		`{"method":"chacha20-ietf-poly1305","plugin":null}`},
	// 3x-ui's stream parameters of a plain TCP inbound
	{"ss with a plain TCP stream in the query",
		"ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwdw@192.0.2.40:8388?type=tcp&headerType=none&security=none#ss-tcp",
		`{"type":"shadowsocks","plugin":null,"transport":null,"tls":null}`},
	{"ss with Xray's raw",
		"ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwdw@192.0.2.40:8388?type=raw#ss-raw",
		`{"type":"shadowsocks","plugin":null}`},
	// The http header next to the plugin that carries it
	{"ss tcp http header with obfs-local",
		"ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwdw@192.0.2.40:8388?type=tcp&headerType=http&plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dexample.com#ss-tcp-http-plugin",
		`{"plugin":"obfs-local","plugin_opts":"obfs=http;obfs-host=example.com"}`},
}

// refusalCase is a link that must be refused; the error names the node
// (name) and contains reason
type refusalCase struct {
	name, link, reason string
}

var refusedLinks = []refusalCase{
	{"xhttp-node", "vless://" + testUUID + "@192.0.2.10:443?type=xhttp&mode=auto&path=%2Fxh&security=reality&sni=www.example.com&fp=chrome&pbk=" + testPBK + "&sid=6ba85179&encryption=none#xhttp-node", "XHTTP"},
	{"splithttp", "vless://" + testUUID + "@192.0.2.10:443?type=splithttp&path=%2Fsh&security=tls#splithttp", "XHTTP"},
	{"kcp", "vless://" + testUUID + "@192.0.2.10:443?type=kcp&headerType=wechat-video&seed=" + testSecret + "#kcp", "mKCP"},
	{"mkcp", "vless://" + testUUID + "@192.0.2.10:443?type=mkcp#mkcp", "mKCP"},
	{"quic-no-tls", "vless://" + testUUID + "@192.0.2.10:443?type=quic#quic-no-tls", "QUIC работает только с TLS"},
	{"quic-encrypted", "vless://" + testUUID + "@192.0.2.10:443?type=quic&quicSecurity=aes-128-gcm&key=" + testSecret + "&security=tls#quic-encrypted", "шифрование QUIC «aes-128-gcm»"},
	{"quic-header", "vless://" + testUUID + "@192.0.2.10:443?type=quic&headerType=wechat-video&security=tls#quic-header", "маскировка QUIC «wechat-video»"},
	{"quic-reality", "vless://" + testUUID + "@192.0.2.10:443?type=quic&security=reality&sni=www.example.com&pbk=" + testPBK + "#quic-reality", "REALITY поверх транспорта QUIC"},
	{"vm-quic-encrypted", vmessJSON(`{"ps":"vm-quic-encrypted","add":"192.0.2.20","port":"443","id":"` + testUUID + `","net":"quic","host":"chacha20-poly1305","path":"` + testSecret + `","tls":"tls"}`), "шифрование QUIC «chacha20-poly1305»"},
	{"fm-sudoku", "vless://" + testUUID + "@192.0.2.10:443?type=tcp&security=tls&fm=" +
		url.QueryEscape(`{"tcp":[{"type":"fragment"},{"type":"sudoku","settings":{"password":"`+testSecret+`"}}]}`) + "#fm-sudoku", "маскировка finalmask «sudoku»"},
	{"fm-tcp-upper", "vless://" + testUUID + "@192.0.2.10:443?security=tls&fm=" +
		url.QueryEscape(`{"TCP":[{"type":"xmc","settings":{"password":"`+testSecret+`"}}]}`) + "#fm-tcp-upper", "маскировка finalmask «xmc»"},
	{"ss-fm-sudoku", "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwdw@192.0.2.40:8388?fm=" +
		url.QueryEscape(`{"tcp":[{"type":"sudoku","settings":{"password":"`+testSecret+`"}}]}`) + "#ss-fm-sudoku", "маскировка finalmask «sudoku»"},
	{"fm-tcp-object", "vless://" + testUUID + "@192.0.2.10:443?security=tls&fm=" +
		url.QueryEscape(`{"tcp":{"type":"sudoku","settings":{"password":"`+testSecret+`"}}}`) + "#fm-tcp-object", "fm (finalmask) в ссылке повреждён"},
	// sing-box's QUIC transport runs over UDP: there the udp layer counts
	{"fm-quic-udp", "vless://" + testUUID + "@192.0.2.10:443?type=quic&security=tls&sni=example.com&fm=" +
		url.QueryEscape(`{"udp":[{"type":"salamander","settings":{"password":"`+testSecret+`"}}]}`) + "#fm-quic-udp", "маскировка finalmask «salamander»"},
	{"vm-fm-quic-udp", vmessJSON(`{"ps":"vm-fm-quic-udp","add":"192.0.2.20","port":"443","id":"` + testUUID + `","net":"quic","tls":"tls","fm":{"udp":[{"type":"salamander","settings":{"password":"` + testSecret + `"}}]}}`), "маскировка finalmask «salamander»"},
	{"fm-broken", "vless://" + testUUID + "@192.0.2.10:443?security=tls&fm=%7B" + testSecret + "#fm-broken", "fm (finalmask) в ссылке повреждён"},
	{"vm-fm", vmessJSON(`{"ps":"vm-fm","add":"192.0.2.20","port":"443","id":"` + testUUID + `","fm":{"tcp":[{"type":"header-custom","settings":{"clients":["` + testSecret + `"]}}]}}`), "маскировка finalmask «header-custom»"},
	{"grpc-custom-path", "vless://" + testUUID + "@192.0.2.10:443?type=grpc&serviceName=%2Fcustom%2Fpath%7Cp2&security=tls#grpc-custom-path", "собственный путь gRPC"},
	{"grpc-root-path", "vless://" + testUUID + "@192.0.2.10:443?type=grpc&serviceName=%2Fsvc&security=tls#grpc-root-path", "собственный путь gRPC"},
	{"grpc-deep-path", "vless://" + testUUID + "@192.0.2.10:443?type=grpc&serviceName=%2Fa%2Fb%2FTun&security=tls#grpc-deep-path", "собственный путь gRPC"},
	{"vm-grpc-path", vmessJSON(`{"ps":"vm-grpc-path","add":"192.0.2.20","port":"443","id":"` + testUUID + `","net":"grpc","path":"/x/y","tls":"tls"}`), "собственный путь gRPC"},
	{"unknown transport", "vless://" + testUUID + "@192.0.2.10:443?type=foo#unknown%20transport", "транспорт «foo»"},
	{"tcp-http-tls", "vless://" + testUUID + "@192.0.2.10:443?type=tcp&headerType=http&security=tls#tcp-http-tls", "HTTP-маскировкой"},
	{"tcp-http-reality", "vless://" + testUUID + "@192.0.2.10:443?type=tcp&headerType=http&security=reality&pbk=" + testPBK + "#tcp-http-reality", "HTTP-маскировкой"},
	{"trojan-tcp-http", "trojan://" + testSecret + "@192.0.2.30:443?type=tcp&headerType=http#trojan-tcp-http", "HTTP-маскировкой"},
	{"tcp-srtp", "vless://" + testUUID + "@192.0.2.10:443?type=tcp&headerType=srtp#tcp-srtp", "маскировка TCP «srtp»"},
	{"vm-kcp", vmessJSON(`{"ps":"vm-kcp","add":"192.0.2.20","port":"443","id":"` + testUUID + `","net":"kcp","type":"none","path":"` + testSecret + `"}`), "mKCP"},
	{"vm-xhttp", vmessJSON(`{"ps":"vm-xhttp","add":"192.0.2.20","port":"443","id":"` + testUUID + `","net":"xhttp","path":"/x"}`), "XHTTP"},
	{"vm-tcp-http-tls", vmessJSON(`{"ps":"vm-tcp-http-tls","add":"192.0.2.20","port":"443","id":"` + testUUID + `","net":"tcp","type":"http","tls":"tls"}`), "HTTP-маскировкой"},

	{"pq-node", "vless://" + testUUID + "@192.0.2.10:443?type=tcp&security=none&encryption=mlkem768x25519plus.native.0rtt." + testSecret + "&flow=xtls-rprx-vision#pq-node", "mlkem768x25519plus"},
	{"enc-other", "vless://" + testUUID + "@192.0.2.10:443?encryption=" + testSecret + "#enc-other", "неизвестный метод"},
	{"direct-flow", "vless://" + testUUID + "@192.0.2.10:443?security=tls&flow=xtls-rprx-direct#direct-flow", "flow «xtls-rprx-direct»"},
	{"vless-security", "vless://" + testUUID + "@192.0.2.10:443?security=xyz#vless-security", "режим защиты «xyz»"},

	// A pin (or vcn) with an insecure flag: sing-box would honour the flag
	// alone and accept any certificate
	{"pcs-insecure", "vless://" + testUUID + "@203.0.113.5:443?security=tls&allowInsecure=1&pcs=" + testSecret + "#pcs-insecure", "закрепление сертификата (pcs)"},
	{"trojan-pcs-insecure", "trojan://" + testSecret + "@192.0.2.30:443?insecure=1&pcs=ab12cd#trojan-pcs-insecure", "закрепление сертификата (pcs)"},
	{"vm-url-pcs-insecure", "vmess://" + testUUID + "@192.0.2.20:443?security=tls&allowInsecure=true&pcs=ab12cd#vm-url-pcs-insecure", "закрепление сертификата (pcs)"},
	{"hy2-pin-insecure", "hysteria2://" + testSecret + "@192.0.2.50:443/?insecure=1&pinSHA256=" + testSecret + "#hy2-pin-insecure", "закрепление сертификата (pinSHA256)"},
	{"hy2-pin-lower", "hysteria2://" + testSecret + "@192.0.2.50:443/?insecure=1&pinsha256=AB%3ACD#hy2-pin-lower", "закрепление сертификата (pinSHA256)"},
	{"hy1-pin-insecure", "hysteria://192.0.2.70:8443?auth=" + testSecret + "&insecure=1&upmbps=10&downmbps=10&pinSHA256=AB#hy1-pin-insecure", "закрепление сертификата (pinSHA256)"},
	{"tuic-pin-insecure", "tuic://" + testUUID + ":" + testSecret + "@192.0.2.60:443?allow_insecure=1&pinSHA256=AB#tuic-pin-insecure", "закрепление сертификата"},
	{"anytls-pin-insecure", "anytls://" + testSecret + "@192.0.2.61/?insecure=1&pcs=AB#anytls-pin-insecure", "закрепление сертификата"},
	{"vcn-other", "vless://" + testUUID + "@192.0.2.10:443?security=tls&sni=decoy.example&vcn=real.example#vcn-other", "по другому имени (vcn)"},
	// The same in the vmess JSON (v2rayN's VmessQRCode and 3x-ui write pcs
	// and vcn there too)
	{"vm-pcs-insecure", vmessJSON(`{"ps":"vm-pcs-insecure","add":"192.0.2.20","port":"443","id":"` + testUUID + `","net":"tcp","tls":"tls","sni":"a.example","insecure":"1","pcs":"` + testSecret + `"}`), "закрепление сертификата (pcs)"},
	{"vm-pcs-insecure-true", vmessJSON(`{"ps":"vm-pcs-insecure-true","add":"192.0.2.20","port":443,"id":"` + testUUID + `","tls":"tls","insecure":true,"pcs":"ab12cd"}`), "закрепление сертификата (pcs)"},
	{"vm-vcn-other", vmessJSON(`{"ps":"vm-vcn-other","add":"192.0.2.20","port":"443","id":"` + testUUID + `","net":"tcp","tls":"tls","sni":"decoy.example","vcn":"real.example"}`), "по другому имени (vcn)"},

	{"long-sid", "vless://" + testUUID + "@192.0.2.10:443?type=tcp&security=reality&sni=www.example.com&fp=chrome&pbk=" + testPBK + "&sid=0123456789abcdef01#long-sid", "short_id"},
	{"odd-sid", "vless://" + testUUID + "@192.0.2.10:443?security=reality&pbk=" + testPBK + "&sid=0123456789abcdef0#odd-sid", "short_id"},
	{"hex-sid", "vless://" + testUUID + "@192.0.2.10:443?security=reality&pbk=" + testPBK + "&sid=zz#hex-sid", "short_id"},
	{"no-pbk", "vless://" + testUUID + "@192.0.2.10:443?security=reality&sid=ab#no-pbk", "pbk"},
	{"bad-pbk", "vless://" + testUUID + "@192.0.2.10:443?security=reality&pbk=" + testSecret + "#bad-pbk", "pbk"},

	// A password with an unescaped '/' or '?': its head would be the server
	{"hy2-slash-pw", "hysteria2://Ab3dEf/" + testSecret + "@srv.example.com:8443#hy2-slash-pw", "ссылка повреждена"},
	{"hy2-query-pw", "hysteria2://Ab3dEf?" + testSecret + "@srv.example.com#hy2-query-pw", "ссылка повреждена"},
	// The same where the credential is optional (socks, hysteria v1): a head
	// of digits read as the port of the user name taken for the server
	{"s5-slash-pw", "socks5://alice:2024/" + testSecret + "@192.0.2.80:1080#s5-slash-pw", "«/», «?» и «#» в пароле"},
	{"s5-query-pw", "socks5://alice:2024?" + testSecret + "@192.0.2.80:1080#s5-query-pw", "«/», «?» и «#» в пароле"},
	{"s5-alpha-pw", "socks5://alice:pw/" + testSecret + "@192.0.2.80:1080#s5-alpha-pw", "«/», «?» и «#» в пароле"},
	{"hy1-slash-pw", "hysteria://ab:12/" + testSecret + "@192.0.2.70:8443?protocol=udp&upmbps=10&downmbps=50#hy1-slash-pw", "«/», «?» и «#» в пароле"},
	{"hy1-query-pw", "hysteria://ab:12?" + testSecret + "@192.0.2.70:8443?protocol=udp&upmbps=10&downmbps=50#hy1-query-pw", "«/», «?» и «#» в пароле"},
	{"hy1-list-pw", "hysteria://ab:12/" + testSecret + "@192.0.2.70:8443,20000-30000?upmbps=10&downmbps=50#hy1-list-pw", "«/», «?» и «#» в пароле"},
	{"hy2-bad-list", "hysteria2://" + testSecret + "@192.0.2.50:443,abc/?sni=example.com#hy2-bad-list", "список портов"},
	{"hy2-bad-mport", "hysteria2://" + testSecret + "@192.0.2.50:443/?mport=30000-20000#hy2-bad-mport", "список портов «30000-20000»"},
	{"hy2-port-0", "hysteria2://" + testSecret + "@192.0.2.50:0/?sni=example.com#hy2-port-0", "неверный порт"},
	{"hy2-xplus", "hysteria2://" + testSecret + "@192.0.2.50:443/?obfs=xplus&obfs-password=x#hy2-xplus", "обфускация «xplus»"},
	{"hy2-obfs-nopw", "hysteria2://" + testSecret + "@192.0.2.50:443/?obfs=salamander#hy2-obfs-nopw", "obfs-password"},
	{"hy1-faketcp", "hysteria://192.0.2.70:8443?protocol=faketcp&auth=" + testSecret + "&upmbps=10&downmbps=10#hy1-faketcp", "faketcp"},
	{"hy1-nospeed", "hysteria://192.0.2.70:8443?auth=" + testSecret + "#hy1-nospeed", "скорость"},
	{"hy1-obfs", "hysteria://192.0.2.70:8443?upmbps=10&downmbps=10&obfs=other&obfsParam=" + testSecret + "#hy1-obfs", "обфускация «other»"},

	{"tuic-v4", "tuic://" + testSecret + "@192.0.2.60:443?alpn=h3#tuic-v4", "TUIC v4"},
	{"tuic-bad-uuid", "tuic://" + testSecret + ":pass@192.0.2.60:443#tuic-bad-uuid", "uuid"},
	{"tuic-cc", "tuic://" + testUUID + ":" + testSecret + "@192.0.2.60:443?congestion_control=vegas#tuic-cc", "«vegas»"},

	{"ss-cert", "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwdw@192.0.2.40:443/?plugin=v2ray-plugin%3Btls%3Bcert%3D%2Fetc%2F" + testSecret + ".pem#ss-cert", "cert"},
	{"ss-quic", "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwdw@192.0.2.40:443/?plugin=v2ray-plugin%3Bmode%3Dquic%3Btls#ss-quic", "QUIC"},
	{"ss-v2ray-key", "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwdw@192.0.2.40:443/?plugin=v2ray-plugin%3B" + testSecret + "%3D1#ss-v2ray-key", "параметр плагина v2ray-plugin"},
	{"ss-ck", "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pw")) + "@192.0.2.40:8388?plugin=ck-client%3BUID%3D" + testSecret + "#ss-ck", "плагин «ck-client»"},
	{"ss-obfs-mode", "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwdw@192.0.2.40:8388/?plugin=obfs-local%3Bobfs%3Dxyz#ss-obfs-mode", "режим obfs"},
	{"ss-method", "ss://" + base64.RawURLEncoding.EncodeToString([]byte("plain:"+testSecret)) + "@192.0.2.40:8388#ss-method", "метод шифрования"},
	// 3x-ui's Shadowsocks over an Xray transport or TLS: sing-box's
	// shadowsocks has neither
	{"ss-ws-tls", "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwdw@cdn.example.com:443?fp=chrome&host=cdn.example.com&path=%2F" + testSecret + "&security=tls&sni=cdn.example.com&type=ws#ss-ws-tls", "транспорт «ws» для Shadowsocks"},
	{"ss-grpc", "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwdw@192.0.2.40:443?type=grpc&serviceName=" + testSecret + "#ss-grpc", "транспорт «grpc» для Shadowsocks"},
	{"ss-kcp", "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwdw@192.0.2.40:443?type=kcp&seed=" + testSecret + "#ss-kcp", "транспорт «kcp» для Shadowsocks"},
	{"ss-httpupgrade", "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwdw@192.0.2.40:443?type=httpupgrade&path=%2Fhu#ss-httpupgrade", "транспорт «httpupgrade» для Shadowsocks"},
	{"ss-other-transport", "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwdw@192.0.2.40:443?type=" + testSecret + "%2F%2F#ss-other-transport", "транспорт «…» для Shadowsocks"},
	{"ss-tls", "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwdw@192.0.2.40:443?type=tcp&security=tls&sni=example.com#ss-tls", "режим защиты «tls» для Shadowsocks"},
	{"ss-reality", "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwdw@192.0.2.40:443?security=reality&pbk=" + testPBK + "#ss-reality", "режим защиты «reality» для Shadowsocks"},
	{"ss-tcp-http", "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwdw@192.0.2.40:80?type=tcp&headerType=http&host=example.com#ss-tcp-http", "маскировка TCP «http» для Shadowsocks"},
	{"ss-legacy-ws", "ss://" + b64("aes-256-gcm:pw@192.0.2.40:8388") + "?type=ws&path=%2Fws#ss-legacy-ws", "транспорт «ws» для Shadowsocks"},

	{"vm-cipher", vmessJSON(`{"ps":"vm-cipher","add":"192.0.2.20","port":"443","id":"` + testUUID + `","scy":"aes-128-ctr"}`), "шифрование VMess «aes-128-ctr»"},
	{"vm-reality", vmessJSON(`{"ps":"vm-reality","add":"192.0.2.20","port":"443","id":"` + testUUID + `","tls":"reality"}`), "режим защиты «reality»"},
	{"vm-noid", vmessJSON(`{"ps":"vm-noid","add":"192.0.2.20","port":"443"}`), "uuid"},

	{"ssr-node", "ssr://" + b64("192.0.2.90:8388:origin:aes-256-cfb:plain:"+testSecret) + "#ssr-node", "ShadowsocksR"},
	{"wg-node", "wireguard://" + testSecret + "@192.0.2.91:51820?publickey=x#wg-node", "WireGuard"},
	{"socks-noport", "socks5://user:" + testSecret + "@192.0.2.80#socks-noport", "порт"},
}

func mustDecode(s string) []byte {
	data, err := decodeBase64(s)
	if err != nil {
		panic(err)
	}
	return data
}

// normalized is the outbound as the config file holds it
func normalized(t *testing.T, o Outbound) map[string]any {
	t.Helper()
	data, err := json.Marshal(o)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return m
}

// mismatch reports where want is not contained in got ("" when it is); a
// null in want means the key must be absent
func mismatch(got, want any, path string) string {
	w, isObject := want.(map[string]any)
	if !isObject {
		if !reflect.DeepEqual(got, want) {
			return fmt.Sprintf("%s: got %v, want %v", path, got, want)
		}
		return ""
	}
	g, ok := got.(map[string]any)
	if !ok {
		return fmt.Sprintf("%s: got %v, want an object", path, got)
	}
	for k, wv := range w {
		gv, present := g[k]
		switch {
		case wv == nil && present:
			return fmt.Sprintf("%s.%s: got %v, want no such key", path, k, gv)
		case wv == nil:
		case !present:
			return fmt.Sprintf("%s.%s: missing", path, k)
		default:
			if m := mismatch(gv, wv, path+"."+k); m != "" {
				return m
			}
		}
	}
	return ""
}

func checkOutbound(t *testing.T, o Outbound, wantJSON string) {
	t.Helper()
	var want any
	if err := json.Unmarshal([]byte(wantJSON), &want); err != nil {
		t.Fatalf("bad want JSON: %v", err)
	}
	if m := mismatch(normalized(t, o), want, "outbound"); m != "" {
		t.Errorf("%s\n%v", m, normalized(t, o))
	}
}

func TestAcceptedLinks(t *testing.T) {
	for _, c := range acceptedLinks {
		t.Run(c.name, func(t *testing.T) {
			o, err := Parse(c.link)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			checkOutbound(t, o, c.want)
		})
	}
}

// russian: a reason for the user is written in Russian
func russian(s string) bool {
	for _, r := range s {
		if unicode.Is(unicode.Cyrillic, r) {
			return true
		}
	}
	return false
}

func TestRefusedLinks(t *testing.T) {
	for _, c := range refusedLinks {
		t.Run(c.name, func(t *testing.T) {
			o, err := Parse(c.link)
			if err == nil {
				t.Fatalf("parsed, want a refusal: %v", o)
			}
			msg := err.Error()
			if !strings.Contains(msg, c.reason) {
				t.Errorf("error %q does not say %q", msg, c.reason)
			}
			if !strings.Contains(msg, "«"+c.name+"»") {
				t.Errorf("error %q does not name the node %q", msg, c.name)
			}
			if !russian(msg) {
				t.Errorf("error %q is not in Russian", msg)
			}
			if strings.Contains(msg, testSecret) || strings.Contains(msg, testUUID) {
				t.Errorf("error quotes the link: %q", msg)
			}

			// The same through the batch: a skip with the name and the reason
			_, skipped, err := ParseAllReport("vless://" + testUUID + "@192.0.2.10:443?security=tls#ok\n" + c.link)
			if err != nil {
				t.Fatalf("ParseAllReport: %v", err)
			}
			if len(skipped) != 1 || skipped[0].Name != c.name || !strings.Contains(skipped[0].Reason, c.reason) {
				t.Fatalf("skipped = %+v", skipped)
			}
			if strings.Contains(skipped[0].Reason, "«"+c.name+"»") {
				t.Errorf("the reason repeats the name: %q", skipped[0].Reason)
			}
		})
	}
}

func TestUTLSFingerprint(t *testing.T) {
	cases := []struct {
		fp      string
		reality bool
		want    string
		ok      bool
	}{
		{"", false, "chrome", true},
		{" ", true, "chrome", true},
		{"unsafe", false, "", false},
		{"unsafe", true, "chrome", true},
		{"none", false, "", false},
		{"HelloGolang", false, "", false},
		{"Chrome", false, "chrome", true},
		{"firefox", false, "firefox", true},
		{"360", false, "360", true},
		{"random", false, "random", true},
		{"randomized", false, "randomized", true},
		{"randomizednoalpn", false, "randomized", true},
		{"hellorandomizedalpn", false, "randomized", true},
		{"hellochrome_auto", false, "chrome", true},
		{"helloios_auto", true, "ios", true},
		{"hellofirefox_120", false, "firefox", true},
		{"helloandroid_11_okhttp", false, "android", true},
		{"chrome_psk", false, "chrome", true},
		{"qwerty", false, "chrome", true},
	}
	for _, c := range cases {
		got, ok := utlsFingerprint(c.fp, c.reality)
		if got != c.want || ok != c.ok {
			t.Errorf("utlsFingerprint(%q, %v) = %q, %v; want %q, %v", c.fp, c.reality, got, ok, c.want, c.ok)
		}
	}
}

// The finding's mixed text: every node is reported, with its name and a
// Russian reason, and nothing of the links comes back
func TestParseAllReportsEverySkip(t *testing.T) {
	text := strings.Join([]string{
		"vless://" + testUUID + "@192.0.2.10:443?security=tls&sni=example.com&fp=chrome#ok",
		"vless://" + testUUID + "@192.0.2.10:443?type=xhttp&security=tls#xhttp-node",
		"vless://" + testUUID + "@192.0.2.10:443?encryption=mlkem768x25519plus.native.0rtt." + testSecret + "#pq-node",
		"ssr://" + b64("192.0.2.90:8388:origin:aes-256-cfb:plain:"+testSecret),
		"tuic://" + testSecret + "@192.0.2.60:443#tuic-v4",
		// Not links: "wss://" contains "ss://", "vmess://" does too
		"wss://example.com/ws",
	}, "\n")
	outbounds, skipped, err := ParseAllReport(text)
	if err != nil {
		t.Fatalf("ParseAllReport: %v", err)
	}
	if len(outbounds) != 1 || outbounds[0].Tag() != "ok" {
		t.Fatalf("outbounds = %v", outbounds)
	}
	wantNames := []string{"xhttp-node", "pq-node", "ссылка 4", "tuic-v4"}
	if len(skipped) != len(wantNames) {
		t.Fatalf("skipped = %+v", skipped)
	}
	for i, sk := range skipped {
		if sk.Name != wantNames[i] {
			t.Errorf("skipped[%d].Name = %q, want %q", i, sk.Name, wantNames[i])
		}
		if !russian(sk.Reason) || strings.Contains(sk.Reason, testSecret) || strings.Contains(sk.Reason, testUUID) {
			t.Errorf("skipped[%d].Reason = %q", i, sk.Reason)
		}
	}
}

// A credential with an unescaped '#': what follows it is the rest of the
// credential and the server's address, not a name — the report numbers such
// a link instead
func TestSkippedLinkNameIsNoCredentialTail(t *testing.T) {
	tail := "tail-" + testSecret
	links := []string{
		"trojan://Passw0rd#" + tail + "@srv.example.com:443",
		"socks5://user:Passw0rd#" + tail + "@srv.example.com:1080",
		"vless://1111#" + tail + "-3333@srv.example.com:443",
		"hysteria2://Ab3dEf#" + tail + "@srv.example.com:443",
		// A head of digits is a port: without the check the user name was
		// the server and the tail the tag of an accepted node
		"socks5://user:2024#" + tail + "@srv.example.com:1080",
		"socks5://user:2024#" + tail + "@srv.example.com:1080#name",
		"hysteria://ab:12#" + tail + "@srv.example.com:443?protocol=udp&upmbps=10&downmbps=50",
	}
	text := "vless://" + testUUID + "@192.0.2.10:443?security=tls#ok\n" + strings.Join(links, "\n")
	outbounds, skipped, err := ParseAllReport(text)
	if err != nil {
		t.Fatalf("ParseAllReport: %v", err)
	}
	if len(outbounds) != 1 || len(skipped) != len(links) {
		t.Fatalf("outbounds %v, skipped %+v", outbounds, skipped)
	}
	for i, sk := range skipped {
		if want := fmt.Sprintf("ссылка %d", i+2); sk.Name != want {
			t.Errorf("skipped[%d].Name = %q, want %q", i, sk.Name, want)
		}
	}
	for _, link := range links {
		if _, err := Parse(link); err == nil || strings.Contains(err.Error(), testSecret) {
			t.Errorf("Parse: %v", err)
		}
	}
}

// A value in the query with an unescaped '#': what net/url takes for the
// name is the rest of the value — often a credential — and of the query. No
// node gets it as its tag (the link is refused: its parameters after the
// '#' are lost), and the report numbers the link instead of naming it so
func TestQueryCutByHashIsNoName(t *testing.T) {
	const damaged = "символ «#» в значении параметра должен быть закодирован (%23)"
	links := []struct{ link, reason string }{
		// Accepted before: the obfs password cut short, the tail the tag
		{"hysteria2://pw@192.0.2.50:443?obfs=salamander&obfs-password=Ob#" + testSecret + "&sni=example.com", damaged},
		// net/url's fragment runs from the first '#': a name after it does
		// not make the rest a name
		{"hysteria2://pw@192.0.2.50:443?obfs=salamander&obfs-password=Ob#" + testSecret + "&sni=example.com#RealName", damaged},
		{"hysteria2://pw@192.0.2.50:443?obfs=salamander&obfs-password=Ob#" + testSecret + "#" + testSecret, damaged},
		{"vless://" + testUUID + "@192.0.2.10:443?security=reality&pbk=" + testPBK + "#" + testSecret + "&sid=6ba85179&sni=example.com&fp=chrome", damaged},
		// Refused for what the '#' cut off: still no name
		{"hysteria://192.0.2.70:8443?protocol=udp&auth=Pa#" + testSecret + "&upmbps=10&downmbps=50", "скорость"},
		{"hysteria2://pw@192.0.2.50:443?obfs=salamander&obfs-password=#" + testSecret + "&sni=example.com", "obfs-password"},
	}
	var texts []string
	for _, l := range links {
		texts = append(texts, l.link)
	}
	text := "vless://" + testUUID + "@192.0.2.10:443?security=tls#ok\n" + strings.Join(texts, "\n")
	outbounds, skipped, err := ParseAllReport(text)
	if err != nil {
		t.Fatalf("ParseAllReport: %v", err)
	}
	if len(outbounds) != 1 || len(skipped) != len(links) {
		t.Fatalf("outbounds %v, skipped %+v", outbounds, skipped)
	}
	for i, sk := range skipped {
		if want := fmt.Sprintf("ссылка %d", i+2); sk.Name != want {
			t.Errorf("skipped[%d].Name = %q, want %q", i, sk.Name, want)
		}
		if !strings.Contains(sk.Reason, links[i].reason) || strings.Contains(sk.Reason, testSecret) {
			t.Errorf("skipped[%d].Reason = %q, want %q", i, sk.Reason, links[i].reason)
		}
	}
	// A single link: refused without a name
	for _, l := range links {
		if o, err := Parse(l.link); err == nil || strings.HasPrefix(err.Error(), "узел") || strings.Contains(err.Error(), testSecret) {
			t.Errorf("Parse = %v, %v", o, err)
		}
	}
}

func TestParseAllNothingImportedListsTheReasons(t *testing.T) {
	text := "vless://" + testUUID + "@192.0.2.10:443?type=kcp#first\n" +
		"hysteria2://" + testSecret + "@192.0.2.50:443,x/#second\n" +
		"wireguard://" + testSecret + "@192.0.2.91:51820#third"
	outbounds, skipped, err := ParseAllReport(text)
	if err == nil {
		t.Fatalf("parsed %v", outbounds)
	}
	msg := err.Error()
	for _, want := range []string{"«first» — транспорт mKCP", "«second» — список портов", "«third» — ссылки WireGuard"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not contain %q", msg, want)
		}
	}
	if strings.Contains(msg, testSecret) || strings.Contains(msg, testUUID) {
		t.Errorf("error quotes a link: %q", msg)
	}
	if len(skipped) != 3 {
		t.Errorf("skipped = %+v", skipped)
	}

	// The domain adapter hands the skips over with the error too
	if _, skipped, err := (Parser{}).Parse(text); err == nil || len(skipped) != 3 {
		t.Errorf("Parser.Parse: %v, %+v", err, skipped)
	}

	// Many refusals: the first few and a count
	var many []string
	for i := range 8 {
		many = append(many, fmt.Sprintf("ssr://x#n%d", i))
	}
	_, _, err = ParseAllReport(strings.Join(many, "\n"))
	if err == nil || !strings.Contains(err.Error(), "и ещё 3") {
		t.Errorf("error = %v", err)
	}
}

// A subscription body with the newer schemes: nothing vanishes
func TestSubscriptionWithNewSchemes(t *testing.T) {
	body := b64(strings.Join([]string{
		"vless://" + testUUID + "@192.0.2.10:443?security=tls&sni=example.com#n1",
		"tuic://" + testUUID + ":pass@192.0.2.60:443?congestion_control=bbr&alpn=h3&sni=example.com#n2",
		"anytls://letmein@192.0.2.61/?sni=example.com#n3",
		"hysteria2://letmein@192.0.2.50:443,20000-30000/?sni=example.com#n4",
		"vless://" + testUUID + "@192.0.2.10:443?type=xhttp&security=tls#n5",
	}, "\n"))
	outbounds, skipped, err := ParseAllReport(body)
	if err != nil {
		t.Fatalf("ParseAllReport: %v", err)
	}
	var tags []string
	for _, o := range outbounds {
		tags = append(tags, o.Tag())
	}
	if strings.Join(tags, ",") != "n1,n2,n3,n4" {
		t.Errorf("tags = %v", tags)
	}
	if len(skipped) != 1 || skipped[0].Name != "n5" {
		t.Errorf("skipped = %+v", skipped)
	}
}

func TestExtractLinksAtWordStart(t *testing.T) {
	text := "wss://example.com/ws (vless://u@h:1#a) xvless://u@h:2 vmess://abc naive+https://u:p@h:3 ss://x"
	got := extractLinks(text)
	want := []string{"vless://u@h:1#a)", "vmess://abc", "naive+https://u:p@h:3", "ss://x"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("extractLinks = %q, want %q", got, want)
	}
}

// Links glued together without a line break: a scheme in a link's name, its
// query or a vmess body starts the next link — the longest one ending at its
// "://", when what follows looks like a link — so no credential of the next
// link becomes a node name or a value of the first one
func TestGluedLinksAreTakenApart(t *testing.T) {
	const b64 = "eyJhZGQiOiIxOTIuMC4yLjIwIn0"
	cases := []struct {
		text string
		want []string
	}{
		{"vless://u@h:1#avmess://" + b64, []string{"vless://u@h:1#a", "vmess://" + b64}},
		{"vless://u@h:1#nssr://" + b64 + "#m", []string{"vless://u@h:1#n", "ssr://" + b64 + "#m"}},
		{"vless://u@h:1#hysteria2://x", []string{"vless://u@h:1#", "hysteria2://x"}},
		// A '#' in the credential: the name is still searched from there
		{"trojan://Pass#word@h:2#ntrojan://p2@h:3", []string{"trojan://Pass#word@h:2#n", "trojan://p2@h:3"}},
		// A link without a name: glued into its last value
		{"vless://u@h:1?security=tls&sni=example.comtrojan://S3cret@h:3#n2", []string{"vless://u@h:1?security=tls&sni=example.com", "trojan://S3cret@h:3#n2"}},
		{"vless://u@h:1?type=ws&path=/wstrojan://S3cret@h:3", []string{"vless://u@h:1?type=ws&path=/ws", "trojan://S3cret@h:3"}},
		{"vmess://" + b64 + "trojan://S3cret@h:3#n2", []string{"vmess://" + b64, "trojan://S3cret@h:3#n2"}},
		// Not the start of a link: an address mentioned in the name (wss://
		// is no ss:// link), a path in a value
		{"vless://u@h:1#see-https://example.com/x", []string{"vless://u@h:1#see-https://example.com/x"}},
		{"vless://u@h:1#see-wss://cdn.example/ws", []string{"vless://u@h:1#see-wss://cdn.example/ws"}},
		{"vless://u@h:1?path=/vless://x#n", []string{"vless://u@h:1?path=/vless://x#n"}},
	}
	for _, c := range cases {
		if got := extractLinks(c.text); !reflect.DeepEqual(got, c.want) {
			t.Errorf("extractLinks(%q) = %q, want %q", c.text, got, c.want)
		}
	}

	text := "hysteria2://letmein@192.0.2.50:443#name1" +
		"hysteria2://" + testSecret + "@192.0.2.51:443#name2" +
		"vless://" + testUUID + "@192.0.2.10:443?type=kcp#name3" +
		vmessJSON(`{"ps":"name4","add":"192.0.2.20","port":443,"id":"`+testUUID+`","tls":"tls"}`)
	outbounds, skipped, err := ParseAllReport(text)
	if err != nil {
		t.Fatalf("ParseAllReport: %v", err)
	}
	var tags []string
	for _, o := range outbounds {
		tags = append(tags, o.Tag())
	}
	if want := []string{"name1", "name2", "name4"}; !reflect.DeepEqual(tags, want) {
		t.Fatalf("tags %q, want %q", tags, want)
	}
	if outbounds[0]["password"] != "letmein" || outbounds[1]["password"] != testSecret || outbounds[1]["server"] != "192.0.2.51" {
		t.Errorf("outbounds %v", outbounds)
	}
	if len(skipped) != 1 || skipped[0].Name != "name3" || !strings.Contains(skipped[0].Reason, "mKCP") {
		t.Errorf("skipped = %+v", skipped)
	}
}

func TestNoLinksErrorIsRussian(t *testing.T) {
	_, _, err := ParseAllReport("просто текст без ссылок")
	if err == nil || !russian(err.Error()) {
		t.Errorf("error = %v", err)
	}
	if _, err := ParseAny("https://example.com/sub"); err == nil || !russian(err.Error()) {
		t.Errorf("ParseAny error = %v", err)
	}
}

// The samples' secrets never come back in a refusal, whatever path it takes
func TestNoSampleSecretInReasons(t *testing.T) {
	secrets := []string{testSecret, testUUID, testPBK, "0123456789abcdef01", "letmein"}
	var texts []string
	for _, c := range refusedLinks {
		texts = append(texts, c.link)
	}
	for _, c := range acceptedLinks {
		texts = append(texts, c.link)
	}
	for _, body := range profileSamples {
		texts = append(texts, body)
	}
	texts = append(texts, strings.Join(texts, "\n"))
	for _, text := range texts {
		_, skipped, err := ParseAllReport(text)
		var said []string
		if err != nil {
			said = append(said, err.Error())
		}
		for _, sk := range skipped {
			said = append(said, sk.Name, sk.Reason)
		}
		if _, err := Parse(text); err != nil {
			said = append(said, err.Error())
		}
		for _, s := range said {
			for _, secret := range secrets {
				if strings.Contains(s, secret) {
					t.Errorf("%q gives away a secret of the sample", s)
				}
			}
		}
	}
}
