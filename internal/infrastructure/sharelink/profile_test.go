package sharelink

import (
	"errors"
	"strings"
	"testing"
)

// A full sing-box config as the panels serve it at their "sing-box" URLs,
// with the nodes an import must leave out
const singBoxProfile = `{
  "log": {"level": "warn"},
  "dns": {"servers": [{"tag": "dns-remote", "type": "https", "server": "1.1.1.1"}]},
  "inbounds": [{"type": "tun", "tag": "tun-in"}],
  "outbounds": [
    {"type": "selector", "tag": "proxy", "outbounds": ["DE", "NL"]},
    {"type": "urltest", "tag": "auto", "outbounds": ["DE", "NL"]},
    {"type": "vless", "tag": "DE", "server": "192.0.2.10", "server_port": 443, "uuid": "` + testUUID + `",
     "flow": "xtls-rprx-vision-udp443", "domain_resolver": "dns-remote",
     "tls": {"enabled": true, "server_name": "www.example.com",
             "reality": {"enabled": true, "public_key": "` + testPBK + `", "short_id": "6ba85179"}}},
    {"type": "trojan", "tag": "NL", "server": "192.0.2.30", "server_port": 443, "password": "pw", "detour": "direct",
     "tls": {"enabled": true, "server_name": "example.com", "utls": {"enabled": true, "fingerprint": "randomizednoalpn"}}},
    {"type": "shadowtls", "tag": "stls", "server": "192.0.2.31", "server_port": 443, "version": 3, "password": "pw",
     "tls": {"enabled": true, "server_name": "example.com"}},
    {"type": "shadowsocks", "tag": "ss-stls", "server": "192.0.2.31", "server_port": 443,
     "method": "2022-blake3-aes-128-gcm", "password": "MDEyMzQ1Njc4OWFiY2RlZg==", "detour": "stls"},
    {"type": "vmess", "tag": "chained-missing", "server": "192.0.2.20", "server_port": 443, "uuid": "` + testUUID + `", "detour": "gone"},
    {"type": "vless", "tag": "long-sid", "server": "192.0.2.10", "server_port": 443, "uuid": "` + testUUID + `",
     "tls": {"enabled": true, "reality": {"enabled": true, "public_key": "` + testPBK + `", "short_id": "0123456789abcdef01"}}},
    {"type": "trojan", "tag": "cert-file", "server": "192.0.2.30", "server_port": 443, "password": "pw",
     "tls": {"enabled": true, "Certificate_Path": "` + testSecret + `.pem"}},
    {"type": "shadowsocks", "tag": "ss-v2ray-cert", "server": "192.0.2.40", "server_port": 443, "method": "aes-256-gcm",
     "password": "pw", "plugin": "v2ray-plugin", "plugin_opts": "tls;cert=/etc/` + testSecret + `.pem"},
    {"type": "tor", "tag": "tor-out"},
    {"type": "wireguard", "tag": "wg-old"},
    {"type": "direct", "tag": "direct"},
    {"type": "block", "tag": "block"},
    {"type": "dns", "tag": "dns-out"}
  ],
  "endpoints": [{"type": "wireguard", "tag": "wg-ep", "private_key": "` + testSecret + `"}],
  "route": {"final": "proxy"}
}`

// profileSamples are the profiles whose nodes must pass `sing-box check`
var profileSamples = map[string]string{
	"sing-box config": singBoxProfile,
	"bare outbounds": `[
	  {"type": "hysteria2", "tag": "hy2", "server": "192.0.2.50", "server_port": 443, "password": "pw",
	   "tls": {"enabled": true, "server_name": "example.com"}},
	  {"type": "direct", "tag": "direct"}
	]`,
	"sip008": `{"version": 1, "servers": [
	  {"id": "27b8a625-4f4b-4428-9f0f-8a2317db7c79", "remarks": "ss-1", "server": "192.0.2.40", "server_port": 8388,
	   "password": "pw1", "method": "aes-256-gcm"},
	  {"remarks": "ss-obfs", "server": "192.0.2.41", "server_port": 8388, "password": "pw2", "method": "chacha20-ietf-poly1305",
	   "plugin": "simple-obfs", "plugin_opts": "obfs=http;obfs-host=example.com"},
	  {"remarks": "ss-ck", "server": "192.0.2.42", "server_port": 8388, "password": "pw3", "method": "aes-256-gcm",
	   "plugin": "ck-client", "plugin_opts": "UID=` + testSecret + `"},
	  {"server": "192.0.2.43", "server_port": "8389", "password": "pw4", "method": "aes-128-gcm"}
	], "bytes_used": 1}`,
}

func TestSingBoxProfile(t *testing.T) {
	outbounds, skipped, err := ParseAllReport(singBoxProfile)
	if err != nil {
		t.Fatalf("ParseAllReport: %v", err)
	}
	byTag := map[string]Outbound{}
	var tags []string
	for _, o := range outbounds {
		byTag[o.Tag()] = o
		tags = append(tags, o.Tag())
	}
	if strings.Join(tags, ",") != "DE,NL,stls,ss-stls" {
		t.Fatalf("imported %v", tags)
	}
	checkOutbound(t, byTag["DE"], `{"flow":"xtls-rprx-vision","domain_resolver":null,
	  "tls":{"utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"public_key":"`+testPBK+`"}}}`)
	checkOutbound(t, byTag["NL"], `{"detour":null,"tls":{"utls":{"fingerprint":"randomized"}}}`)
	checkOutbound(t, byTag["ss-stls"], `{"detour":"stls"}`)

	wantSkipped := map[string]string{
		"chained-missing": "«gone»",
		"long-sid":        "short_id",
		"cert-file":       "certificate_path",
		"ss-v2ray-cert":   "cert",
		"tor-out":         "«tor»",
		"wg-old":          "WireGuard",
		"wg-ep":           "endpoint",
	}
	if len(skipped) != len(wantSkipped) {
		t.Errorf("skipped = %+v", skipped)
	}
	for _, sk := range skipped {
		want, ok := wantSkipped[sk.Name]
		if !ok || !strings.Contains(sk.Reason, want) {
			t.Errorf("skipped %q: %q, want it to say %q", sk.Name, sk.Reason, want)
		}
		if !russian(sk.Reason) || strings.Contains(sk.Reason, testSecret) || strings.Contains(sk.Reason, "0123456789abcdef01") {
			t.Errorf("reason %q", sk.Reason)
		}
	}
}

func TestBareOutboundsAndBase64Profile(t *testing.T) {
	for _, text := range []string{profileSamples["bare outbounds"], b64(profileSamples["bare outbounds"])} {
		outbounds, skipped, err := ParseAllReport(text)
		if err != nil || len(outbounds) != 1 || outbounds[0].Tag() != "hy2" || len(skipped) != 0 {
			t.Errorf("got %v, %+v, %v", outbounds, skipped, err)
		}
	}
}

func TestSIP008(t *testing.T) {
	outbounds, skipped, err := ParseAllReport(profileSamples["sip008"])
	if err != nil {
		t.Fatalf("ParseAllReport: %v", err)
	}
	if len(outbounds) != 3 {
		t.Fatalf("outbounds = %v", outbounds)
	}
	checkOutbound(t, outbounds[0], `{"type":"shadowsocks","tag":"ss-1","server":"192.0.2.40","server_port":8388,
	  "method":"aes-256-gcm","password":"pw1","plugin":null,"id":null}`)
	checkOutbound(t, outbounds[1], `{"tag":"ss-obfs","plugin":"obfs-local","plugin_opts":"obfs=http;obfs-host=example.com"}`)
	checkOutbound(t, outbounds[2], `{"tag":"ss-192.0.2.43-8389","server_port":8389}`)
	if len(skipped) != 1 || skipped[0].Name != "ss-ck" || !strings.Contains(skipped[0].Reason, "ck-client") ||
		strings.Contains(skipped[0].Reason, testSecret) {
		t.Errorf("skipped = %+v", skipped)
	}
}

func TestForeignProfilesAreNamed(t *testing.T) {
	clash := "mixed-port: 7890\nproxies:\n  - name: \"DE\"\n    type: vless\n    server: 192.0.2.10\n    port: 443\n" +
		"    uuid: " + testUUID + "\nproxy-groups:\n  - name: proxy\n    type: select\n    proxies: [DE]\n"
	xray := `{"outbounds": [{"protocol": "vless", "tag": "proxy", "settings": {"vnext": [{"address": "192.0.2.10", "port": 443,
	  "users": [{"id": "` + testUUID + `", "encryption": "none"}]}]}}, {"protocol": "freedom", "tag": "direct"}]}`
	xrayArray := `[{"remarks": "DE", "outbounds": [{"protocol": "vless", "settings": {}}]}]`
	cases := []struct {
		text string
		want error
	}{
		{clash, errClashProfile},
		{b64(clash), errClashProfile},
		{xray, errXrayProfile},
		{xrayArray, errXrayProfile},
		{`{"outbounds": [{"type": "direct", "tag": "direct"}]}`, errEmptyProfile},
		{`{"hello": "world"}`, errNoLinks},
	}
	for _, c := range cases {
		_, _, err := ParseAllReport(c.text)
		if !errors.Is(err, c.want) {
			t.Errorf("%.40q: error %v, want %v", c.text, err, c.want)
		}
		if err != nil && strings.Contains(err.Error(), testUUID) {
			t.Errorf("error quotes the body: %v", err)
		}
	}
}

// A list of links is read as links even when a name has JSON-like characters
func TestLinksWithBracesStayLinks(t *testing.T) {
	text := "vless://" + testUUID + "@192.0.2.10:443?security=tls#{DE}\n" +
		"trojan://pw@192.0.2.30:443#[NL]"
	outbounds, err := ParseAll(text)
	if err != nil || len(outbounds) != 2 || outbounds[0].Tag() != "{DE}" || outbounds[1].Tag() != "[NL]" {
		t.Errorf("got %v, %v", outbounds, err)
	}
}
