package sharelink

import (
	"encoding/json"
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
	// Keys as sing-box reads them, not as they are spelled
	"folded keys": `[
	  {"type": "vless", "tag": "R", "Server": "192.0.2.60", "server_port": 443, "UUID": "` + testUUID + `", "Flow": "xtls-rprx-vision",
	   "TLS": {"Enabled": true, "Server_Name": "www.example.com", "Reality": {"Enabled": true, "Public_Key": "` + testPBK + `", "Short_Id": "6ba85179"}}},
	  {"type": "trojan", "tag": "T", "server": "192.0.2.61", "server_port": 443, "password": "pw", "Detour": "R"}
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

// sing-box reads keys case-insensitively: a key spelled otherwise is read as
// sing-box reads it, so the checks of a detour, a short_id or a plugin do not
// miss it; one option spelled two ways is refused (which one sing-box takes
// depends on the order in the text)
func TestProfileKeysReadAsSingBoxReadsThem(t *testing.T) {
	profile := `[
	  {"type": "vless", "tag": "chained-away", "server": "192.0.2.10", "server_port": 443, "uuid": "` + testUUID + `", "Detour": "MyVPN"},
	  {"type": "vless", "tag": "via-direct", "server": "192.0.2.11", "server_port": 443, "uuid": "` + testUUID + `", "DETOUR": "direct",
	   "Domain_Resolver": "dns-remote", "Transport": {"Type": "ws", "PATH": "/ws", "headers": {"Host": "example.com"}}},
	  {"type": "vless", "tag": "crash-sid", "server": "192.0.2.12", "server_port": 443, "uuid": "` + testUUID + `",
	   "TLS": {"enabled": true, "utls": {"enabled": true, "fingerprint": "chrome"},
	           "Reality": {"Enabled": true, "public_key": "` + testPBK + `", "ſhort_id": "00112233445566778899"}}},
	  {"type": "vless", "tag": "reality", "server": "192.0.2.13", "server_port": 443, "uuid": "` + testUUID + `", "Flow": "xtls-rprx-vision-udp443",
	   "tls": {"Enabled": true, "Reality": {"ENABLED": true, "Public_Key": "` + testPBK + `", "short_id": "6ba85179"}}},
	  {"type": "vless", "tag": "twice", "server": "192.0.2.14", "server_port": 443, "uuid": "` + testUUID + `", "detour": "via-direct", "Detour": "reality"},
	  {"Type": "trojan", "Tag": "folded-type", "server": "192.0.2.15", "server_port": 443, "password": "pw"},
	  {"type": "direct", "tag": "direct"}
	]`
	outbounds, skipped, err := ParseAllReport(profile)
	if err != nil {
		t.Fatalf("ParseAllReport: %v", err)
	}
	byTag := map[string]Outbound{}
	for _, o := range outbounds {
		byTag[o.Tag()] = o
	}
	if len(outbounds) != 3 || byTag["via-direct"] == nil || byTag["reality"] == nil || byTag["folded-type"] == nil {
		t.Fatalf("imported %v", outbounds)
	}
	checkOutbound(t, byTag["via-direct"], `{"detour":null,"DETOUR":null,"domain_resolver":null,"Domain_Resolver":null,
	  "transport":{"type":"ws","path":"/ws","headers":{"Host":"example.com"}}}`)
	checkOutbound(t, byTag["reality"], `{"flow":"xtls-rprx-vision","Flow":null,
	  "tls":{"enabled":true,"utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,"public_key":"`+testPBK+`","short_id":"6ba85179"}}}`)
	checkOutbound(t, byTag["folded-type"], `{"type":"trojan","tag":"folded-type","Type":null,"Tag":null}`)

	reasons := map[string]string{}
	for _, sk := range skipped {
		reasons[sk.Name] = sk.Reason
	}
	if !strings.Contains(reasons["chained-away"], "«MyVPN»") || !strings.Contains(reasons["crash-sid"], "short_id") ||
		!strings.Contains(reasons["twice"], "«detour»") || len(skipped) != 3 {
		t.Fatalf("skipped = %+v", skipped)
	}
}

// A detour ring passes sing-box check and sing-box then does not start: the
// nodes of the ring are left out, and so are the ones chained into it
func TestProfileDetourRing(t *testing.T) {
	trojan := func(tag, detour string) string {
		return `{"type": "trojan", "tag": "` + tag + `", "server": "192.0.2.30", "server_port": 443, "password": "pw", "detour": "` + detour + `"}`
	}
	profile := "[" + strings.Join([]string{
		trojan("C", "D"), trojan("D", "C"), trojan("E", "C"), trojan("self", "self"),
		`{"type": "trojan", "tag": "ok", "server": "192.0.2.31", "server_port": 443, "password": "pw"}`, trojan("ok-chained", "ok"),
	}, ",") + "]"
	outbounds, skipped, err := ParseAllReport(profile)
	if err != nil {
		t.Fatalf("ParseAllReport: %v", err)
	}
	if len(outbounds) != 2 || outbounds[0].Tag() != "ok" || outbounds[1].Tag() != "ok-chained" {
		t.Fatalf("imported %v", outbounds)
	}
	reasons := map[string]string{}
	for _, sk := range skipped {
		reasons[sk.Name] = sk.Reason
	}
	if len(skipped) != 4 || !strings.Contains(reasons["C"], "кольцо") || !strings.Contains(reasons["D"], "кольцо") ||
		!strings.Contains(reasons["self"], "кольцо") || !strings.Contains(reasons["E"], "«C»") {
		t.Fatalf("skipped = %+v", skipped)
	}
}

// Hysteria 2 realm (a rendezvous server with a token) is refused, as the
// hysteria2+realm:// links are
func TestProfileHysteria2Realm(t *testing.T) {
	_, skipped, err := ParseAllReport(`[
	  {"type": "hysteria2", "tag": "h", "password": "pw", "tls": {"enabled": true, "server_name": "example.com"},
	   "Realm": {"server_url": "https://realm.example.com/x", "token": "` + testSecret + `", "realm_id": "r"}},
	  {"type": "hysteria2", "tag": "plain", "server": "192.0.2.50", "server_port": 443, "password": "pw"}
	]`)
	if err != nil || len(skipped) != 1 || skipped[0].Name != "h" || !strings.Contains(skipped[0].Reason, "realm") ||
		strings.Contains(skipped[0].Reason, testSecret) {
		t.Fatalf("skipped %+v, %v", skipped, err)
	}
}

// A provider's name reaches the popups: a skipped node is named on one line,
// shortened, like a skipped link — never by text that would read as the
// app's own
func TestProfileSkipNamesArePlain(t *testing.T) {
	fake := "x»\n\nВнимание! Подписка истекла.\n\n«y"
	long := strings.Repeat("Ж", 5000)
	quote := func(s string) string {
		b, _ := json.Marshal(s)
		return string(b)
	}
	profile := `{"outbounds": [
	  {"type": "tor", "tag": ` + quote(fake) + `},
	  {"type": "tor", "tag": ` + quote(long) + `},
	  {"type": "trojan", "tag": "chained", "server": "192.0.2.30", "server_port": 443, "password": "pw", "detour": ` + quote(fake) + `},
	  {"type": "trojan", "tag": "ok", "server": "192.0.2.31", "server_port": 443, "password": "pw"}
	], "endpoints": [{"type": "wireguard", "tag": ` + quote(fake) + `}]}`
	_, skipped, err := ParseAllReport(profile)
	if err != nil {
		t.Fatalf("ParseAllReport: %v", err)
	}
	sip008 := `{"version": 1, "servers": [{"remarks": ` + quote(fake) + `, "server": "192.0.2.40", "server_port": 8388, "method": "aes-256-gcm"},
	  {"remarks": "ok", "server": "192.0.2.41", "server_port": 8388, "password": "pw", "method": "aes-256-gcm"}]}`
	_, more, err := ParseAllReport(sip008)
	if err != nil {
		t.Fatalf("ParseAllReport: %v", err)
	}
	skipped = append(skipped, more...)

	names := []string{}
	for _, sk := range skipped {
		names = append(names, sk.Name)
		if !plainName(sk.Name) || !plainName(sk.Reason) || len([]rune(sk.Name)) > 101 || strings.Contains(sk.Reason, "Внимание") {
			t.Errorf("skipped %q: %q", sk.Name, sk.Reason)
		}
	}
	want := []string{"узел 1", strings.Repeat("Ж", 100) + "…", "chained", "endpoint 1", "узел 1"}
	if strings.Join(names, "|") != strings.Join(want, "|") {
		t.Fatalf("names = %q", names)
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
