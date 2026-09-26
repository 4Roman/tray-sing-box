package sharelink

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestParseVLESSReality(t *testing.T) {
	link := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443" +
		"?type=tcp&security=reality&sni=cdn.example.org&fp=chrome&pbk=PUBKEY&sid=6ba85179&flow=xtls-rprx-vision#My%20Server"

	o, err := Parse(link)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if o["type"] != "vless" || o["server"] != "example.com" || o["server_port"] != 443 {
		t.Fatalf("basic fields wrong: %v", o)
	}
	if o.Tag() != "My Server" {
		t.Fatalf("tag = %q", o.Tag())
	}
	if o["flow"] != "xtls-rprx-vision" {
		t.Fatalf("flow = %v", o["flow"])
	}
	tls := o["tls"].(map[string]any)
	if tls["server_name"] != "cdn.example.org" {
		t.Fatalf("server_name = %v", tls["server_name"])
	}
	reality := tls["reality"].(map[string]any)
	if reality["public_key"] != "PUBKEY" || reality["short_id"] != "6ba85179" {
		t.Fatalf("reality = %v", reality)
	}
	utls := tls["utls"].(map[string]any)
	if utls["fingerprint"] != "chrome" {
		t.Fatalf("utls = %v", utls)
	}
}

func TestParseVLESSWebsocket(t *testing.T) {
	link := "vless://uuid-1@1.2.3.4:8443?type=ws&security=tls&path=%2Fws&host=cdn.example.org#ws-node"

	o, err := Parse(link)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	transport := o["transport"].(map[string]any)
	if transport["type"] != "ws" || transport["path"] != "/ws" {
		t.Fatalf("transport = %v", transport)
	}
	headers := transport["headers"].(map[string]any)
	if headers["Host"] != "cdn.example.org" {
		t.Fatalf("headers = %v", headers)
	}
}

func TestParseVMess(t *testing.T) {
	payload := `{"v":"2","ps":"vmess node","add":"5.6.7.8","port":"443","id":"uuid-2",` +
		`"aid":"0","scy":"auto","net":"ws","host":"cdn.example.com","path":"/path","tls":"tls","sni":"sni.example.com"}`
	link := "vmess://" + base64.StdEncoding.EncodeToString([]byte(payload))

	o, err := Parse(link)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if o["type"] != "vmess" || o["server"] != "5.6.7.8" || o["server_port"] != 443 {
		t.Fatalf("basic fields wrong: %v", o)
	}
	if o.Tag() != "vmess node" || o["uuid"] != "uuid-2" || o["alter_id"] != 0 {
		t.Fatalf("fields wrong: %v", o)
	}
	tls := o["tls"].(map[string]any)
	if tls["server_name"] != "sni.example.com" {
		t.Fatalf("tls = %v", tls)
	}
	transport := o["transport"].(map[string]any)
	if transport["type"] != "ws" || transport["path"] != "/path" {
		t.Fatalf("transport = %v", transport)
	}
}

func TestParseVMessNumericPort(t *testing.T) {
	payload := `{"ps":"n","add":"h.example.com","port":8080,"id":"u","aid":0,"net":"tcp","tls":""}`
	link := "vmess://" + base64.RawURLEncoding.EncodeToString([]byte(payload))

	o, err := Parse(link)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if o["server_port"] != 8080 {
		t.Fatalf("port = %v", o["server_port"])
	}
	if _, hasTLS := o["tls"]; hasTLS {
		t.Fatal("tls should be absent")
	}
}

func TestParseTrojan(t *testing.T) {
	link := "trojan://secret@9.9.9.9:443?sni=t.example.com#trojan-node"

	o, err := Parse(link)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if o["type"] != "trojan" || o["password"] != "secret" {
		t.Fatalf("fields wrong: %v", o)
	}
	tls := o["tls"].(map[string]any)
	if tls["enabled"] != true || tls["server_name"] != "t.example.com" {
		t.Fatalf("trojan must default to TLS with sni: %v", tls)
	}
}

func TestParseShadowsocksSIP002(t *testing.T) {
	userinfo := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pass-123"))
	link := "ss://" + userinfo + "@10.0.0.1:8388#ss-node"

	o, err := Parse(link)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if o["method"] != "aes-256-gcm" || o["password"] != "pass-123" {
		t.Fatalf("credentials wrong: %v", o)
	}
	if o["server"] != "10.0.0.1" || o["server_port"] != 8388 {
		t.Fatalf("server wrong: %v", o)
	}
}

func TestParseShadowsocksLegacy(t *testing.T) {
	body := base64.StdEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:pw@11.0.0.1:8389"))
	link := "ss://" + body + "#legacy"

	o, err := Parse(link)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if o["method"] != "chacha20-ietf-poly1305" || o["password"] != "pw" {
		t.Fatalf("credentials wrong: %v", o)
	}
	if o["server"] != "11.0.0.1" || o["server_port"] != 8389 || o.Tag() != "legacy" {
		t.Fatalf("server wrong: %v", o)
	}
}

func TestParseHysteria2(t *testing.T) {
	link := "hy2://authpass@12.0.0.1:4443?sni=h.example.com&insecure=1&obfs=salamander&obfs-password=op#hy2-node"

	o, err := Parse(link)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if o["type"] != "hysteria2" || o["password"] != "authpass" {
		t.Fatalf("fields wrong: %v", o)
	}
	tls := o["tls"].(map[string]any)
	if tls["server_name"] != "h.example.com" || tls["insecure"] != true {
		t.Fatalf("tls wrong: %v", tls)
	}
	obfs := o["obfs"].(map[string]any)
	if obfs["type"] != "salamander" || obfs["password"] != "op" {
		t.Fatalf("obfs wrong: %v", obfs)
	}
}

func TestParseAnyExtractsLinkFromNoise(t *testing.T) {
	text := "вот сервер:\nvless://u@h.example.com:443?security=tls#x\nспасибо"

	o, err := ParseAny(text)
	if err != nil {
		t.Fatalf("ParseAny: %v", err)
	}
	if o["server"] != "h.example.com" {
		t.Fatalf("server = %v", o["server"])
	}
}

func TestParseAllMultipleLinks(t *testing.T) {
	text := "vless://u1@a.example.com:443?security=tls#node\n" +
		"trojan://pw@b.example.com:443#node\n" + // duplicate tag
		"hy2://pw@c.example.com:443#third\n"

	outbounds, err := ParseAll(text)
	if err != nil {
		t.Fatalf("ParseAll: %v", err)
	}
	if len(outbounds) != 3 {
		t.Fatalf("got %d outbounds", len(outbounds))
	}
	if outbounds[0].Tag() != "node" || outbounds[1].Tag() != "node (2)" {
		t.Fatalf("duplicate tags not disambiguated: %q, %q", outbounds[0].Tag(), outbounds[1].Tag())
	}
}

func TestParseAllBase64Subscription(t *testing.T) {
	plain := "vless://u1@a.example.com:443?security=tls#first\nss://" +
		base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pw")) + "@b.example.com:8388#second\n"
	blob := base64.StdEncoding.EncodeToString([]byte(plain))

	outbounds, err := ParseAll(blob)
	if err != nil {
		t.Fatalf("ParseAll: %v", err)
	}
	if len(outbounds) != 2 {
		t.Fatalf("got %d outbounds: %v", len(outbounds), outbounds)
	}
	if outbounds[0].Tag() != "first" || outbounds[1].Tag() != "second" {
		t.Fatalf("tags wrong: %q, %q", outbounds[0].Tag(), outbounds[1].Tag())
	}
}

func TestParseAllSkipsBrokenLinks(t *testing.T) {
	text := "vless://broken-no-port@x\nvless://ok@a.example.com:443?security=tls#good"

	outbounds, err := ParseAll(text)
	if err != nil {
		t.Fatalf("ParseAll: %v", err)
	}
	if len(outbounds) != 1 || outbounds[0].Tag() != "good" {
		t.Fatalf("outbounds = %v", outbounds)
	}
}

func TestParseRejectsUnsupported(t *testing.T) {
	if _, err := Parse("http://example.com"); err == nil {
		t.Fatal("expected error for unsupported scheme")
	}
	if _, err := ParseAny("просто текст без ссылок"); err == nil {
		t.Fatal("expected error for text without links")
	}
	if _, err := Parse("vless://u@h:0?x=1"); err == nil {
		t.Fatal("expected error for invalid port")
	}
}

// A link that fails to parse must not come back in the error: net/url quotes
// its whole input, and the error text reaches the log and the settings page
func TestParseErrorsDoNotQuoteTheLink(t *testing.T) {
	const secret = "S3CRET-b831381d"
	legacy := base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:" + secret + "@host:bad port"))
	links := []string{
		"vless://" + secret + "@host:bad/%zz",
		"trojan://" + secret + "@host/%zz",
		"ss://" + base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:"+secret)) + "@host/%zz",
		"ss://" + legacy,
		"hysteria2://" + secret + "@host/%zz",
		"ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pw")) + "@host:8388?plugin=ck-client%3BUID%3D" + secret,
		"vmess://" + base64.StdEncoding.EncodeToString([]byte(`{"add":"host","port":"`+secret+`","id":"u"}`)),
		"vmess://" + base64.StdEncoding.EncodeToString([]byte(`{"add":"host","port":443,"aid":"`+secret+`","id":"u"}`)),
	}
	for _, link := range links {
		_, err := Parse(link)
		if err == nil {
			t.Errorf("%s: parsed, want an error", link)
			continue
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("error quotes the link's credential: %v", err)
		}
		_, skipped, err := (Parser{}).Parse(link)
		if err != nil && strings.Contains(err.Error(), secret) {
			t.Errorf("Parser.Parse error quotes the link's credential: %v", err)
		}
		for _, sk := range skipped {
			if strings.Contains(sk.Name+" "+sk.Reason, secret) {
				t.Errorf("the skipped-link report quotes the link's credential: %+v", sk)
			}
		}
	}
}

// A legacy link whose password contains '/' (base64-generated passwords do):
// the decoded "method:password@host:port" is not a valid URL authority as is
func TestParseLegacyShadowsocksPasswordWithSlash(t *testing.T) {
	const password = "Ab3/xYz+9Q=="
	link := "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:"+password+"@ss.example.com:8388")) + "#legacy"
	o, err := Parse(link)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if o["password"] != password || o["method"] != "aes-256-gcm" || o["server"] != "ss.example.com" || o["server_port"] != 8388 || o.Tag() != "legacy" {
		t.Fatalf("parsed %v", o)
	}
}
