package configfile

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every kind of credential in the spellings sing-box's decoder accepts
// (UUID, Password, LONG S, KELVIN SIGN), nested ones included. Every secret
// value starts with "secret-", every value that must stay visible with
// "visible-".
const secretsConfig = `{
  "log": {"level": "info"},
  "outbounds": [
    {"type": "selector", "tag": "proxy", "outbounds": ["vless-a", "trojan-b", "direct"]},
    {"type": "vless", "tag": "vless-a", "server": "a.example.com", "server_port": 443,
     "uuid": "secret-vless-uuid-A", "flow": "xtls-rprx-vision",
     "tls": {"enabled": true, "server_name": "a.example.com",
             "reality": {"enabled": true, "public_key": "visible-reality-public-key", "short_id": "visible-0123"}}},
    {"type": "trojan", "tag": "trojan-b", "server": "b.example.com", "server_port": 443,
     "Password": "secret-trojan-B", "tls": {"enabled": true, "insecure": false}},
    {"type": "vmess", "tag": "vmess-c", "server": "c.example.com", "server_port": 443, "UUID": "secret-vmess-C",
     "security": "auto",
     "transport": {"type": "ws", "path": "/ws", "headers": {"Host": "visible-host-C", "Authorization": "Bearer secret-header-C"}}},
    {"type": "hysteria2", "tag": "hy2-d", "server": "d.example.com", "server_port": 8443,
     "password": "secret-hy2-D", "obfs": {"type": "salamander", "password": "secret-obfs-D"}, "tls": {"enabled": true}},
    {"type": "hysteria", "tag": "hy1-e", "server": "e.example.com", "server_port": 443, "up_mbps": 100, "down_mbps": 100,
     "auth_str": "secret-auth-E", "obfs": "secret-obfs-E"},
    {"type": "wireguard", "tag": "wg-f", "server": "f.example.com", "server_port": 51820,
     "private_\u212Aey": "secret-wg-private-F", "peer_public_key": "visible-peer-public-key",
     "pre_\u017Fhared_key": "secret-wg-psk-F",
     "peers": [{"server": "f2.example.com", "server_port": 51820, "public_key": "visible-peer2-public-key",
                "pre_shared_key": "secret-wg-peer-psk-F"}]},
    {"type": "ssh", "tag": "ssh-g", "server": "g.example.com", "user": "visible-user-G",
     "private_key": ["secret-begin-G", "secret-ssh-key-line-G", "secret-end-G"],
     "private_key_passphrase": "secret-ssh-passphrase-G"},
    {"type": "shadowsocks", "tag": "ss-h", "server": "h.example.com", "server_port": 8388,
     "method": "2022-blake3-aes-128-gcm", "pa\u017F\u017Fword": "secret-ss-H"},
    {"type": "socks", "tag": "socks-i", "server": "127.0.0.1", "server_port": 1080,
     "username": "visible-user-I", "password": ""},
    {"type": "direct", "tag": "direct"}
  ],
  "route": {"rules": [{"protocol": "dns", "action": "hijack-dns"}], "final": "proxy"}
}`

// secretsMasked is the number of credential strings in secretsConfig (the
// ssh key has three lines, the empty socks password is not one)
const secretsMasked = 16

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func decodeNumbers(t *testing.T, text string) any {
	t.Helper()
	decoder := json.NewDecoder(strings.NewReader(text))
	decoder.UseNumber()
	var v any
	if err := decoder.Decode(&v); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, text)
	}
	return v
}

// fileSection returns a section of the config file as the editor loads it
func fileSection(t *testing.T, path, name string) any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return decodeNumbers(t, string(raw)).(map[string]any)[name]
}

// shape blanks every string value: two documents of the same shape differ
// in nothing else
func shape(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, child := range x {
			out[k] = shape(child)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, child := range x {
			out[i] = shape(child)
		}
		return out
	case string:
		return ""
	}
	return v
}

// editMasked saves a section the way the page does: the masked text, edited
func editMasked(t *testing.T, e *Editor, name string, edit func(section any) any) error {
	t.Helper()
	text, err := e.ReadSection(name)
	if err != nil {
		t.Fatalf("ReadSection: %v", err)
	}
	edited, err := marshalIndent(edit(decodeNumbers(t, text)))
	if err != nil {
		t.Fatal(err)
	}
	return e.WriteSection(name, edited)
}

func outboundIn(t *testing.T, list any, tag string) map[string]any {
	t.Helper()
	for _, it := range list.([]any) {
		if o := it.(map[string]any); o["tag"] == tag {
			return o
		}
	}
	t.Fatalf("no outbound %q", tag)
	return nil
}

// byTag maps every tagged outbound to its canonical text: equal maps, equal
// outbounds, whatever the order
func byTag(list any) map[string]string {
	out := map[string]string{}
	for _, it := range list.([]any) {
		o := it.(map[string]any)
		tag, _ := o["tag"].(string)
		out[tag] = canonical(o)
	}
	return out
}

func TestReadSectionMasksSecrets(t *testing.T) {
	path := writeConfig(t, secretsConfig)
	before, _ := os.ReadFile(path)
	e := New(path)

	text, err := e.ReadSection("outbounds")
	if err != nil {
		t.Fatalf("ReadSection: %v", err)
	}
	if strings.Contains(text, "secret-") {
		t.Fatalf("a secret reached the display text:\n%s", text)
	}
	for _, visible := range []string{
		"visible-reality-public-key", "visible-0123", "visible-host-C", "visible-peer-public-key",
		"visible-peer2-public-key", "visible-user-G", "visible-user-I",
	} {
		if !strings.Contains(text, visible) {
			t.Errorf("%s masked, it is not a secret", visible)
		}
	}
	if n := strings.Count(text, SecretPlaceholder); n != secretsMasked {
		t.Errorf("%d placeholders, want %d:\n%s", n, secretsMasked, text)
	}
	if !strings.Contains(text, `"password": ""`) {
		t.Error("an empty password must stay empty (nothing to hide)")
	}

	// Valid JSON of the same shape; apart from the secrets nothing changed
	masked := decodeNumbers(t, text)
	stored := fileSection(t, path, "outbounds")
	if canonical(shape(masked)) != canonical(shape(stored)) {
		t.Fatalf("masked shape differs:\n%s\n%s", canonical(shape(masked)), canonical(shape(stored)))
	}
	if canonical(stripSecrets(masked)) != canonical(stripSecrets(stored)) {
		t.Fatal("masking changed more than the secrets")
	}

	route, err := e.ReadSection("route")
	if err != nil || strings.Contains(route, SecretPlaceholder) || !strings.Contains(route, `"final": "proxy"`) {
		t.Fatalf("route: %v\n%s", err, route)
	}

	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("ReadSection modified the file")
	}
}

// The page's everyday save: the masked text as it was, or with an unrelated
// edit — every real secret must survive byte for byte
func TestWriteSectionKeepsMaskedSecrets(t *testing.T) {
	path := writeConfig(t, secretsConfig)
	e := New(path)
	original := decodeNumbers(t, secretsConfig).(map[string]any)["outbounds"]

	text, err := e.ReadSection("outbounds")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.WriteSection("outbounds", []byte(text)); err != nil {
		t.Fatalf("unchanged masked text refused: %v", err)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), SecretPlaceholder) {
		t.Fatalf("a placeholder reached the config:\n%s", raw)
	}
	if got := fileSection(t, path, "outbounds"); canonical(got) != canonical(original) {
		t.Fatalf("outbounds changed:\n%s\n%s", canonical(got), canonical(original))
	}

	// An edit of another outbound (the selector) keeps them as well
	err = editMasked(t, e, "outbounds", func(section any) any {
		outboundIn(t, section, "proxy")["default"] = "trojan-b"
		return section
	})
	if err != nil {
		t.Fatalf("edit of the selector refused: %v", err)
	}
	got := byTag(fileSection(t, path, "outbounds"))
	want := byTag(original)
	for tag, o := range want {
		if tag != "proxy" && got[tag] != o {
			t.Errorf("%s changed:\n%s\n%s", tag, got[tag], o)
		}
	}
}

// Anything else changed while a placeholder stays would send the stored
// credential somewhere new: refused, the file untouched
func TestWriteSectionRefusesChangedOutboundWithPlaceholder(t *testing.T) {
	cases := map[string]func(o map[string]any){
		"server":          func(o map[string]any) { o["server"] = "evil.example.com" },
		"server_port":     func(o map[string]any) { o["server_port"] = json.Number("8443") },
		"tls.insecure":    func(o map[string]any) { o["tls"].(map[string]any)["insecure"] = true },
		"tls.server_name": func(o map[string]any) { o["tls"].(map[string]any)["server_name"] = "evil.example.com" },
		"detour":          func(o map[string]any) { o["detour"] = "direct" },
		"transport":       func(o map[string]any) { o["transport"] = map[string]any{"type": "ws", "path": "/x"} },
		"type":            func(o map[string]any) { o["type"] = "shadowsocks" },
		"added key":       func(o map[string]any) { o["Server"] = "evil.example.com" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			path := writeConfig(t, secretsConfig)
			before, _ := os.ReadFile(path)
			err := editMasked(t, New(path), "outbounds", func(section any) any {
				change(outboundIn(t, section, "trojan-b"))
				return section
			})
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), "trojan-b") || !strings.Contains(err.Error(), "password") {
				t.Errorf("error does not name the server and the field: %v", err)
			}
			if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
				t.Fatal("config changed")
			}
		})
	}
}

// With every secret of the outbound typed anew, it may change freely
func TestWriteSectionAcceptsChangedOutboundWithTypedSecret(t *testing.T) {
	path := writeConfig(t, secretsConfig)
	e := New(path)
	err := editMasked(t, e, "outbounds", func(section any) any {
		o := outboundIn(t, section, "trojan-b")
		o["server"] = "new.example.com"
		o["Password"] = "typed-new-password"
		return section
	})
	if err != nil {
		t.Fatalf("refused: %v", err)
	}
	saved := fileSection(t, path, "outbounds")
	if o := outboundIn(t, saved, "trojan-b"); o["server"] != "new.example.com" || o["Password"] != "typed-new-password" {
		t.Fatalf("trojan-b = %v", o)
	}
	if o := outboundIn(t, saved, "vless-a"); o["uuid"] != "secret-vless-uuid-A" {
		t.Fatalf("another outbound lost its secret: %v", o)
	}

	// Only one of two secrets typed: the other would still go to the new
	// server
	before, _ := os.ReadFile(path)
	err = editMasked(t, e, "outbounds", func(section any) any {
		o := outboundIn(t, section, "hy2-d")
		o["server"] = "new.example.com"
		o["password"] = "typed-hy2-password"
		return section
	})
	if err == nil || !strings.Contains(err.Error(), "hy2-d") {
		t.Fatalf("obfs placeholder kept with a new server: %v", err)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Fatal("config changed")
	}
}

// A placeholder with nothing stored to restore it from
func TestWriteSectionRefusesUnmatchedPlaceholder(t *testing.T) {
	cases := map[string]func(section any) any{
		"new outbound": func(section any) any {
			return append(section.([]any), map[string]any{
				"type": "trojan", "tag": "new-node", "server": "x.example.com", "server_port": json.Number("443"),
				"password": SecretPlaceholder,
			})
		},
		"renamed tag": func(section any) any {
			outboundIn(t, section, "trojan-b")["tag"] = "trojan-renamed"
			return section
		},
		"no tag": func(section any) any {
			delete(outboundIn(t, section, "trojan-b"), "tag")
			return section
		},
		"field the stored outbound lacks": func(section any) any {
			outboundIn(t, section, "vless-a")["password"] = SecretPlaceholder
			return section
		},
		"line array grown": func(section any) any {
			o := outboundIn(t, section, "ssh-g")
			o["private_key"] = append(o["private_key"].([]any), SecretPlaceholder)
			return section
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			path := writeConfig(t, secretsConfig)
			before, _ := os.ReadFile(path)
			if err := editMasked(t, New(path), "outbounds", edit); err == nil {
				t.Fatal("accepted")
			}
			if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
				t.Fatal("config changed")
			}
		})
	}
}

// Placeholders follow their outbound by tag, not by position
func TestWriteSectionReorderedOutbounds(t *testing.T) {
	path := writeConfig(t, secretsConfig)
	err := editMasked(t, New(path), "outbounds", func(section any) any {
		list := section.([]any)
		for i, j := 0, len(list)-1; i < j; i, j = i+1, j-1 {
			list[i], list[j] = list[j], list[i]
		}
		return list
	})
	if err != nil {
		t.Fatalf("reordered outbounds refused: %v", err)
	}
	saved := fileSection(t, path, "outbounds").([]any)
	if saved[0].(map[string]any)["tag"] != "direct" {
		t.Fatalf("order not saved: %v", saved[0])
	}
	got, want := byTag(saved), byTag(decodeNumbers(t, secretsConfig).(map[string]any)["outbounds"])
	for tag, o := range want {
		if got[tag] != o {
			t.Errorf("%s changed:\n%s\n%s", tag, got[tag], o)
		}
	}
}

// The placeholder text at a key that holds no credential is ordinary data
func TestWriteSectionPlaceholderAtOrdinaryKey(t *testing.T) {
	path := writeConfig(t, secretsConfig)
	err := editMasked(t, New(path), "outbounds", func(section any) any {
		return append(section.([]any), map[string]any{
			"type": "vless", "tag": "literal", "server": SecretPlaceholder, "server_port": json.Number("443"),
			"uuid": "typed-uuid",
		})
	})
	if err != nil {
		t.Fatalf("refused: %v", err)
	}
	if o := outboundIn(t, fileSection(t, path, "outbounds"), "literal"); o["server"] != SecretPlaceholder || o["uuid"] != "typed-uuid" {
		t.Fatalf("literal = %v", o)
	}
}

// The detour chain decides where the handshake goes: a placeholder is not
// restored while an outbound it dials through was changed
func TestWriteSectionRefusesChangedDetourTarget(t *testing.T) {
	const chained = `{
  "outbounds": [
    {"type": "vless", "tag": "proxy", "server": "a.example.com", "server_port": 443, "uuid": "secret-dep-uuid", "detour": "chain"},
    {"type": "socks", "tag": "chain", "server": "127.0.0.1", "server_port": 1080, "detour": "dpi-bypass"},
    {"type": "http", "tag": "dpi-bypass", "server": "127.0.0.1", "server_port": 3128},
    {"type": "direct", "tag": "direct"}
  ],
  "route": {"final": "proxy"}
}`
	refused := map[string]func(section any) any{
		"detour target": func(section any) any {
			outboundIn(t, section, "chain")["server"] = "evil.example.com"
			return section
		},
		"transitive target": func(section any) any {
			outboundIn(t, section, "dpi-bypass")["server"] = "evil.example.com"
			return section
		},
		"target removed": func(section any) any {
			list := section.([]any)
			return append(list[:1:1], list[2:]...)
		},
		"second target with a folded tag key": func(section any) any {
			return append(section.([]any), map[string]any{
				"type": "http", "Tag": "dpi-bypass", "server": "evil.example.com", "server_port": json.Number("3128"),
			})
		},
	}
	for name, edit := range refused {
		t.Run(name, func(t *testing.T) {
			path := writeConfig(t, chained)
			before, _ := os.ReadFile(path)
			err := editMasked(t, New(path), "outbounds", edit)
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), "proxy") {
				t.Errorf("error does not name the server: %v", err)
			}
			if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
				t.Fatal("config changed")
			}
		})
	}

	accepted := map[string]func(section any) any{
		"unrelated outbound added": func(section any) any {
			return append(section.([]any), map[string]any{"type": "direct", "tag": "direct2"})
		},
		"target changed, secret typed": func(section any) any {
			outboundIn(t, section, "proxy")["uuid"] = "secret-dep-uuid"
			outboundIn(t, section, "dpi-bypass")["server_port"] = json.Number("3129")
			return section
		},
	}
	for name, edit := range accepted {
		t.Run(name, func(t *testing.T) {
			path := writeConfig(t, chained)
			if err := editMasked(t, New(path), "outbounds", edit); err != nil {
				t.Fatalf("refused: %v", err)
			}
			if o := outboundIn(t, fileSection(t, path, "outbounds"), "proxy"); o["uuid"] != "secret-dep-uuid" {
				t.Fatalf("proxy = %v", o)
			}
		})
	}
}

func TestWriteSectionRouteRoundTrip(t *testing.T) {
	path := writeConfig(t, secretsConfig)
	e := New(path)
	text, err := e.ReadSection("route")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.WriteSection("route", []byte(text)); err != nil {
		t.Fatalf("route refused: %v", err)
	}
	want := decodeNumbers(t, secretsConfig).(map[string]any)["route"]
	if got := fileSection(t, path, "route"); canonical(got) != canonical(want) {
		t.Fatalf("route changed:\n%s\n%s", canonical(got), canonical(want))
	}
}

// An object section follows the same rule as an outbound, as a whole (a
// route normally holds no credential; this one does to exercise the path)
func TestWriteSectionObjectSectionPlaceholder(t *testing.T) {
	const withSecret = `{
  "outbounds": [{"type": "direct", "tag": "direct"}],
  "route": {"rule_set": [{"type": "remote", "tag": "r", "url": "https://rules.example.com/r.srs", "password": "secret-route-R"}],
            "final": "direct"}
}`
	path := writeConfig(t, withSecret)
	e := New(path)
	text, err := e.ReadSection("route")
	if err != nil || strings.Contains(text, "secret-") {
		t.Fatalf("route not masked: %v\n%s", err, text)
	}
	if err := e.WriteSection("route", []byte(text)); err != nil {
		t.Fatalf("route refused: %v", err)
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), "secret-route-R") {
		t.Fatalf("route secret lost:\n%s", raw)
	}

	before := raw
	err = editMasked(t, e, "route", func(section any) any {
		section.(map[string]any)["final"] = "other"
		return section
	})
	if err == nil || !strings.Contains(err.Error(), "route") {
		t.Fatalf("changed route with a placeholder: %v", err)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Fatal("config changed")
	}
}
