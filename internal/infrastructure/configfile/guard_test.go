package configfile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func decode(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("%s: %v", s, err)
	}
	return m
}

func TestGuardRefusesNewRiskyConstructs(t *testing.T) {
	base := `{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}`
	refused := map[string]string{
		"tor outbound":        `{"outbounds":[{"type":"tor","tag":"t","executable_path":"C:\\x.exe"}]}`,
		"tor without paths":   `{"outbounds":[{"type":"tor","tag":"t"}]}`,
		"certificate path":    `{"outbounds":[{"type":"vless","tag":"v","tls":{"enabled":true,"certificate_path":"C:\\a.pem"}}]}`,
		"ssh key path":        `{"outbounds":[{"type":"ssh","tag":"s","private_key_path":"C:\\id"}]}`,
		"log output":          `{"log":{"output":"C:\\Windows\\x.log"},"outbounds":[]}`,
		"cache file path":     `{"experimental":{"cache_file":{"enabled":true,"path":"C:\\x.db"}},"outbounds":[]}`,
		"external ui":         `{"experimental":{"clash_api":{"external_ui":"C:\\ui","external_ui_download_url":"https://x/ui.zip"}},"outbounds":[]}`,
		"local rule set path": `{"route":{"rule_set":[{"type":"local","tag":"r","format":"binary","path":"C:\\x.srs"}]},"outbounds":[]}`,
		"rule set traversal":  `{"route":{"rule_set":[{"type":"local","tag":"r","path":"..\\x.srs"}]},"outbounds":[]}`,
		"geoip database":      `{"route":{"geoip":{"path":"C:\\x","download_url":"https://x"}},"outbounds":[]}`,
		// sing-box matches keys like encoding/json: case-insensitively,
		// KELVIN SIGN = k, LONG S = s
		"capitalised key":    `{"outbounds":[{"type":"vless","tag":"v","tls":{"Certificate_Path":"C:\\a.pem"}}]}`,
		"kelvin sign key":    "{\"outbounds\":[{\"type\":\"vless\",\"tag\":\"v\",\"tls\":{\"\u212Aey_path\":\"C:\\\\k\"}}]}",
		"long s key":         "{\"inbounds\":[{\"type\":\"tun\",\"\u017Ftate_directory\":\"C:\\\\x\"}],\"outbounds\":[]}",
		"capitalised output": `{"log":{"Output":"C:\\x.log"},"outbounds":[]}`,
		"capitalised type":   `{"outbounds":[{"Type":"tor","tag":"t"}]}`,
		"two type keys":      `{"outbounds":[{"type":"direct","TYPE":"tor","tag":"t"}]}`,
		"cache file Path":    `{"experimental":{"cache_file":{"Path":"C:\\x.db"}},"outbounds":[]}`,
		"Outbounds section":  `{"Outbounds":[{"type":"tor","tag":"t"}]}`,
		// Off the loopback: the elevated sing-box open to the network
		"inbound on all":    `{"inbounds":[{"type":"mixed","tag":"in","listen":"0.0.0.0","listen_port":2080}],"outbounds":[]}`,
		"clash api on all":  `{"experimental":{"clash_api":{"external_controller":"0.0.0.0:9090"}},"outbounds":[]}`,
		"debug on loopback": `{"experimental":{"debug":{"listen":"127.0.0.1:6060"}},"outbounds":[]}`,
	}
	for name, updated := range refused {
		err := checkNoNewRisky([]byte(base), decode(t, updated))
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	allowed := map[string]string{
		"ws transport path":  `{"outbounds":[{"type":"vless","tag":"v","transport":{"type":"ws","path":"/ws"}}]}`,
		"http outbound path": `{"outbounds":[{"type":"http","tag":"dpi-bypass","server":"127.0.0.1","server_port":3128,"path":"/"}]}`,
		"rule set file name": `{"route":{"rule_set":[{"type":"local","tag":"r","path":"ads.srs"}]},"outbounds":[]}`,
		"geoip rule":         `{"route":{"rules":[{"geoip":["private"],"outbound":"direct"}]},"outbounds":[]}`,
		"process path rule":  `{"route":{"rules":[{"process_path":["C:\\a.exe"],"outbound":"direct"}]},"outbounds":[]}`,
		"remote rule set":    `{"route":{"rule_set":[{"type":"remote","tag":"r","url":"https://x/r.srs"}]},"outbounds":[]}`,
		"all protocol types": `{"outbounds":[{"type":"hysteria2","tag":"a"},{"type":"shadowsocks","tag":"b"},{"type":"trojan","tag":"c"},{"type":"vmess","tag":"d"},{"type":"selector","tag":"e"},{"type":"urltest","tag":"f"}]}`,
	}
	for name, updated := range allowed {
		if err := checkNoNewRisky([]byte(base), decode(t, updated)); err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
	}
}

// What an administrator wrote by hand stays: only additions are refused
func TestGuardKeepsExistingRiskyConstructs(t *testing.T) {
	existing := `{"log":{"output":"box.log"},"outbounds":[{"type":"tor","tag":"t","executable_path":"C:\\tor\\tor.exe"},{"type":"direct","tag":"direct"}]}`
	// Unchanged, reordered, and with an unrelated outbound added: fine
	same := `{"outbounds":[{"type":"direct","tag":"direct"},{"type":"vless","tag":"v"},{"type":"tor","tag":"t","executable_path":"C:\\tor\\tor.exe"}],"log":{"output":"box.log"}}`
	if err := checkNoNewRisky([]byte(existing), decode(t, same)); err != nil {
		t.Fatalf("existing constructs refused: %v", err)
	}
	// ...but not changed
	changed := strings.Replace(same, `tor.exe`, `evil.exe`, 1)
	if err := checkNoNewRisky([]byte(existing), decode(t, changed)); err == nil {
		t.Fatal("a changed executable_path accepted")
	}
	moved := strings.Replace(same, `"box.log"`, `"C:\\Windows\\box.log"`, 1)
	if err := checkNoNewRisky([]byte(existing), decode(t, moved)); err == nil {
		t.Fatal("a changed log.output accepted")
	}

	// A LAN listener an administrator configured stays, an edit elsewhere
	// does not trip over it
	lan := `{"inbounds":[{"type":"mixed","tag":"in","listen":"0.0.0.0","listen_port":2080}],"outbounds":[{"type":"direct","tag":"direct"}]}`
	edited := `{"inbounds":[{"type":"mixed","tag":"in","listen":"0.0.0.0","listen_port":2080}],"outbounds":[{"type":"direct","tag":"direct"},{"type":"vless","tag":"v"}]}`
	if err := checkNoNewRisky([]byte(lan), decode(t, edited)); err != nil {
		t.Fatalf("an existing LAN listener refused: %v", err)
	}
}

// The guard sits in the save path: a web-UI section write cannot add them
func TestWriteSectionRefusesATorOutbound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}`), 0644); err != nil {
		t.Fatal(err)
	}
	e := New(path)
	err := e.WriteSection("outbounds", []byte(`[{"type":"direct","tag":"direct"},{"type":"tor","tag":"t","executable_path":"C:\\x.exe"}]`))
	if err == nil {
		t.Fatal("tor outbound written")
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "tor") {
		t.Fatalf("config changed: %s", data)
	}
}
