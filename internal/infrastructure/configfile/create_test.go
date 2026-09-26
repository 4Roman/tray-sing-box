package configfile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"tray-sing-box/internal/domain"
)

const firstConfig = `{
  "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": 2080}],
  "outbounds": [{"type": "vless", "tag": "p1", "server": "a.example.com"}, {"type": "direct", "tag": "direct"}],
  "route": {"final": "p1"}
}`

// leftovers lists the files next to config.json other than config.json itself
func leftovers(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if e.Name() != "config.json" {
			names = append(names, e.Name())
		}
	}
	return names
}

// A fresh install has no config: every read says so, in a form the UI knows
func TestMissingConfigIsReportedAsSuch(t *testing.T) {
	e := New(filepath.Join(t.TempDir(), "config.json"))
	if _, err := e.ReadSection("outbounds"); !errors.Is(err, domain.ErrConfigMissing) {
		t.Fatalf("ReadSection: want ErrConfigMissing, got %v", err)
	}
	if err := e.AddOutbound(map[string]any{"type": "direct", "tag": "d"}); !errors.Is(err, domain.ErrConfigMissing) {
		t.Fatalf("AddOutbounds: want ErrConfigMissing, got %v", err)
	}
}

func TestCreateConfigWritesTheFirstConfig(t *testing.T) {
	dir := t.TempDir()
	e := New(filepath.Join(dir, "config.json"))
	if err := e.CreateConfig([]byte(firstConfig)); err != nil {
		t.Fatalf("CreateConfig: %v", err)
	}
	list, err := e.ListOutbounds()
	if err != nil || len(list) != 2 || list[0].Tag != "p1" {
		t.Fatalf("outbounds after create: %v, %v", list, err)
	}
	if left := leftovers(t, dir); len(left) != 0 {
		t.Fatalf("files left next to config.json: %v", left)
	}
}

func TestCreateConfigNeverReplacesAConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(testConfigText), 0644); err != nil {
		t.Fatal(err)
	}
	e := New(path)
	if err := e.CreateConfig([]byte(firstConfig)); err == nil {
		t.Fatal("an existing config was replaced")
	}
	data, _ := os.ReadFile(path)
	if string(data) != testConfigText {
		t.Fatalf("existing config changed: %s", data)
	}
}

// Two requests (two editors: nothing shared but the file) racing to create
// the first config: exactly one wins, and the file is whole
func TestCreateConfigRaceHasOneWinner(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cfg := strings.Replace(firstConfig, `"p1"`, fmt.Sprintf(`"p%d"`, i), -1)
			errs[i] = New(path).CreateConfig([]byte(cfg))
		}(i)
	}
	wg.Wait()
	wins := 0
	for _, err := range errs {
		if err == nil {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("%d requests created the config, want exactly 1: %v", wins, errs)
	}
	if _, err := New(path).ListOutbounds(); err != nil {
		t.Fatalf("the created config is not whole: %v", err)
	}
	if left := leftovers(t, dir); len(left) != 0 {
		t.Fatalf("files left next to config.json: %v", left)
	}
}

// Whatever arrives this way passes the guard against an empty config
func TestCreateConfigRefusesWhatTheGuardRefuses(t *testing.T) {
	refused := map[string]string{
		"log output":          `{"log":{"output":"C:\\Windows\\x.log"},"outbounds":[]}`,
		"tor outbound":        `{"outbounds":[{"type":"tor","tag":"t"}]}`,
		"inbound on all":      `{"inbounds":[{"type":"mixed","tag":"in","listen":"0.0.0.0","listen_port":2080}]}`,
		"inbound on ::":       `{"inbounds":[{"type":"socks","tag":"in","listen":"::","listen_port":1080}]}`,
		"inbound on a LAN IP": `{"inbounds":[{"type":"http","tag":"in","listen":"192.168.1.5","listen_port":8080}]}`,
		"clash api on all":    `{"experimental":{"clash_api":{"external_controller":"0.0.0.0:9090"}}}`,
		"clash api no host":   `{"experimental":{"clash_api":{"external_controller":":9090"}}}`,
		"v2ray api on all":    `{"experimental":{"v2ray_api":{"listen":"0.0.0.0:8080"}}}`,
		"debug listener":      `{"experimental":{"debug":{"listen":"127.0.0.1:6060"}}}`,
		"service on all":      `{"services":[{"type":"ssm-api","tag":"s","listen":"0.0.0.0","listen_port":8080}]}`,
		"capitalised Listen":  `{"inbounds":[{"type":"mixed","tag":"in","Listen":"0.0.0.0","listen_port":2080}]}`,
		"listen not a string": `{"inbounds":[{"type":"mixed","tag":"in","listen":0,"listen_port":2080}]}`,
		"not an object":       `[{"type":"direct"}]`,
		"trailing data":       `{"outbounds":[]} {"outbounds":[]}`,
		"not json":            `outbounds: []`,
		"null":                `null`,
		"comments":            "{\n// sing-box itself allows these\n\"outbounds\":[]}",
		// Allow-lists: sections, inbound and endpoint types
		"services section":     `{"services":[{"type":"resolved","tag":"r"}]}`,
		"server inbound":       `{"inbounds":[{"type":"shadowsocks","tag":"ss","listen":"127.0.0.1","listen_port":8388,"method":"aes-128-gcm","password":"x"}]}`,
		"masquerade":           `{"inbounds":[{"type":"hysteria2","tag":"h","listen":"127.0.0.1","masquerade":"file:///C:/Users"}]}`,
		"tailscale endpoint":   `{"endpoints":[{"type":"tailscale","tag":"ts","auth_key":"x","control_url":"https://hs.example"}]}`,
		"wireguard listening":  `{"endpoints":[{"type":"wireguard","tag":"wg","listen_port":51820,"address":["10.0.0.2/32"],"private_key":"x","peers":[]}]}`,
		"ntp sets the clock":   `{"ntp":{"enabled":true,"server":"time.example","write_to_system":true}}`,
		"any _path key":        `{"outbounds":[{"type":"vless","tag":"v","tls":{"enabled":true,"ech":{"enabled":true,"config_path":"C:\\x"}}}]}`,
		"any _directory key":   `{"inbounds":[{"type":"tun","tag":"t","cache_directory":"C:\\x"}]}`,
		"hosts server file":    `{"dns":{"servers":[{"type":"hosts","tag":"h","path":["C:\\Windows\\hosts2"]}]}}`,
		"cache file elsewhere": `{"experimental":{"cache_file":{"enabled":true,"path":"C:\\x.db"}}}`,
	}
	for name, cfg := range refused {
		dir := t.TempDir()
		e := New(filepath.Join(dir, "config.json"))
		if err := e.CreateConfig([]byte(cfg)); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if _, err := os.Stat(filepath.Join(dir, "config.json")); err == nil {
			t.Errorf("%s: config.json written", name)
		}
		if left := leftovers(t, dir); len(left) != 0 {
			t.Errorf("%s: files left: %v", name, left)
		}
	}

	allowed := map[string]string{
		"loopback inbound":    `{"inbounds":[{"type":"mixed","tag":"in","listen":"127.0.0.1","listen_port":2080}]}`,
		"ipv6 loopback":       `{"inbounds":[{"type":"mixed","tag":"in","listen":"::1","listen_port":2080}]}`,
		"localhost":           `{"inbounds":[{"type":"mixed","tag":"in","listen":"localhost","listen_port":2080}]}`,
		"tun":                 `{"inbounds":[{"type":"tun","tag":"tun","address":["172.19.0.1/30"],"auto_route":true}]}`,
		"clash api loopback":  `{"experimental":{"clash_api":{"external_controller":"127.0.0.1:9090","secret":"x"}}}`,
		"clash api ipv6 loop": `{"experimental":{"clash_api":{"external_controller":"[::1]:9090"}}}`,
		"cache file, no path": `{"experimental":{"cache_file":{"enabled":true}}}`,
		"remote rule set":     `{"route":{"rule_set":[{"type":"remote","tag":"r","url":"https://x/r.srs"}]}}`,
		// No false refusals of what a client config commonly holds
		"cache file in data":  `{"experimental":{"cache_file":{"enabled":true,"path":"cache.db"}}}`,
		"doh server path":     `{"dns":{"servers":[{"type":"https","tag":"d","server":"dns.example","path":"/dns-query"}]}}`,
		"h3 server path":      `{"dns":{"servers":[{"type":"h3","tag":"d","server":"dns.example","path":"/abc123"}]}}`,
		"v2ray api loopback":  `{"experimental":{"v2ray_api":{"listen":"127.0.0.1:8080"}}}`,
		"clash api disabled":  `{"experimental":{"clash_api":{"external_controller":""}}}`,
		"process path rule":   `{"route":{"rules":[{"process_path":["C:\\Program Files\\x.exe"],"outbound":"direct"}]}}`,
		"wireguard endpoint":  `{"endpoints":[{"type":"wireguard","tag":"wg","address":["10.0.0.2/32"],"private_key":"x","peers":[{"address":"1.2.3.4","port":51820,"public_key":"y","allowed_ips":["0.0.0.0/0"]}]}]}`,
		"ntp without writing": `{"ntp":{"enabled":true,"server":"time.example","write_to_system":false}}`,
		"typical client": `{
			"log": {"level": "info", "timestamp": true},
			"dns": {"servers": [{"type": "https", "tag": "remote", "server": "1.1.1.1", "detour": "p1"}, {"type": "local", "tag": "local"}], "final": "remote"},
			"inbounds": [{"type": "tun", "tag": "tun", "address": ["172.19.0.1/30"], "auto_route": true, "strict_route": true},
			             {"type": "mixed", "tag": "mixed", "listen": "127.0.0.1", "listen_port": 2080}],
			"outbounds": [{"type": "vless", "tag": "p1", "server": "a.example.com", "server_port": 443, "uuid": "00000000-0000-0000-0000-000000000000",
			               "tls": {"enabled": true, "server_name": "a.example.com", "utls": {"enabled": true, "fingerprint": "chrome"}}},
			              {"type": "direct", "tag": "direct"}],
			"route": {"rule_set": [{"type": "remote", "tag": "geosite-ru", "format": "binary", "url": "https://x/ru.srs", "download_detour": "p1"}],
			          "rules": [{"action": "sniff"}, {"protocol": "dns", "action": "hijack-dns"}, {"rule_set": "geosite-ru", "outbound": "direct"}],
			          "final": "p1", "auto_detect_interface": true},
			"experimental": {"cache_file": {"enabled": true}, "clash_api": {"external_controller": "127.0.0.1:9090", "secret": "s"}}
		}`,
	}
	for name, cfg := range allowed {
		e := New(filepath.Join(t.TempDir(), "config.json"))
		if err := e.CreateConfig([]byte(cfg)); err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
	}
}

func TestCreateConfigRunsTheValidator(t *testing.T) {
	dir := t.TempDir()
	e := New(filepath.Join(dir, "config.json"))
	e.SetValidator(func([]byte) error { return errors.New("FATAL: sing-box says no") })
	if err := e.CreateConfig([]byte(firstConfig)); err == nil || !strings.Contains(err.Error(), "sing-box says no") {
		t.Fatalf("validator result not reported: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "config.json")); err == nil {
		t.Fatal("a config sing-box rejects was written")
	}
}

// The first config is never saved unchecked: the page edits only outbounds
// and route, a mistake elsewhere could not be fixed without an administrator.
// An ordinary save goes ahead without the binary, as before.
func TestCreateConfigNeedsSingBox(t *testing.T) {
	missing := func([]byte) error { return fmt.Errorf("%w at: C:\\bin\\sing-box.exe", domain.ErrSingBoxMissing) }

	dir := t.TempDir()
	e := New(filepath.Join(dir, "config.json"))
	e.SetValidator(missing)
	if err := e.CreateConfig([]byte(firstConfig)); err == nil || !strings.Contains(err.Error(), "скачайте sing-box") {
		t.Fatalf("created without sing-box: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "config.json")); err == nil {
		t.Fatal("config.json written without a check")
	}

	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(testConfigText), 0644); err != nil {
		t.Fatal(err)
	}
	e = New(path)
	e.SetValidator(missing)
	if err := e.WriteSection("route", []byte(`{"final":"direct","auto_detect_interface":true}`)); err != nil {
		t.Fatalf("an ordinary save refused without sing-box: %v", err)
	}
}

// What is written is exactly what the guard and the validator saw
func TestCreateConfigWritesWhatWasChecked(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	e := New(path)
	var checked []byte
	e.SetValidator(func(b []byte) error { checked = b; return nil })
	if err := e.CreateConfig([]byte("  " + firstConfig + "\n\n")); err != nil {
		t.Fatal(err)
	}
	written, _ := os.ReadFile(path)
	if string(written) != string(checked) {
		t.Fatalf("written differs from what was checked:\n%s\n---\n%s", written, checked)
	}
}

// An existing config wins over any paste — also one the guard would refuse
func TestCreateConfigOverAConfigSaysSo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(testConfigText), 0644); err != nil {
		t.Fatal(err)
	}
	err := New(path).CreateConfig([]byte(`{"log":{"output":"C:\\x.log"}}`))
	if !errors.Is(err, errConfigExists) {
		t.Fatalf("want errConfigExists, got %v", err)
	}
}

// A file system without hard links (FAT32, exFAT): an exclusive create
func TestCreateConfigWithoutHardLinks(t *testing.T) {
	old := linkFile
	linkFile = func(string, string) error { return errors.New("hard links not supported") }
	t.Cleanup(func() { linkFile = old })

	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := New(path).CreateConfig([]byte(firstConfig)); err != nil {
		t.Fatalf("CreateConfig: %v", err)
	}
	if _, err := New(path).ListOutbounds(); err != nil {
		t.Fatalf("created config unreadable: %v", err)
	}
	if left := leftovers(t, dir); len(left) != 0 {
		t.Fatalf("files left next to config.json: %v", left)
	}
	if err := New(path).CreateConfig([]byte(firstConfig)); !errors.Is(err, errConfigExists) {
		t.Fatalf("second create: %v", err)
	}
}

// The refusal of a first config says what to remove and that the rest is
// fine, names the entries by tag, and says how many more there are
func TestCreateConfigRefusalIsActionable(t *testing.T) {
	cfg := `{"log":{"output":"x.log"},"inbounds":[{"type":"mixed","tag":"lan","listen":"0.0.0.0","listen_port":1}],
		"ntp":{"write_to_system":true},"services":[],
		"experimental":{"clash_api":{"external_ui":"ui","external_ui_download_url":"https://x"},"debug":{"listen":"127.0.0.1:1"}},
		"outbounds":[{"type":"tor","tag":"t"}]}`
	err := New(filepath.Join(t.TempDir(), "config.json")).CreateConfig([]byte(cfg))
	if err == nil {
		t.Fatal("accepted")
	}
	msg := err.Error()
	for _, want := range []string{"уберите из конфига", "остальное приложение примет", `(tag "lan")`, "и ещё"} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal lacks %q: %s", want, msg)
		}
	}
	if strings.Contains(msg, "0.0.0.0") || strings.Contains(msg, "https://x") {
		t.Errorf("refusal quotes values: %s", msg)
	}
}

const testConfigText = `{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}`
