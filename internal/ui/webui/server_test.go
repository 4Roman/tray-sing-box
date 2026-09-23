package webui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tray-sing-box/internal/domain"
	"tray-sing-box/internal/infrastructure/configfile"
	"tray-sing-box/internal/infrastructure/sharelink"
)

type nopProcessManager struct{ running bool }

func (n *nopProcessManager) Start() error    { n.running = true; return nil }
func (n *nopProcessManager) Stop() error     { n.running = false; return nil }
func (n *nopProcessManager) IsRunning() bool { return n.running }

type nopStorage struct{ state bool }

func (n *nopStorage) SaveVPNState(running bool) error { n.state = running; return nil }
func (n *nopStorage) LoadVPNState() (bool, error)     { return n.state, nil }

const testConfig = `{
  "outbounds": [
    {"type": "vless", "tag": "p1", "server": "a.example.com"},
    {"type": "direct", "tag": "direct"}
  ],
  "route": {"rules": [{"outbound": "p1"}], "final": "direct"}
}`

// newTestServer starts a real settings server over a temp config
func newTestServer(t *testing.T, clip TextSource) (*Server, string) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(testConfig), 0644); err != nil {
		t.Fatal(err)
	}

	editor := configfile.New(path)
	vpn := domain.NewVPNService(&nopProcessManager{}, &nopStorage{})
	settings := domain.NewSettingsService(editor, vpn)
	importer := domain.NewImportService(sharelink.Parser{}, editor, vpn)

	server := New(settings, importer, nil, nil, nil, nil, Sources{Clipboard: clip}, LogAccess{})
	pageURL, err := server.start()
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	return server, pageURL
}

func baseURL(t *testing.T, pageURL string) string {
	t.Helper()
	u, err := url.Parse(pageURL)
	if err != nil {
		t.Fatal(err)
	}
	return "http://" + u.Host
}

func call(t *testing.T, method, rawURL, token string, body any) (int, map[string]any) {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, rawURL, reader)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("X-Token", token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var data map[string]any
	json.NewDecoder(resp.Body).Decode(&data)
	return resp.StatusCode, data
}

func TestPageRequiresToken(t *testing.T) {
	server, pageURL := newTestServer(t, nil)
	base := baseURL(t, pageURL)

	resp, err := http.Get(base + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("page without token: status %d", resp.StatusCode)
	}

	resp, err = http.Get(pageURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("page with token: status %d", resp.StatusCode)
	}
	_ = server
}

func TestAPIRequiresToken(t *testing.T) {
	_, pageURL := newTestServer(t, nil)
	base := baseURL(t, pageURL)

	status, _ := call(t, "GET", base+"/api/config", "", nil)
	if status != http.StatusForbidden {
		t.Fatalf("api without token: status %d", status)
	}
	status, _ = call(t, "GET", base+"/api/config", "wrong", nil)
	if status != http.StatusForbidden {
		t.Fatalf("api with wrong token: status %d", status)
	}
}

func TestConfigEndpoint(t *testing.T) {
	server, pageURL := newTestServer(t, nil)
	base := baseURL(t, pageURL)

	status, data := call(t, "GET", base+"/api/config", server.token, nil)
	if status != http.StatusOK {
		t.Fatalf("status %d: %v", status, data)
	}
	if !strings.Contains(data["outbounds"].(string), `"p1"`) {
		t.Fatalf("outbounds text wrong: %v", data["outbounds"])
	}
	if data["active"] != "p1" {
		t.Fatalf("active = %v", data["active"])
	}
	list := data["list"].([]any)
	if len(list) != 2 {
		t.Fatalf("list = %v", list)
	}
	if data["running"] != false || data["status"] != "stopped" {
		t.Fatalf("running/status = %v/%v, want false/stopped", data["running"], data["status"])
	}
}

// The page can start and stop the VPN like the tray does: an explicit action
// that records the intent
func TestVPNEndpointStartsAndStops(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(testConfig), 0644); err != nil {
		t.Fatal(err)
	}
	editor := configfile.New(path)
	pm := &nopProcessManager{}
	st := &nopStorage{}
	vpn := domain.NewVPNService(pm, st)
	server := New(domain.NewSettingsService(editor, vpn), domain.NewImportService(sharelink.Parser{}, editor, vpn),
		nil, nil, nil, nil, Sources{}, LogAccess{})
	pageURL, err := server.start()
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	base := baseURL(t, pageURL)

	status, data := call(t, http.MethodPost, base+"/api/vpn", server.token, map[string]any{"running": true})
	if status != http.StatusOK || data["running"] != true || data["status"] != "running" {
		t.Fatalf("start: status %d, data %v", status, data)
	}
	if !pm.running || !st.state {
		t.Fatalf("start did not start the process / record the intent: running=%v intent=%v", pm.running, st.state)
	}

	status, data = call(t, http.MethodPost, base+"/api/vpn", server.token, map[string]any{"running": false})
	if status != http.StatusOK || data["running"] != false || data["status"] != "stopped" {
		t.Fatalf("stop: status %d, data %v", status, data)
	}
	if pm.running || st.state {
		t.Fatalf("stop did not stop the process / record the intent: running=%v intent=%v", pm.running, st.state)
	}

	if status, _ := call(t, http.MethodPost, base+"/api/vpn", "", map[string]any{"running": true}); status != http.StatusForbidden {
		t.Fatalf("vpn without token: status %d", status)
	}
}

// While the app is still bringing the VPN up the page must not say "stopped"
func TestConfigEndpointReportsStarting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(testConfig), 0644); err != nil {
		t.Fatal(err)
	}
	editor := configfile.New(path)
	// Down, but the stored intent says "running"
	vpn := domain.NewVPNService(&nopProcessManager{}, &nopStorage{state: true})
	server := New(domain.NewSettingsService(editor, vpn), domain.NewImportService(sharelink.Parser{}, editor, vpn),
		nil, nil, nil, nil, Sources{}, LogAccess{})
	pageURL, err := server.start()
	if err != nil {
		t.Fatalf("start: %v", err)
	}

	_, data := call(t, "GET", baseURL(t, pageURL)+"/api/config", server.token, nil)
	if data["running"] != false || data["status"] != "starting" {
		t.Fatalf("running/status = %v/%v, want false/starting", data["running"], data["status"])
	}
}

func TestSaveSectionAndSwitch(t *testing.T) {
	server, pageURL := newTestServer(t, nil)
	base := baseURL(t, pageURL)

	newOutbounds := `[
  {"type": "vless", "tag": "p1", "server": "a.example.com"},
  {"type": "trojan", "tag": "p2", "server": "b.example.com"},
  {"type": "direct", "tag": "direct"}
]`
	status, data := call(t, "POST", base+"/api/section", server.token,
		map[string]string{"name": "outbounds", "content": newOutbounds})
	if status != http.StatusOK {
		t.Fatalf("save section: status %d: %v", status, data)
	}

	status, data = call(t, "POST", base+"/api/switch", server.token,
		map[string]string{"tag": "p2"})
	if status != http.StatusOK {
		t.Fatalf("switch: status %d: %v", status, data)
	}

	_, data = call(t, "GET", base+"/api/config", server.token, nil)
	if data["active"] != "p2" {
		t.Fatalf("active after switch = %v", data["active"])
	}

	// Invalid JSON must be rejected with a readable error
	status, data = call(t, "POST", base+"/api/section", server.token,
		map[string]string{"name": "route", "content": "{broken"})
	if status != http.StatusBadRequest || data["error"] == "" {
		t.Fatalf("broken JSON accepted: %d %v", status, data)
	}
}

func TestImportEndpoint(t *testing.T) {
	link := "vless://uuid@imported.example.com:443?security=tls#web-import"
	server, pageURL := newTestServer(t, func() (string, error) { return link, nil })
	base := baseURL(t, pageURL)

	status, data := call(t, "POST", base+"/api/import", server.token,
		map[string]string{"source": "clipboard"})
	if status != http.StatusOK {
		t.Fatalf("import: status %d: %v", status, data)
	}
	tags := data["tags"].([]any)
	if len(tags) != 1 || tags[0] != "web-import" {
		t.Fatalf("tags = %v", tags)
	}

	status, data = call(t, "POST", base+"/api/import", server.token,
		map[string]string{"source": "qr"})
	if status != http.StatusBadRequest {
		t.Fatalf("unavailable source accepted: %d %v", status, data)
	}
}
