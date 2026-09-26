package webui

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
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

// newTestServer starts a real settings server over a temp config and
// returns it with its base URL
func newTestServer(t *testing.T, clip TextSource) (*Server, string) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(testConfig), 0644); err != nil {
		t.Fatal(err)
	}

	editor := configfile.New(path)
	vpn := domain.NewVPNService(&nopProcessManager{}, &nopStorage{})
	settings := domain.NewSettingsService(editor, vpn)
	importer := domain.NewImportService(sharelink.Parser{}, editor, nil, vpn)

	server := New(settings, importer, nil, nil, nil, nil, Sources{Clipboard: clip}, LogAccess{})
	return server, start(t, server)
}

// start starts the listener and returns the base URL
func start(t *testing.T, server *Server) string {
	t.Helper()
	base, err := server.start()
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	return base
}

// secretInLoginPage finds the session secret in the page /login serves
var secretInLoginPage = regexp.MustCompile(`const SESSION = "([0-9a-f]{64})";`)

// login gets a session the way the browser does: a code issued as for a
// tray click, GET /login?code=, the secret out of the page it returns
func login(t *testing.T, server *Server) string {
	t.Helper()
	code, err := server.issueCode()
	if err != nil {
		t.Fatal(err)
	}
	status, body := get(t, server.base+"/login?code="+code)
	if status != http.StatusOK {
		t.Fatalf("login: status %d: %s", status, body)
	}
	m := secretInLoginPage.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no session secret in the login page: %s", body)
	}
	return m[1]
}

// get fetches a page without a session
func get(t *testing.T, rawURL string) (int, string) {
	t.Helper()
	resp, err := http.Get(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(body)
}

// callRaw sends an API request with the given session ("" = none) and
// returns the raw response body
func callRaw(t *testing.T, method, rawURL, session string, body any) (int, string) {
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
	if session != "" {
		req.Header.Set(sessionHeader, session)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(raw)
}

// call is callRaw with the JSON response decoded
func call(t *testing.T, method, rawURL, session string, body any) (int, map[string]any) {
	t.Helper()
	status, raw := callRaw(t, method, rawURL, session, body)
	var data map[string]any
	json.Unmarshal([]byte(raw), &data)
	return status, data
}

func TestConfigEndpoint(t *testing.T) {
	server, base := newTestServer(t, nil)
	session := login(t, server)

	status, data := call(t, "GET", base+"/api/config", session, nil)
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
	server := New(domain.NewSettingsService(editor, vpn), domain.NewImportService(sharelink.Parser{}, editor, nil, vpn),
		nil, nil, nil, nil, Sources{}, LogAccess{})
	base := start(t, server)
	session := login(t, server)

	status, data := call(t, http.MethodPost, base+"/api/vpn", session, map[string]any{"running": true})
	if status != http.StatusOK || data["running"] != true || data["status"] != "running" {
		t.Fatalf("start: status %d, data %v", status, data)
	}
	if !pm.running || !st.state {
		t.Fatalf("start did not start the process / record the intent: running=%v intent=%v", pm.running, st.state)
	}

	status, data = call(t, http.MethodPost, base+"/api/vpn", session, map[string]any{"running": false})
	if status != http.StatusOK || data["running"] != false || data["status"] != "stopped" {
		t.Fatalf("stop: status %d, data %v", status, data)
	}
	if pm.running || st.state {
		t.Fatalf("stop did not stop the process / record the intent: running=%v intent=%v", pm.running, st.state)
	}

	if status, _ := call(t, http.MethodPost, base+"/api/vpn", "", map[string]any{"running": true}); status != http.StatusUnauthorized {
		t.Fatalf("vpn without a session: status %d", status)
	}
	if pm.running || st.state {
		t.Fatal("a request without a session started the VPN")
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
	server := New(domain.NewSettingsService(editor, vpn), domain.NewImportService(sharelink.Parser{}, editor, nil, vpn),
		nil, nil, nil, nil, Sources{}, LogAccess{})
	base := start(t, server)

	_, data := call(t, "GET", base+"/api/config", login(t, server), nil)
	if data["running"] != false || data["status"] != "starting" {
		t.Fatalf("running/status = %v/%v, want false/starting", data["running"], data["status"])
	}
}

func TestSaveSectionAndSwitch(t *testing.T) {
	server, base := newTestServer(t, nil)
	session := login(t, server)

	newOutbounds := `[
  {"type": "vless", "tag": "p1", "server": "a.example.com"},
  {"type": "trojan", "tag": "p2", "server": "b.example.com"},
  {"type": "direct", "tag": "direct"}
]`
	status, data := call(t, "POST", base+"/api/section", session,
		map[string]string{"name": "outbounds", "content": newOutbounds})
	if status != http.StatusOK {
		t.Fatalf("save section: status %d: %v", status, data)
	}

	status, data = call(t, "POST", base+"/api/switch", session,
		map[string]string{"tag": "p2"})
	if status != http.StatusOK {
		t.Fatalf("switch: status %d: %v", status, data)
	}

	_, data = call(t, "GET", base+"/api/config", session, nil)
	if data["active"] != "p2" {
		t.Fatalf("active after switch = %v", data["active"])
	}

	// Invalid JSON must be rejected with a readable error
	status, data = call(t, "POST", base+"/api/section", session,
		map[string]string{"name": "route", "content": "{broken"})
	if status != http.StatusBadRequest || data["error"] == "" {
		t.Fatalf("broken JSON accepted: %d %v", status, data)
	}
}

func TestImportEndpoint(t *testing.T) {
	link := "vless://uuid@imported.example.com:443?security=tls#web-import"
	server, base := newTestServer(t, func() (string, error) { return link, nil })
	session := login(t, server)

	status, data := call(t, "POST", base+"/api/import", session,
		map[string]string{"source": "clipboard"})
	if status != http.StatusOK {
		t.Fatalf("import: status %d: %v", status, data)
	}
	tags := data["tags"].([]any)
	if len(tags) != 1 || tags[0] != "web-import" {
		t.Fatalf("tags = %v", tags)
	}

	status, data = call(t, "POST", base+"/api/import", session,
		map[string]string{"source": "qr"})
	if status != http.StatusBadRequest {
		t.Fatalf("unavailable source accepted: %d %v", status, data)
	}
}
