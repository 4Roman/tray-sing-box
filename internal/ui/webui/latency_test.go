package webui

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"tray-sing-box/internal/domain"
	"tray-sing-box/internal/infrastructure/configfile"
	"tray-sing-box/internal/infrastructure/sharelink"
)

// Two servers with credentials and addresses none of the answers may carry
const latencyConfig = `{
  "outbounds": [
    {"type": "vless", "tag": "de-1", "server": "203.0.113.7", "server_port": 443, "uuid": "11111111-2222-3333-4444-555555555555"},
    {"type": "trojan", "tag": "nl-2", "server": "203.0.113.8", "server_port": 8443, "password": "pw-secret-123"},
    {"type": "direct", "tag": "direct"}
  ],
  "route": {"final": "de-1"}
}`

// What a test instance of the fake knows and the page must never see: its
// Clash API secret and address
const (
	fakeProbeSecret = "c1a5c1a5c1a5c1a5c1a5c1a5c1a5c1a5c1a5c1a5c1a5c1a5c1a5c1a5c1a5c1a5"
	fakeProbeAPI    = "127.0.0.1:47123"
)

// fakeProber stands in for the test sing-box: fixed delays, or (wait) it
// measures until its ctx ends
type fakeProber struct {
	mu      sync.Mutex
	calls   int
	plans   []*domain.ProbePlan
	delays  map[string]domain.Delay
	wait    bool
	started chan struct{}
	ended   chan struct{} // closed once a waiting Measure saw its ctx end
}

func (f *fakeProber) Measure(ctx context.Context, plan *domain.ProbePlan, tags []string) (map[string]domain.Delay, error) {
	f.mu.Lock()
	f.calls++
	f.plans = append(f.plans, plan)
	wait := f.wait
	f.mu.Unlock()
	if wait {
		close(f.started)
		select {
		case <-ctx.Done():
			close(f.ended)
		case <-time.After(10 * time.Second):
		}
		return map[string]domain.Delay{}, nil
	}
	return f.delays, nil
}

func (f *fakeProber) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// newLatencyServer is a settings server over latencyConfig; withLatency:
// the latency test wired in as main wires it (the editor as the source, the
// switch through SettingsService.UseOutbound under the server's op lock)
func newLatencyServer(t *testing.T, prober *fakeProber, withLatency bool) (*Server, string, string) {
	t.Helper()
	return newLatencyServerWith(t, prober, withLatency, latencyConfig)
}

// newLatencyServerWith is newLatencyServer over another config
func newLatencyServerWith(t *testing.T, prober *fakeProber, withLatency bool, cfg string) (*Server, string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(cfg), 0644); err != nil {
		t.Fatal(err)
	}
	editor := configfile.New(path)
	vpn := domain.NewVPNService(&nopProcessManager{}, &nopStorage{})
	settings := domain.NewSettingsService(editor, vpn)
	server := New(settings, domain.NewImportService(sharelink.Parser{}, editor, nil, vpn), nil, nil, nil, nil, Sources{}, LogAccess{})
	if withLatency {
		server.SetLatency(domain.NewLatencyService(editor, prober, settings.UseOutbound, server.opMu))
	}
	return server, start(t, server), path
}

func twoDelays() *fakeProber {
	return &fakeProber{delays: map[string]domain.Delay{
		"de-1": {Ms: 300, Status: domain.LatencyOK},
		"nl-2": {Ms: 100, Status: domain.LatencyOK},
	}}
}

// Nothing in an answer names a server's address or credential, the test
// instance's secret or port
func checkNothingLeaks(t *testing.T, what, body string) {
	t.Helper()
	for _, secret := range []string{"203.0.113.7", "203.0.113.8", "11111111-2222", "pw-secret-123", fakeProbeSecret, fakeProbeAPI} {
		if strings.Contains(body, secret) {
			t.Errorf("%s carries %q: %s", what, secret, body)
		}
	}
}

func TestLatencyNeedsASession(t *testing.T) {
	prober := twoDelays()
	_, base, _ := newLatencyServer(t, prober, true)
	if status, _ := call(t, http.MethodPost, base+"/api/latency", "", map[string]any{"select": false}); status != http.StatusUnauthorized {
		t.Fatalf("POST without a session: status %d", status)
	}
	if status, _ := call(t, http.MethodGet, base+"/api/latency", "", nil); status != http.StatusUnauthorized {
		t.Fatalf("GET without a session: status %d", status)
	}
	if prober.callCount() != 0 {
		t.Fatal("a check ran without a session")
	}
}

// The endpoints exist without the latency test too: a clear error, and the
// page hides the buttons (no "latency" in /api/config)
func TestLatencyNotWired(t *testing.T) {
	server, base, _ := newLatencyServer(t, nil, false)
	session := login(t, server)
	for _, method := range []string{http.MethodPost, http.MethodGet} {
		var body any
		if method == http.MethodPost {
			body = map[string]any{"select": false}
		}
		status, data := call(t, method, base+"/api/latency", session, body)
		if status != http.StatusBadRequest || data["error"] != "проверка задержки недоступна" {
			t.Fatalf("%s: status %d, %v", method, status, data)
		}
	}
	if _, data := call(t, http.MethodGet, base+"/api/config", session, nil); data["latency"] != nil {
		t.Fatalf("/api/config offers the latency test: %v", data["latency"])
	}
}

// A check: the report of every server, nothing of the test instance or the
// servers' addresses; GET answers the last one
func TestLatencyCheck(t *testing.T) {
	prober := twoDelays()
	server, base, path := newLatencyServer(t, prober, true)
	session := login(t, server)

	if _, data := call(t, http.MethodGet, base+"/api/config", session, nil); data["latency"] != true {
		t.Fatalf("/api/config: latency = %v", data["latency"])
	}
	status, body := callRaw(t, http.MethodGet, base+"/api/latency", session, nil)
	if status != http.StatusOK || strings.TrimSpace(body) != `{"report":null}` {
		t.Fatalf("GET before a check: %d %s", status, body)
	}

	before, _ := os.ReadFile(path)
	status, body = callRaw(t, http.MethodPost, base+"/api/latency", session, map[string]any{"select": false})
	if status != http.StatusOK {
		t.Fatalf("POST: %d %s", status, body)
	}
	checkNothingLeaks(t, "the check", body)
	var resp struct {
		Report  domain.LatencyReport   `json:"report"`
		Fastest *domain.FastestOutcome `json:"fastest"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Fastest != nil || resp.Report.Fastest != "nl-2" || resp.Report.Answered != 2 || len(resp.Report.Results) != 3 {
		t.Fatalf("answer: %s", body)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(after, before) {
		t.Fatal("a check changed config.json")
	}
	// The plan the prober got carried the servers: the answer did not
	if p := prober.plans[0]; len(p.Candidates) != 3 {
		t.Fatalf("plan candidates: %+v", p.Candidates)
	}

	status, last := callRaw(t, http.MethodGet, base+"/api/latency", session, nil)
	if status != http.StatusOK || !strings.Contains(last, `"fastest":"nl-2"`) {
		t.Fatalf("GET after the check: %d %s", status, last)
	}
	checkNothingLeaks(t, "the last report", last)
}

// "Select the fastest": switched in config.json through the usual switch
// (backup kept), the outcome with the ready text
func TestLatencySelectFastest(t *testing.T) {
	server, base, path := newLatencyServer(t, twoDelays(), true)
	session := login(t, server)

	status, body := callRaw(t, http.MethodPost, base+"/api/latency", session, map[string]any{"select": true, "confirm": false})
	if status != http.StatusOK {
		t.Fatalf("POST: %d %s", status, body)
	}
	checkNothingLeaks(t, "the switch", body)
	var resp struct {
		Fastest domain.FastestOutcome `json:"fastest"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Fastest.Switched || resp.Fastest.Tag != "nl-2" || resp.Fastest.Message != "Выбран самый быстрый — «nl-2» (100 мс; был «de-1» — 300 мс)." {
		t.Fatalf("outcome: %s", body)
	}
	var cfg struct {
		Route struct {
			Final string `json:"final"`
		} `json:"route"`
	}
	raw, _ := os.ReadFile(path)
	if err := json.Unmarshal(raw, &cfg); err != nil || cfg.Route.Final != "nl-2" {
		t.Fatalf("route.final = %q (%v)", cfg.Route.Final, err)
	}
	if _, err := os.Stat(path + ".bak"); err != nil {
		t.Fatalf("no backup: %v", err)
	}
}

// The traffic goes through a WireGuard endpoint: "select the fastest" moves
// nothing off it — the answer is the refusal the page shows as a warning
// (no tag), config.json stays as it was
func TestLatencySelectFastestKeepsAnEndpoint(t *testing.T) {
	cfg := strings.Replace(latencyConfig, `"route": {"final": "de-1"}`,
		`"endpoints": [{"type": "wireguard", "tag": "warp"}], "route": {"rules": [{"domain": ["intranet.example"], "outbound": "direct"}], "final": "warp"}`, 1)
	server, base, path := newLatencyServerWith(t, twoDelays(), true, cfg)
	session := login(t, server)

	before, _ := os.ReadFile(path)
	status, body := callRaw(t, http.MethodPost, base+"/api/latency", session, map[string]any{"select": true, "confirm": true})
	if status != http.StatusOK {
		t.Fatalf("POST: %d %s", status, body)
	}
	var resp struct {
		Fastest domain.FastestOutcome `json:"fastest"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatal(err)
	}
	want := domain.FastestOutcome{Previous: "warp", Message: "Трафик идёт через endpoint «warp» — проверка его не измеряет; выберите сервер вручную."}
	if resp.Fastest != want {
		t.Fatalf("outcome: %s", body)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(after, before) {
		t.Fatal("config.json changed")
	}
}

// A check only reads: the handler takes no operation lock, and a long
// operation from the tray (a sing-box update) does not hold it up
func TestLatencyCheckTakesNoOpLock(t *testing.T) {
	server, base, _ := newLatencyServer(t, twoDelays(), true)
	session := login(t, server)
	server.opMu.Lock()
	defer server.opMu.Unlock()

	done := make(chan int, 1)
	go func() {
		status, _ := callRaw(t, http.MethodPost, base+"/api/latency", session, map[string]any{"select": false})
		done <- status
	}()
	select {
	case status := <-done:
		if status != http.StatusOK {
			t.Fatalf("status %d", status)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the check waited for the operation lock")
	}
}

// The request names the two choices only: the test URL is the app's
// constant, a field it does not know is refused before anything runs
func TestLatencyRequestIsStrict(t *testing.T) {
	prober := twoDelays()
	server, base, _ := newLatencyServer(t, prober, true)
	session := login(t, server)
	for _, body := range []string{
		`{"select": false, "url": "http://127.0.0.1:1/x"}`,
		`{"select": false}{"select": true}`,
		`{"select": "yes"}`,
	} {
		req, _ := http.NewRequest(http.MethodPost, base+"/api/latency", strings.NewReader(body))
		req.Header.Set(sessionHeader, session)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: status %d", body, resp.StatusCode)
		}
	}
	if prober.callCount() != 0 {
		t.Fatalf("a refused request ran %d checks", prober.callCount())
	}
}

// The page going away (the tab closed) ends the check
func TestLatencyEndsWithThePage(t *testing.T) {
	prober := &fakeProber{wait: true, started: make(chan struct{}), ended: make(chan struct{})}
	server, base, _ := newLatencyServer(t, prober, true)
	session := login(t, server)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/latency", strings.NewReader(`{"select": false}`))
	req.Header.Set(sessionHeader, session)
	go func() {
		if resp, err := http.DefaultClient.Do(req); err == nil {
			resp.Body.Close()
		}
	}()
	select {
	case <-prober.started:
	case <-time.After(5 * time.Second):
		t.Fatal("the check did not start")
	}
	cancel()
	select {
	case <-prober.ended:
	case <-time.After(3 * time.Second):
		t.Fatal("the check went on after the page went away")
	}
}
