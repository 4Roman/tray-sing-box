package webui

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tray-sing-box/internal/domain"
	"tray-sing-box/internal/infrastructure/configfile"
	"tray-sing-box/internal/infrastructure/sharelink"
)

func TestHistoryRequiresSession(t *testing.T) {
	_, base := newTestServer(t, nil)

	for _, ep := range []struct{ method, path string }{
		{"GET", "/api/history"},
		{"POST", "/api/history/restore"},
		{"POST", "/api/update"},
		{"POST", "/api/dpi/direct"},
	} {
		if status, _ := call(t, ep.method, base+ep.path, "", map[string]string{}); status != http.StatusUnauthorized {
			t.Errorf("%s %s without a session: status %d", ep.method, ep.path, status)
		}
	}
}

// A save archives the previous config; rolling back to it brings the old
// outbounds back, through the ordinary save path
func TestHistoryListAndRollback(t *testing.T) {
	server, base := newTestServer(t, nil)
	session := login(t, server)

	status, data := call(t, "GET", base+"/api/history", session, nil)
	if status != http.StatusOK {
		t.Fatalf("history: status %d: %v", status, data)
	}
	if versions, _ := data["versions"].([]any); len(versions) != 0 {
		t.Fatalf("history of an unsaved config: %v", versions)
	}

	added := `[
  {"type": "vless", "tag": "p1", "server": "a.example.com"},
  {"type": "trojan", "tag": "p2", "server": "b.example.com"},
  {"type": "direct", "tag": "direct"}
]`
	if status, data := call(t, "POST", base+"/api/section", session, map[string]string{"name": "outbounds", "content": added}); status != http.StatusOK {
		t.Fatalf("save: status %d: %v", status, data)
	}

	_, data = call(t, "GET", base+"/api/history", session, nil)
	versions, _ := data["versions"].([]any)
	if len(versions) != 1 {
		t.Fatalf("history after one save: %v", data)
	}
	name, _ := versions[0].(map[string]any)["name"].(string)
	if !strings.HasPrefix(name, "config-") {
		t.Fatalf("version name %q", name)
	}

	status, data = call(t, "POST", base+"/api/history/restore", session, map[string]string{"name": name})
	if status != http.StatusOK {
		t.Fatalf("restore: status %d: %v", status, data)
	}
	_, data = call(t, "GET", base+"/api/config", session, nil)
	if strings.Contains(data["outbounds"].(string), `"p2"`) {
		t.Fatalf("p2 still configured after the rollback: %v", data["outbounds"])
	}
	// The rollback is a save too: the replaced config is in the history now
	_, data = call(t, "GET", base+"/api/history", session, nil)
	if versions, _ := data["versions"].([]any); len(versions) != 2 {
		t.Fatalf("history after the rollback: %v", data)
	}
}

// Version names come from the page: only archive names are accepted, never a
// path to another file
func TestHistoryRestoreRefusesOtherFiles(t *testing.T) {
	server, base := newTestServer(t, nil)
	session := login(t, server)

	for _, name := range []string{"../config.json", "config.json", "config-20260101-000000.000000000.json/../../x", ""} {
		status, data := call(t, "POST", base+"/api/history/restore", session, map[string]string{"name": name})
		if status == http.StatusOK {
			t.Errorf("restore %q accepted: %v", name, data)
		}
	}
}

func TestDPIDirectEnable(t *testing.T) {
	server, base := newDPITestServer(t)
	session := login(t, server)

	status, data := call(t, "POST", base+"/api/dpi/direct", session, map[string]bool{"enable": true})
	if status != http.StatusOK {
		t.Fatalf("direct enable: status %d: %v", status, data)
	}
	_, cfg := call(t, "GET", base+"/api/config", session, nil)
	if !strings.Contains(cfg["outbounds"].(string), `"dpi-bypass"`) {
		t.Fatalf("no dpi-bypass outbound after enabling: %v", cfg["outbounds"])
	}
	// Turning it off is choosing another server, not this endpoint
	if status, _ := call(t, "POST", base+"/api/dpi/direct", session, map[string]bool{"enable": false}); status == http.StatusOK {
		t.Fatal("direct disable accepted")
	}
}

type fakeBinaryRepo struct {
	current, latest string
	installed       bool
	downloadErr     error
}

func (f *fakeBinaryRepo) CurrentVersion() (string, error) { return f.current, nil }
func (f *fakeBinaryRepo) LatestRelease() (domain.ReleaseInfo, error) {
	return domain.ReleaseInfo{Version: f.latest}, nil
}
func (f *fakeBinaryRepo) Download(domain.ReleaseInfo) (string, error) {
	return "staged", f.downloadErr
}
func (f *fakeBinaryRepo) Install(string) error { f.installed = true; return nil }

func newUpdateTestServer(t *testing.T, repo *fakeBinaryRepo) (*Server, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(testConfig), 0644); err != nil {
		t.Fatal(err)
	}
	editor := configfile.New(path)
	vpn := domain.NewVPNService(&nopProcessManager{}, &nopStorage{})
	settings := domain.NewSettingsService(editor, vpn)
	importer := domain.NewImportService(sharelink.Parser{}, editor, nil, vpn)
	var updater *domain.UpdateService
	if repo != nil {
		updater = domain.NewUpdateService(repo, vpn)
	}
	server := New(settings, importer, updater, nil, nil, nil, Sources{}, LogAccess{})
	return server, start(t, server)
}

func TestUpdateEndpoint(t *testing.T) {
	repo := &fakeBinaryRepo{current: "1.12.0", latest: "1.14.2"}
	server, base := newUpdateTestServer(t, repo)
	session := login(t, server)

	status, data := call(t, "POST", base+"/api/update", session, map[string]string{})
	if status != http.StatusOK || data["updated"] != true || data["latest"] != "1.14.2" || data["current"] != "1.12.0" {
		t.Fatalf("update: status %d: %v", status, data)
	}
	if !repo.installed {
		t.Fatal("the new binary was not installed")
	}

	// Up to date: nothing installed, not an error
	repo.installed = false
	repo.current = "1.14.2"
	status, data = call(t, "POST", base+"/api/update", session, map[string]string{})
	if status != http.StatusOK || data["updated"] != false || repo.installed {
		t.Fatalf("update when current: status %d: %v (installed %v)", status, data, repo.installed)
	}

	// A failed download is reported and installs nothing
	repo.current = "1.12.0"
	repo.downloadErr = errors.New("checksum mismatch")
	status, data = call(t, "POST", base+"/api/update", session, map[string]string{})
	if status == http.StatusOK || !strings.Contains(data["error"].(string), "checksum mismatch") || repo.installed {
		t.Fatalf("failed download: status %d: %v (installed %v)", status, data, repo.installed)
	}
}

func TestUpdateEndpointWithoutUpdater(t *testing.T) {
	server, base := newUpdateTestServer(t, nil)
	session := login(t, server)
	if status, _ := call(t, "POST", base+"/api/update", session, map[string]string{}); status == http.StatusOK {
		t.Fatal("update without an update service accepted")
	}
}
