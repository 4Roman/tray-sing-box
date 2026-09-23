package webui

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tray-sing-box/internal/domain"
	"tray-sing-box/internal/infrastructure/configfile"
	"tray-sing-box/internal/infrastructure/logtail"
	"tray-sing-box/internal/infrastructure/sharelink"
)

// TestLogsEndpoint wires the real logtail reader over a temp dir and checks
// the /api/logs response shape: present file with content, absent file
// flagged as missing.
func TestLogsEndpoint(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	// log.output configured but the sing-box log file itself does not exist
	cfg := `{"log": {"output": "sing-box.log"}, "outbounds": [{"type": "direct", "tag": "direct"}]}`
	if err := os.WriteFile(configPath, []byte(cfg), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tray-sing-box.log"), []byte("hello log\n"), 0644); err != nil {
		t.Fatal(err)
	}

	editor := configfile.New(configPath)
	vpn := domain.NewVPNService(&nopProcessManager{}, &nopStorage{})
	settings := domain.NewSettingsService(editor, vpn)
	importer := domain.NewImportService(sharelink.Parser{}, editor, vpn)

	reader := logtail.New(dir)
	server := New(settings, importer, nil, nil, nil, nil, Sources{}, LogAccess{
		Files: func() []LogFile {
			var files []LogFile
			for _, f := range reader.Files() {
				files = append(files, LogFile{ID: f.ID, Path: f.Path})
			}
			return files
		},
		Tail: logtail.Tail,
	})
	base := start(t, server)

	status, data := call(t, http.MethodGet, base+"/api/logs", login(t, server), nil)
	if status != http.StatusOK {
		t.Fatalf("logs: status %d", status)
	}
	files, ok := data["files"].([]any)
	if !ok || len(files) != 2 {
		t.Fatalf("want 2 log files, got %#v", data["files"])
	}

	app := files[0].(map[string]any)
	if app["id"] != "app" || app["missing"] == true {
		t.Fatalf("unexpected app entry: %#v", app)
	}
	if !strings.Contains(app["content"].(string), "hello log") {
		t.Fatalf("app log content lost: %#v", app["content"])
	}

	sb := files[1].(map[string]any)
	if sb["id"] != "singbox" || sb["missing"] != true {
		t.Fatalf("sing-box log must be reported missing: %#v", sb)
	}
}

// TestLogsEndpointRequiresSession ensures /api/logs sits behind the session
// check
func TestLogsEndpointRequiresSession(t *testing.T) {
	_, base := newTestServer(t, nil)

	status, _ := call(t, http.MethodGet, base+"/api/logs", "", nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("logs without a session: status %d", status)
	}
}
