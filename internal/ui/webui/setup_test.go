package webui

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tray-sing-box/internal/domain"
	"tray-sing-box/internal/infrastructure/configfile"
	"tray-sing-box/internal/infrastructure/sharelink"
)

// A fresh install has no config.json: the page is told so (instead of an
// error) and may create the first one — once, through the guard
func TestFirstConfigFromThePage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	editor := configfile.New(path)
	vpn := domain.NewVPNService(&nopProcessManager{}, &nopStorage{})
	settings := domain.NewSettingsService(editor, vpn)
	importer := domain.NewImportService(sharelink.Parser{}, editor, vpn)
	server := New(settings, importer, nil, nil, nil, nil, Sources{}, LogAccess{})
	base := start(t, server)
	session := login(t, server)

	status, cfg := call(t, "GET", base+"/api/config", session, nil)
	if status != http.StatusOK || cfg["missing"] != true || !strings.Contains(fmt.Sprint(cfg["detail"]), path) {
		t.Fatalf("GET /api/config without a config: %d %v", status, cfg)
	}

	// Not without a session
	if status, _ := call(t, "POST", base+"/api/config/create", "", map[string]string{"content": testConfig}); status != http.StatusUnauthorized {
		t.Fatalf("create without a session: %d", status)
	}

	// The guard applies: a proxy for the whole LAN is refused, nothing written
	lan := `{"inbounds":[{"type":"mixed","tag":"in","listen":"0.0.0.0","listen_port":2080}],"outbounds":[{"type":"direct","tag":"direct"}]}`
	if status, resp := call(t, "POST", base+"/api/config/create", session, map[string]string{"content": lan}); status != http.StatusBadRequest {
		t.Fatalf("a LAN listener accepted: %d %v", status, resp)
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("config.json written for a refused config")
	}

	if status, resp := call(t, "POST", base+"/api/config/create", session, map[string]string{"content": testConfig}); status != http.StatusOK {
		t.Fatalf("create: %d %v", status, resp)
	}
	status, cfg = call(t, "GET", base+"/api/config", session, nil)
	if status != http.StatusOK || cfg["missing"] != nil || !strings.Contains(fmt.Sprint(cfg["outbounds"]), `"p1"`) {
		t.Fatalf("GET /api/config after create: %d %v", status, cfg)
	}

	// Never a second time: the config is edited by sections from now on
	status, resp := call(t, "POST", base+"/api/config/create", session, map[string]string{"content": `{"outbounds":[]}`})
	if status != http.StatusBadRequest || !strings.Contains(fmt.Sprint(resp["error"]), "уже есть") {
		t.Fatalf("second create: %d %v", status, resp)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), `"p1"`) {
		t.Fatalf("the config was replaced: %s", data)
	}
}
