package webui

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tray-sing-box/internal/domain"
	"tray-sing-box/internal/infrastructure/configfile"
	"tray-sing-box/internal/infrastructure/sharelink"
)

type stubDPIManager struct{ state domain.ContainerState }

func (s *stubDPIManager) Available() error { return nil }
func (s *stubDPIManager) State() (domain.ContainerState, error) {
	if s.state == "" {
		return domain.ContainerAbsent, nil
	}
	return s.state, nil
}
func (s *stubDPIManager) Start() error             { s.state = domain.ContainerRunning; return nil }
func (s *stubDPIManager) Stop() error              { s.state = domain.ContainerStopped; return nil }
func (s *stubDPIManager) ProxyAddr() (string, int) { return "127.0.0.1", 3128 }

func newDPITestServer(t *testing.T) (*Server, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(testConfig), 0644); err != nil {
		t.Fatal(err)
	}
	editor := configfile.New(path)
	vpn := domain.NewVPNService(&nopProcessManager{}, &nopStorage{})
	settings := domain.NewSettingsService(editor, vpn)
	importer := domain.NewImportService(sharelink.Parser{}, editor, vpn)
	dpi := domain.NewDPIBypassService(&stubDPIManager{}, editor, vpn)

	server := New(settings, importer, nil, dpi, nil, nil, Sources{}, LogAccess{})
	return server, start(t, server)
}

func TestDPIRequiresSession(t *testing.T) {
	_, base := newDPITestServer(t)

	status, _ := call(t, "GET", base+"/api/dpi", "", nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("api/dpi without a session: status %d", status)
	}
}

func TestDPIChainEnableSetsDetour(t *testing.T) {
	server, base := newDPITestServer(t)
	session := login(t, server)

	status, data := call(t, "POST", base+"/api/dpi/chain", session,
		map[string]bool{"enable": true})
	if status != http.StatusOK {
		t.Fatalf("chain enable: status %d: %v", status, data)
	}
	if data["chain"] != true || data["chainTarget"] != "p1" {
		t.Fatalf("chain status wrong: %v", data)
	}

	// The config now has the bypass outbound and a detour on the active proxy
	_, cfg := call(t, "GET", base+"/api/config", session, nil)
	outbounds := cfg["outbounds"].(string)
	if !strings.Contains(outbounds, "dpi-bypass") || !strings.Contains(outbounds, "detour") {
		t.Fatalf("detour not written to config: %s", outbounds)
	}

	// Disabling clears it again
	status, data = call(t, "POST", base+"/api/dpi/chain", session,
		map[string]bool{"enable": false})
	if status != http.StatusOK || data["chain"] != false {
		t.Fatalf("chain disable failed: %d %v", status, data)
	}
}
