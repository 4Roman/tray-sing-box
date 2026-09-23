package webui

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"tray-sing-box/internal/domain"
	"tray-sing-box/internal/infrastructure/configfile"
	"tray-sing-box/internal/infrastructure/sharelink"
)

// fakeAppRepo stands in for the GitHub-backed self-updater
type fakeAppRepo struct {
	latest     domain.AppRelease
	installed  bool
	relaunched bool
}

func (f *fakeAppRepo) LatestRelease() (domain.AppRelease, error) { return f.latest, nil }
func (f *fakeAppRepo) Download(r domain.AppRelease) (string, error) {
	return "staged-" + r.Version, nil
}
func (f *fakeAppRepo) Install(string) error { f.installed = true; return nil }
func (f *fakeAppRepo) Relaunch() error      { f.relaunched = true; return nil }

func newAppUpdateServer(t *testing.T, repo *fakeAppRepo) (*Server, string, chan struct{}) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(testConfig), 0644); err != nil {
		t.Fatal(err)
	}
	editor := configfile.New(path)
	vpn := domain.NewVPNService(&nopProcessManager{}, &nopStorage{})
	server := New(domain.NewSettingsService(editor, vpn), domain.NewImportService(sharelink.Parser{}, editor, vpn),
		nil, nil, nil, nil, Sources{}, LogAccess{})

	relaunched := make(chan struct{}, 1)
	if repo != nil {
		svc := domain.NewAppUpdateService(repo, "v1.0.0")
		server.SetAppUpdater(svc, func() {
			svc.Relaunch()
			relaunched <- struct{}{}
		})
	}
	return server, start(t, server), relaunched
}

// Without a configured updater the page hides the section and the actions
// fail with a clear message
func TestAppUpdateNotConfigured(t *testing.T) {
	server, base, _ := newAppUpdateServer(t, nil)
	session := login(t, server)

	status, data := call(t, http.MethodGet, base+"/api/app-update", session, nil)
	if status != http.StatusOK || data["configured"] != false {
		t.Fatalf("check: status %d, data %v", status, data)
	}
	if status, _ := call(t, http.MethodPost, base+"/api/app-update", session, map[string]any{}); status == http.StatusOK {
		t.Fatal("update succeeded without a configured updater")
	}
	if status, _ := call(t, http.MethodPost, base+"/api/app-update/relaunch", session, map[string]any{}); status == http.StatusOK {
		t.Fatal("relaunch succeeded without a configured updater")
	}
}

// Check -> update (installs, no relaunch yet) -> relaunch (after the
// response, through the app's callback)
func TestAppUpdateFlow(t *testing.T) {
	repo := &fakeAppRepo{latest: domain.AppRelease{Version: "1.1.0", Notes: "notes"}}
	server, base, relaunched := newAppUpdateServer(t, repo)
	session := login(t, server)

	// A relaunch before an update must be refused
	if status, _ := call(t, http.MethodPost, base+"/api/app-update/relaunch", session, map[string]any{}); status == http.StatusOK {
		t.Fatal("relaunch without an installed update succeeded")
	}

	status, data := call(t, http.MethodGet, base+"/api/app-update", session, nil)
	if status != http.StatusOK || data["configured"] != true || data["available"] != true || data["latest"] != "1.1.0" || data["installed"] != false {
		t.Fatalf("check: status %d, data %v", status, data)
	}

	status, data = call(t, http.MethodPost, base+"/api/app-update", session, map[string]any{})
	if status != http.StatusOK || data["installed"] != true || data["latest"] != "1.1.0" {
		t.Fatalf("update: status %d, data %v", status, data)
	}
	if !repo.installed || repo.relaunched {
		t.Fatalf("installed=%v relaunched=%v after update, want true/false", repo.installed, repo.relaunched)
	}

	status, data = call(t, http.MethodPost, base+"/api/app-update/relaunch", session, map[string]any{})
	if status != http.StatusOK || data["relaunching"] != true {
		t.Fatalf("relaunch: status %d, data %v", status, data)
	}
	select {
	case <-relaunched:
	case <-time.After(5 * time.Second):
		t.Fatal("relaunch callback not called")
	}
	if !repo.relaunched {
		t.Fatal("repository Relaunch not called")
	}

	if status, _ := call(t, http.MethodGet, base+"/api/app-update", "", nil); status != http.StatusUnauthorized {
		t.Fatalf("app-update without a session: status %d", status)
	}
}
