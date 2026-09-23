package domain

import (
	"errors"
	"testing"
)

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.12.4", "1.12.4", 0},
		{"1.12.3", "1.12.4", -1},
		{"1.13.0", "1.12.9", 1},
		{"1.12", "1.12.0", 0},
		{"v1.12.4", "1.12.4", 0},
		{"1.13.0-alpha.1", "1.13.0", -1},
		{"1.13.0", "1.13.0-beta.2", 1},
		{"1.13.0-alpha.1", "1.13.0-alpha.2", -1},
		{"2.0.0", "1.99.99", 1},
	}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

type fakeRepo struct {
	current     string
	latest      ReleaseInfo
	latestErr   error
	downloadErr error
	installErr  error
	installed   bool
}

func (f *fakeRepo) CurrentVersion() (string, error) { return f.current, nil }
func (f *fakeRepo) LatestRelease() (ReleaseInfo, error) {
	return f.latest, f.latestErr
}
func (f *fakeRepo) Download(r ReleaseInfo) (string, error) {
	if f.downloadErr != nil {
		return "", f.downloadErr
	}
	return "staged.exe", nil
}
func (f *fakeRepo) Install(staged string) error {
	if f.installErr != nil {
		return f.installErr
	}
	f.installed = true
	return nil
}

func TestUpdateUpToDate(t *testing.T) {
	repo := &fakeRepo{current: "1.12.4", latest: ReleaseInfo{Version: "1.12.4"}}
	svc := NewUpdateService(repo, NewVPNService(&fakeProcessManager{}, &fakeStorage{}))

	result, err := svc.Update()
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if result.Updated || repo.installed {
		t.Fatalf("must not update when versions match: %+v", result)
	}
}

func TestUpdateNewerCurrentNotDowngraded(t *testing.T) {
	repo := &fakeRepo{current: "1.13.0-beta.1", latest: ReleaseInfo{Version: "1.12.4"}}
	svc := NewUpdateService(repo, NewVPNService(&fakeProcessManager{}, &fakeStorage{}))

	result, err := svc.Update()
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if result.Updated || repo.installed {
		t.Fatalf("must not downgrade: %+v", result)
	}
}

func TestUpdateInstallsAndRestarts(t *testing.T) {
	repo := &fakeRepo{current: "1.12.3", latest: ReleaseInfo{Version: "1.12.4", AssetURL: "url"}}
	pm := &fakeProcessManager{running: true}
	svc := NewUpdateService(repo, NewVPNService(pm, &fakeStorage{state: true}))

	result, err := svc.Update()
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if !result.Updated || !repo.installed {
		t.Fatalf("binary not installed: %+v", result)
	}
	if !result.Restarted || !pm.IsRunning() {
		t.Fatalf("VPN not restarted: %+v", result)
	}
}

// The binary swap is a maintenance stop: a VPN that fails to come back must
// not flip the stored intent to "stopped" (it would stay off after reboots),
// and the failure must reach the user.
func TestUpdateFailedRestartKeepsIntentAndReports(t *testing.T) {
	repo := &fakeRepo{current: "1.12.3", latest: ReleaseInfo{Version: "1.12.4", AssetURL: "url"}}
	pm := &fakeProcessManager{running: true, startErr: errors.New("blocked by antivirus")}
	st := &fakeStorage{state: true}
	svc := NewUpdateService(repo, NewVPNService(pm, st))

	result, err := svc.Update()
	if err == nil {
		t.Fatal("a VPN that did not start again must be reported")
	}
	if !result.Updated || result.Restarted {
		t.Fatalf("result = %+v, want Updated without Restarted", result)
	}
	if state, saves := st.snapshot(); !state || saves != 0 {
		t.Fatalf("update touched the intent: state=%v saves=%d", state, saves)
	}
}

func TestUpdateFreshInstall(t *testing.T) {
	repo := &fakeRepo{current: "", latest: ReleaseInfo{Version: "1.12.4", AssetURL: "url"}}
	svc := NewUpdateService(repo, NewVPNService(&fakeProcessManager{}, &fakeStorage{}))

	result, err := svc.Update()
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if !result.Updated || result.CurrentVersion != "" {
		t.Fatalf("fresh install failed: %+v", result)
	}
}

func TestUpdateDownloadFailureKeepsVPNRunning(t *testing.T) {
	repo := &fakeRepo{
		current:     "1.12.3",
		latest:      ReleaseInfo{Version: "1.12.4", AssetURL: "url"},
		downloadErr: errors.New("network down"),
	}
	pm := &fakeProcessManager{running: true}
	svc := NewUpdateService(repo, NewVPNService(pm, &fakeStorage{state: true}))

	if _, err := svc.Update(); err == nil {
		t.Fatal("expected download error")
	}
	if !pm.IsRunning() {
		t.Fatal("VPN must keep running when the download fails")
	}
}
