package domain

import (
	"errors"
	"fmt"
	"strings"
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

	stagedCheckErr    error // `sing-box check` of the download
	installedCheckErr error // `sing-box check` of the installed binary
	rollbackErr       error
	rolledBack        bool
	onRollback        func() // called inside Rollback
	calls             []string
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
func (f *fakeRepo) CheckConfig(binary string) error {
	if binary == "" {
		f.calls = append(f.calls, "check installed")
		return f.installedCheckErr
	}
	f.calls = append(f.calls, "check "+binary)
	return f.stagedCheckErr
}
func (f *fakeRepo) Discard(staged string) error {
	f.calls = append(f.calls, "discard "+staged)
	return nil
}
func (f *fakeRepo) Install(staged string) error {
	f.calls = append(f.calls, "install "+staged)
	if f.installErr != nil {
		return f.installErr
	}
	f.installed = true
	return nil
}
func (f *fakeRepo) Rollback() error {
	f.calls = append(f.calls, "rollback")
	if f.onRollback != nil {
		f.onRollback()
	}
	if f.rollbackErr != nil {
		return f.rollbackErr
	}
	f.rolledBack = true
	return nil
}

// startHook: a start with the new binary installed fails with newErr, one
// with the old binary (never replaced, or put back) with oldErr
func (f *fakeRepo) startHook(newErr, oldErr error) func() error {
	return func() error {
		if f.installed && !f.rolledBack {
			return newErr
		}
		return oldErr
	}
}

func sameCalls(got []string, want ...string) bool {
	return strings.Join(got, "|") == strings.Join(want, "|")
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
// and the failure must reach the user — here neither version starts, so the
// rollback brings back a version that fails as well, and both errors are told.
func TestUpdateFailedRestartKeepsIntentAndReports(t *testing.T) {
	repo := &fakeRepo{current: "1.12.3", latest: ReleaseInfo{Version: "1.12.4", AssetURL: "url"}}
	newErr, oldErr := errors.New("blocked by antivirus"), errors.New("TUN adapter busy")
	pm := &fakeProcessManager{running: true}
	pm.startHook = repo.startHook(newErr, oldErr)
	st := &fakeStorage{state: true}
	svc := NewUpdateService(repo, NewVPNService(pm, st))

	result, err := svc.Update()
	if err == nil {
		t.Fatal("a VPN that did not start again must be reported")
	}
	if result.Updated || !result.RolledBack || result.Restarted {
		t.Fatalf("result = %+v, want rolled back without Restarted", result)
	}
	if !errors.Is(err, newErr) || !errors.Is(err, oldErr) || !strings.Contains(err.Error(), "но и она не запустилась") {
		t.Fatalf("error = %v, want both start failures", err)
	}
	if pm.startCount() != 2 || pm.IsRunning() {
		t.Fatalf("starts = %d, running = %v, want the new and the old version tried once each", pm.startCount(), pm.IsRunning())
	}
	if state, saves := st.snapshot(); !state || saves != 0 {
		t.Fatalf("update touched the intent: state=%v saves=%d", state, saves)
	}
}

// A newer sing-box that refuses the config the installed one runs with
// would leave the VPN down: the update is called off before anything is
// stopped, and the download goes
func TestUpdateRefusedWhenOnlyTheNewVersionRejectsTheConfig(t *testing.T) {
	checkErr := errors.New("FATAL[0000] decode config at config.json: inbounds[0].sniff: unknown field")
	repo := &fakeRepo{
		current:        "1.11.4",
		latest:         ReleaseInfo{Version: "1.14.2", AssetURL: "url"},
		stagedCheckErr: checkErr,
	}
	pm := &fakeProcessManager{running: true}
	st := &fakeStorage{state: true}
	svc := NewUpdateService(repo, NewVPNService(pm, st))

	result, err := svc.Update()
	if err == nil {
		t.Fatal("an update that would break the config must be refused")
	}
	if !errors.Is(err, checkErr) {
		t.Fatalf("error = %v, want sing-box's own message in it", err)
	}
	for _, want := range []string{"1.14.2", "1.11.4", "Обновление отменено"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %q, want %q in it", err, want)
		}
	}
	if !result.ConfigRejected || result.Updated || result.Restarted {
		t.Fatalf("result = %+v", result)
	}
	if !sameCalls(repo.calls, "check staged.exe", "check installed", "discard staged.exe") {
		t.Fatalf("calls = %v, want both checks and the download discarded, nothing installed", repo.calls)
	}
	if !pm.IsRunning() || pm.startCount() != 0 {
		t.Fatalf("the VPN was touched: running=%v starts=%d", pm.IsRunning(), pm.startCount())
	}
	if state, saves := st.snapshot(); !state || saves != 0 {
		t.Fatalf("update touched the intent: state=%v saves=%d", state, saves)
	}
}

// When the installed binary refuses the config as well (or there is none),
// the new version may be exactly what the config needs: the update goes on
func TestUpdateProceedsWhenTheInstalledVersionRejectsTheConfigToo(t *testing.T) {
	for name, tc := range map[string]struct {
		current      string
		installedErr error
	}{
		"both refuse":         {"1.11.4", errors.New("unknown field \"endpoints\"")},
		"no installed binary": {"", fmt.Errorf("%w at: sing-box.exe", ErrSingBoxMissing)},
	} {
		repo := &fakeRepo{
			current:           tc.current,
			latest:            ReleaseInfo{Version: "1.14.2", AssetURL: "url"},
			stagedCheckErr:    errors.New("outbounds[1]: unknown field"),
			installedCheckErr: tc.installedErr,
		}
		svc := NewUpdateService(repo, NewVPNService(&fakeProcessManager{}, &fakeStorage{}))

		result, err := svc.Update()
		if err != nil {
			t.Fatalf("%s: Update: %v", name, err)
		}
		if !result.Updated || result.ConfigRejected {
			t.Fatalf("%s: result = %+v", name, result)
		}
		if !sameCalls(repo.calls, "check staged.exe", "check installed", "install staged.exe") {
			t.Fatalf("%s: calls = %v", name, repo.calls)
		}
	}
}

// A config the new version accepts (or no config.json yet — the repository
// answers nil then) needs no second opinion
func TestUpdateChecksTheConfigBeforeTheSwap(t *testing.T) {
	repo := &fakeRepo{current: "1.12.3", latest: ReleaseInfo{Version: "1.12.4", AssetURL: "url"}}
	svc := NewUpdateService(repo, NewVPNService(&fakeProcessManager{running: true}, &fakeStorage{state: true}))

	if _, err := svc.Update(); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if !sameCalls(repo.calls, "check staged.exe", "install staged.exe") {
		t.Fatalf("calls = %v", repo.calls)
	}
}

// A new version that installs but does not start is rolled back and the old
// one started again — within the one maintenance stop: the crash monitor
// must not get to retry the new binary in between, and the intent is not
// written
func TestUpdateRollsBackANewVersionThatDoesNotStart(t *testing.T) {
	repo := &fakeRepo{current: "1.11.4", latest: ReleaseInfo{Version: "1.14.2", AssetURL: "url"}}
	startErr := errors.New("sing-box exited right after start (exit status 1):\nFATAL[0000] start service: initialize inbound[0]")
	pm := &fakeProcessManager{running: true}
	pm.startHook = repo.startHook(startErr, nil)
	st := &fakeStorage{state: true}
	vpn := NewVPNService(pm, st)
	svc := NewUpdateService(repo, vpn)
	// The monitor ticks while the rollback is under way: it must find the
	// lifecycle busy
	repo.onRollback = func() { vpn.monitorTick(VPNStatusStopped) }

	result, err := svc.Update()
	if err == nil {
		t.Fatal("a new version that did not start must be reported")
	}
	if !errors.Is(err, startErr) {
		t.Fatalf("error = %v, want the start error in it", err)
	}
	for _, want := range []string{"1.14.2", "Возвращена прежняя версия 1.11.4", "VPN снова работает"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %q, want %q in it", err, want)
		}
	}
	if !result.RolledBack || result.Updated || !result.Restarted {
		t.Fatalf("result = %+v, want rolled back and restarted", result)
	}
	if !sameCalls(repo.calls, "check staged.exe", "install staged.exe", "rollback") {
		t.Fatalf("calls = %v", repo.calls)
	}
	if pm.startCount() != 2 || !pm.IsRunning() {
		t.Fatalf("starts = %d, running = %v, want the new version tried, then the old one running", pm.startCount(), pm.IsRunning())
	}
	if state, saves := st.snapshot(); !state || saves != 0 {
		t.Fatalf("update touched the intent: state=%v saves=%d", state, saves)
	}
}

// A rollback that fails is told together with the reason it was needed; no
// start is attempted on a half-restored installation
func TestUpdateRollbackFailure(t *testing.T) {
	repo := &fakeRepo{
		current:     "1.11.4",
		latest:      ReleaseInfo{Version: "1.14.2", AssetURL: "url"},
		rollbackErr: errors.New("failed to restore the previous binary: access denied"),
	}
	startErr := errors.New("sing-box exited right after start")
	pm := &fakeProcessManager{running: true}
	pm.startHook = repo.startHook(startErr, nil)
	st := &fakeStorage{state: true}
	svc := NewUpdateService(repo, NewVPNService(pm, st))

	result, err := svc.Update()
	if !errors.Is(err, startErr) || !errors.Is(err, repo.rollbackErr) || !strings.Contains(err.Error(), "Вернуть прежнюю версию 1.11.4 не удалось") {
		t.Fatalf("error = %v, want the start and the rollback failure", err)
	}
	if result.RolledBack || result.Restarted || !result.Updated {
		t.Fatalf("result = %+v", result)
	}
	if pm.startCount() != 1 {
		t.Fatalf("starts = %d, want only the new version's", pm.startCount())
	}
	if state, saves := st.snapshot(); !state || saves != 0 {
		t.Fatalf("update touched the intent: state=%v saves=%d", state, saves)
	}
}

// A VPN that was off tells nothing about the new version: nothing is started
// and nothing rolled back
func TestUpdateNoRollbackWhenTheVPNWasNotRunning(t *testing.T) {
	repo := &fakeRepo{current: "1.11.4", latest: ReleaseInfo{Version: "1.14.2", AssetURL: "url"}}
	pm := &fakeProcessManager{}
	pm.startHook = repo.startHook(errors.New("would not start"), nil)
	svc := NewUpdateService(repo, NewVPNService(pm, &fakeStorage{}))

	result, err := svc.Update()
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if !result.Updated || result.RolledBack || result.Restarted {
		t.Fatalf("result = %+v", result)
	}
	if pm.startCount() != 0 || repo.rolledBack {
		t.Fatalf("starts = %d, rolled back = %v", pm.startCount(), repo.rolledBack)
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
