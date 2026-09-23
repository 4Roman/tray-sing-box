package domain

import (
	"errors"
	"testing"
)

type fakeAppRepo struct {
	latest      AppRelease
	latestErr   error
	downloadErr error
	installErr  error
	downloads   int
	installed   string
	relaunched  int
}

func (f *fakeAppRepo) LatestRelease() (AppRelease, error) { return f.latest, f.latestErr }
func (f *fakeAppRepo) Download(r AppRelease) (string, error) {
	f.downloads++
	if f.downloadErr != nil {
		return "", f.downloadErr
	}
	return "staged-" + r.Version, nil
}
func (f *fakeAppRepo) Install(staged string) error {
	if f.installErr != nil {
		return f.installErr
	}
	f.installed = staged
	return nil
}
func (f *fakeAppRepo) Relaunch() error { f.relaunched++; return nil }

func TestIsReleaseVersion(t *testing.T) {
	for v, want := range map[string]bool{
		"v1.2.3": true, "1.2.3": true, " v1.0.0 ": true,
		"dev": false, "b056ce3-dirty": false, "v1.2.3-4-gabcdef": false, "v1.2.3-dirty": false, "1.2": false,
	} {
		if got := IsReleaseVersion(v); got != want {
			t.Errorf("IsReleaseVersion(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestAppUpdateUpToDate(t *testing.T) {
	repo := &fakeAppRepo{latest: AppRelease{Version: "1.2.0"}}
	svc := NewAppUpdateService(repo, "v1.2.0")

	result, err := svc.Update()
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if result.Available || result.Installed || repo.downloads != 0 {
		t.Fatalf("must not update when up to date: %+v", result)
	}
}

func TestAppUpdateNoDowngrade(t *testing.T) {
	repo := &fakeAppRepo{latest: AppRelease{Version: "1.1.9"}}
	svc := NewAppUpdateService(repo, "v1.2.0")

	result, _ := svc.Update()
	if result.Available || repo.downloads != 0 {
		t.Fatalf("must not downgrade: %+v", result)
	}
}

func TestAppUpdateInstallsNewerAndRelaunches(t *testing.T) {
	repo := &fakeAppRepo{latest: AppRelease{Version: "1.3.0", Notes: "fixes"}}
	svc := NewAppUpdateService(repo, "v1.2.0")

	if err := svc.Relaunch(); err == nil {
		t.Fatal("Relaunch before an update must fail")
	}

	result, err := svc.Update()
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if !result.Available || !result.Installed || result.Notes != "fixes" {
		t.Fatalf("result = %+v", result)
	}
	if repo.installed != "staged-1.3.0" {
		t.Fatalf("installed = %q", repo.installed)
	}
	if !svc.Installed() {
		t.Fatal("Installed() false after an install")
	}

	// A second Update must not download again — the exe on disk is already
	// the new one, only the relaunch is missing. It must report the version
	// ON DISK, not a newer one GitHub published meanwhile, and it must work
	// without the network at all.
	repo.latest = AppRelease{Version: "1.4.0"}
	repo.latestErr = errors.New("offline")
	again, err := svc.Update()
	if err != nil || repo.downloads != 1 {
		t.Fatalf("second Update: err=%v downloads=%d", err, repo.downloads)
	}
	if !again.Installed || again.LatestVersion != "1.3.0" || again.Notes != "fixes" {
		t.Fatalf("pending relaunch misreported: %+v", again)
	}
	if svc.InstalledVersion() != "1.3.0" {
		t.Fatalf("InstalledVersion = %q", svc.InstalledVersion())
	}
	repo.latestErr = nil

	if err := svc.Relaunch(); err != nil || repo.relaunched != 1 {
		t.Fatalf("Relaunch: %v (relaunched=%d)", err, repo.relaunched)
	}
}

// A development build ("b056ce3-dirty") cannot be compared: a release is
// offered on request, but the build must never be reported as outdated by a
// silent background check (see Check callers)
func TestAppUpdateDevBuildTakesAnyRelease(t *testing.T) {
	repo := &fakeAppRepo{latest: AppRelease{Version: "0.1.0"}}
	svc := NewAppUpdateService(repo, "b056ce3-dirty")

	result, err := svc.Check()
	if err != nil || !result.Available {
		t.Fatalf("dev build must see a release as available: %+v (%v)", result, err)
	}

	// ...but not a non-release tag
	repo.latest = AppRelease{Version: "0.1.0-rc1"}
	if result, _ := svc.Check(); result.Available {
		t.Fatalf("pre-release offered to a dev build: %+v", result)
	}
}

func TestAppUpdateFailuresLeaveNothingInstalled(t *testing.T) {
	repo := &fakeAppRepo{latest: AppRelease{Version: "1.3.0"}, downloadErr: errors.New("network down")}
	svc := NewAppUpdateService(repo, "v1.2.0")
	if _, err := svc.Update(); err == nil || svc.Installed() {
		t.Fatalf("download failure: err=%v installed=%v", err, svc.Installed())
	}

	repo = &fakeAppRepo{latest: AppRelease{Version: "1.3.0"}, installErr: errors.New("access denied")}
	svc = NewAppUpdateService(repo, "v1.2.0")
	if _, err := svc.Update(); err == nil || svc.Installed() {
		t.Fatalf("install failure: err=%v installed=%v", err, svc.Installed())
	}

	repo = &fakeAppRepo{latestErr: errors.New("api down")}
	svc = NewAppUpdateService(repo, "v1.2.0")
	if _, err := svc.Update(); err == nil {
		t.Fatal("API failure must be reported")
	}
}
