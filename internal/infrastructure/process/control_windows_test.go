//go:build windows

package process

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"tray-sing-box/internal/config"
)

// The quit handshake within one process: the watcher's callback runs once
// the event is signalled. Private object names: the real quit event would
// end a tray app running on the developer machine
func TestQuitRequest(t *testing.T) {
	usePrivateObjectNames(t)
	// No instance yet: nothing to quit, no error
	if ok, err := RequestQuit(); err != nil || ok {
		t.Fatalf("RequestQuit without a watcher = %v, %v", ok, err)
	}

	quit := make(chan struct{}, 1)
	if err := WatchQuitRequest(func() { quit <- struct{}{} }); err != nil {
		t.Fatalf("WatchQuitRequest: %v", err)
	}
	ok, err := RequestQuit()
	if err != nil || !ok {
		t.Fatalf("RequestQuit = %v, %v", ok, err)
	}
	select {
	case <-quit:
	case <-time.After(5 * time.Second):
		t.Fatal("quit callback never ran")
	}
}

// StopInstallation itself: the tray app (the fake under the app's own exe
// name) and the sing-box of one directory end, the same image in another
// directory survives. Antivirus heuristics may take this shape of test (a
// fresh unsigned binary that copies itself and terminates its copies) for a
// trojan and delete the test binary: build tests in a GOTMPDIR the antivirus
// does not scan.
func TestStopInstallation(t *testing.T) {
	dir := installFakeSingBox(t, "run")
	other := installFakeSingBox(t, "run") // same image names, another directory
	mOther := NewAt(other)
	t.Cleanup(func() { mOther.Stop() })
	if err := mOther.Start(); err != nil {
		t.Fatalf("start other: %v", err)
	}

	trayCopy := filepath.Join(dir, config.AppExeName)
	data, err := os.ReadFile(filepath.Join(dir, config.SingBoxExe))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(trayCopy, data, 0755); err != nil {
		t.Fatal(err)
	}
	tray := NewHiddenCommand(trayCopy, "run")
	if err := tray.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tray.Process.Kill(); tray.Wait() })
	m := NewAt(dir)
	if err := m.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { m.Stop() })

	stopped, err := StopInstallation(dir)
	if err != nil {
		t.Fatalf("StopInstallation: %v", err)
	}
	if stopped != 2 {
		t.Fatalf("stopped %d processes, want 2 (tray app + sing-box)", stopped)
	}
	if pids, _ := findProcesses(filepath.Join(dir, config.SingBoxExe)); len(pids) != 0 {
		t.Fatalf("sing-box of the installation still running: %v", pids)
	}
	if pids, _ := findProcesses(trayCopy); len(pids) != 0 {
		t.Fatalf("tray app of the installation still running: %v", pids)
	}
	if !mOther.IsRunning() {
		t.Fatal("the other installation's sing-box was stopped too")
	}
}

// StopProcessesOf (what StopInstallation is built on) ends every named
// exe of the given directory. The fake plays both processes; the second
// one runs under a neutral name — a test binary that copies itself under
// the app's own exe name trips the antivirus on the developer machine.
// That another directory's sing-box survives is covered by
// TestManagerIgnoresForeignInstallation (same full-path matching).
func TestStopProcessesOf(t *testing.T) {
	dir := installFakeSingBox(t, "run")
	const helperName = "helper-fake.exe"
	helperPath := filepath.Join(dir, helperName)
	data, _ := os.ReadFile(filepath.Join(dir, config.SingBoxExe))
	if err := os.WriteFile(helperPath, data, 0755); err != nil {
		t.Fatal(err)
	}
	helper := NewHiddenCommand(helperPath, "run")
	if err := helper.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { helper.Process.Kill(); helper.Wait() })
	m := NewAt(dir)
	if err := m.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { m.Stop() })

	stopped, err := StopProcessesOf(dir, helperName, config.SingBoxExe)
	if err != nil {
		t.Fatalf("StopProcessesOf: %v", err)
	}
	if stopped != 2 {
		t.Fatalf("stopped %d processes, want 2", stopped)
	}
	if pids, _ := findProcesses(filepath.Join(dir, config.SingBoxExe)); len(pids) != 0 {
		t.Fatalf("sing-box of the installation still running: %v", pids)
	}
	if pids, _ := findProcesses(helperPath); len(pids) != 0 {
		t.Fatalf("helper of the installation still running: %v", pids)
	}
}

func TestWaitForInstanceExitWithoutInstance(t *testing.T) {
	usePrivateObjectNames(t) // the real mutex may well be held by a live instance
	// No mutex of ours in this test process: returns at once
	if InstanceRunning() {
		t.Fatal("InstanceRunning without an instance")
	}
	start := time.Now()
	if err := WaitForInstanceExit(5 * time.Second); err != nil {
		t.Fatalf("WaitForInstanceExit: %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("waited although no instance exists")
	}
}

// The mutex taken by AcquireSingleInstance is what InstanceRunning and
// WaitForInstanceExit look at
func TestInstanceRunningSeesTheSingleInstanceMutex(t *testing.T) {
	usePrivateObjectNames(t)
	if !AcquireSingleInstance() {
		t.Fatal("AcquireSingleInstance with a fresh private name")
	}
	if !InstanceRunning() {
		t.Fatal("InstanceRunning must see the mutex this process holds")
	}
	// A second attempt (same owner: genuine) loses, and closes its handle
	if AcquireSingleInstance() {
		t.Fatal("a second AcquireSingleInstance must lose against a genuine holder")
	}
	if err := WaitForInstanceExit(300 * time.Millisecond); err == nil {
		t.Fatal("WaitForInstanceExit must time out while the mutex is held")
	}
}

// `--uninstall-cleanup` runs from the very installation it cleans up: the
// helper must not terminate itself before it reaches sing-box, the task and
// the registry key
func TestStopProcessesOfSkipsTheCallingProcess(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	n, err := StopProcessesOf(filepath.Dir(self), filepath.Base(self))
	if err != nil {
		t.Fatalf("StopProcessesOf on our own exe: %v", err)
	}
	if n != 0 {
		t.Fatalf("stopped %d processes, want 0 (only this process runs that exe)", n)
	}
	// Still alive, obviously — the assertion is the line above being reached
}

// usePrivateObjectNames points the kernel object names at per-process,
// per-test names for the duration of the test (a mutex taken by
// AcquireSingleInstance lives until the process exits, so tests must not
// share names)
func usePrivateObjectNames(t *testing.T) {
	t.Helper()
	oldMutex, oldEvent, oldMarker, oldSDDL, oldTrust := instanceMutexName, quitEventName, markerPrefix, objectSDDL, trustCurrentUser
	suffix := fmt.Sprintf("-test-%d-%s", os.Getpid(), t.Name())
	instanceMutexName, quitEventName, markerPrefix = oldMutex+suffix, oldEvent+suffix, oldMarker+suffix+"-"
	// A non-elevated test process cannot make Administrators the owner
	if !windows.GetCurrentProcessToken().IsElevated() {
		if user, err := windows.GetCurrentProcessToken().GetTokenUser(); err == nil {
			objectSDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;" + user.User.Sid.String() + ")"
		}
		trustCurrentUser = true
	}
	t.Cleanup(func() {
		instanceMutexName, quitEventName, markerPrefix, objectSDDL, trustCurrentUser = oldMutex, oldEvent, oldMarker, oldSDDL, oldTrust
	})
}

// The marker ties "the running instance" to a directory
func TestInstallationMarker(t *testing.T) {
	usePrivateObjectNames(t)
	dir := t.TempDir()
	if InstallationRunning(dir) {
		t.Fatal("marked before MarkInstallation")
	}
	if err := MarkInstallation(dir); err != nil {
		t.Fatalf("MarkInstallation: %v", err)
	}
	t.Cleanup(func() { windows.CloseHandle(markerHandle); markerHandle = 0 })
	if !InstallationRunning(dir) {
		t.Fatal("marker not seen")
	}
	if !InstallationRunning(strings.ToUpper(dir) + `\`) {
		t.Fatal("marker must not depend on case or a trailing separator")
	}
	if InstallationRunning(t.TempDir()) {
		t.Fatal("another directory counted as marked")
	}
}
