//go:build windows

package process

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"tray-sing-box/internal/config"
	"tray-sing-box/internal/domain"
)

// fakeModeEnv turns the test binary into a stand-in for sing-box.exe: the
// lifecycle tests copy it to <temp>\sing-box.exe and let the Manager run it.
// Everything in this package finds and kills processes by FULL image path, so
// a real sing-box.exe running on the machine is never touched.
const fakeModeEnv = "TRAY_SINGBOX_FAKE_MODE"

func TestMain(m *testing.M) {
	if mode := os.Getenv(fakeModeEnv); mode != "" && len(os.Args) > 1 && os.Args[1] == "run" {
		fakeSingBox(mode)
		return
	}
	// Started as "sing-box run ..." without its mode (the environment did
	// not make it): never run the test suite recursively
	if len(os.Args) > 1 && os.Args[1] == "run" {
		os.Exit(3)
	}
	if name := os.Getenv(quitChildEnv); name != "" {
		quitChild(name)
		return
	}
	// The fakes this test starts run at the test's own level (below High on
	// a developer machine): they must count as elevated, like the real
	// sing-box started by the elevated app
	if level, err := ownIntegrity(); err == nil {
		trustedIntegrity = level
	}
	os.Exit(m.Run())
}

func ownIntegrity() (uint32, error) {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return 0, err
	}
	defer token.Close()
	return integrityLevel(token)
}

func fakeSingBox(mode string) {
	switch mode {
	case "crash":
		// Coloured, like the real thing: sing-box prints ANSI escapes even
		// when its output is redirected
		fmt.Fprintln(os.Stderr, "\x1b[31mFATAL\x1b[0m[0000] start service: fake failure for the test")
		os.Exit(1)
	case "die-late":
		fmt.Fprintln(os.Stderr, "INFO[0000] fake sing-box started")
		time.Sleep(1500 * time.Millisecond)
		fmt.Fprintln(os.Stderr, "FATAL[0001] configure tun interface: fake late failure")
		os.Exit(1)
	case "chatty":
		for {
			fmt.Fprintln(os.Stderr, "INFO[0000] connection: a fake log line of a reasonable length")
			time.Sleep(10 * time.Millisecond)
		}
	default:
		fmt.Fprintln(os.Stderr, "INFO[0000] fake sing-box started")
		time.Sleep(2 * time.Minute)
	}
}

// installFakeSingBox prepares a sing-box "installation" in a temp dir
func installFakeSingBox(t *testing.T, mode string) (dir string) {
	t.Helper()
	dir = t.TempDir()

	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	src, err := os.Open(self)
	if err != nil {
		t.Fatalf("open test binary: %v", err)
	}
	defer src.Close()
	dst, err := os.Create(filepath.Join(dir, config.SingBoxExe))
	if err != nil {
		t.Fatalf("create fake sing-box: %v", err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		t.Fatalf("copy fake sing-box: %v", err)
	}
	dst.Close()

	if err := os.WriteFile(filepath.Join(dir, config.SingBoxConfig), []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(fakeModeEnv, mode)
	// The manager builds sing-box's environment from scratch
	// (SingBoxEnv): the mode must be passed explicitly
	old := testEnv
	testEnv = []string{fakeModeEnv + "=" + mode}
	t.Cleanup(func() { testEnv = old })
	return dir
}

// findProcesses replaced "tasklist /FI IMAGENAME eq ..." — check it against
// the real process list: the test binary itself is certainly running.
func TestFindProcessesMatchesByFullPath(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	// Case-insensitive, like Windows paths
	pids, err := findProcesses(strings.ToUpper(self))
	if err != nil {
		t.Fatalf("findProcesses: %v", err)
	}
	found := false
	for _, p := range pids {
		if p.pid == uint32(os.Getpid()) {
			found = true
			if !p.elevated {
				t.Fatal("own process (at the trusted level) not reported as elevated")
			}
		}
	}
	if !found {
		t.Fatalf("own process not found by path %q (got %v)", self, pids)
	}

	// Same image name, other directory: must NOT match. This is what keeps a
	// foreign sing-box.exe (another client's, or the developer's live VPN)
	// from being adopted or killed.
	elsewhere := filepath.Join(t.TempDir(), filepath.Base(self))
	pids, err = findProcesses(elsewhere)
	if err != nil {
		t.Fatalf("findProcesses: %v", err)
	}
	if len(pids) != 0 {
		t.Fatalf("processes of another directory matched %q: %v", elsewhere, pids)
	}
}

func TestSamePath(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "a.exe")
	if err := os.WriteFile(file, nil, 0644); err != nil {
		t.Fatal(err)
	}
	if !samePath(file, strings.ToUpper(file)) {
		t.Fatal("case-insensitive match failed")
	}
	if !samePath(file, filepath.Join(dir, ".", "sub", "..", "a.exe")) {
		t.Fatal("unclean path not matched")
	}
	if samePath(file, filepath.Join(dir, "b.exe")) {
		t.Fatal("different files matched")
	}
}

// The whole life cycle against a real process: start, adopt, stop (and wait
// until it is really gone), idempotent stop.
func TestManagerLifecycle(t *testing.T) {
	dir := installFakeSingBox(t, "run")
	m := NewAt(dir)
	t.Cleanup(func() { m.Stop() })

	if m.IsRunning() {
		t.Fatal("nothing started yet, but IsRunning reports true")
	}
	if err := m.Stop(); err != nil {
		t.Fatalf("Stop with nothing running must succeed: %v", err)
	}

	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !m.IsRunning() {
		t.Fatal("not running after Start")
	}
	pids, err := findProcesses(m.singBoxPath())
	if err != nil || len(pids) != 1 {
		t.Fatalf("want exactly one fake sing-box, got %v (%v)", pids, err)
	}

	// A second manager (the tray app restarted) adopts the running instance
	// instead of starting another one
	adopter := NewAt(dir)
	if !adopter.IsRunning() {
		t.Fatal("running instance not detected by a fresh manager")
	}
	if err := adopter.Start(); err != nil {
		t.Fatalf("adopting Start: %v", err)
	}
	if pids, _ := findProcesses(m.singBoxPath()); len(pids) != 1 {
		t.Fatalf("adopting Start launched another instance: %v", pids)
	}

	// sing-box writes into its own file, not into this process (polled: how
	// soon the child gets to its first line is up to the machine)
	consolePath := filepath.Join(dir, config.SingBoxConsoleLog)
	if !eventually(10*time.Second, func() bool {
		console, _ := os.ReadFile(consolePath)
		return strings.Contains(string(console), "fake sing-box started")
	}) {
		console, err := os.ReadFile(consolePath)
		t.Fatalf("console output not captured: %q (%v)", console, err)
	}

	// Stop returns only when the process is gone: a Start right after must
	// not see a dying instance
	if err := adopter.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if pids, _ := findProcesses(m.singBoxPath()); len(pids) != 0 {
		t.Fatalf("process still listed right after Stop: %v", pids)
	}
	if adopter.IsRunning() {
		t.Fatal("IsRunning still true after Stop")
	}
	// m owned the process that another manager killed: its Wait goroutine
	// clears the flag asynchronously
	if !eventually(5*time.Second, func() bool { return !m.IsRunning() }) {
		t.Fatal("owner still reports running after the process was killed")
	}

	// ...so an immediate restart really starts a new one
	if err := m.Start(); err != nil {
		t.Fatalf("restart: %v", err)
	}
	if pids, _ := findProcesses(m.singBoxPath()); len(pids) != 1 {
		t.Fatalf("restart did not start a new instance: %v", pids)
	}
}

// A sing-box that dies right away (bad config, busy port) is a failed start
// and the error carries what it printed
func TestStartReportsImmediateExit(t *testing.T) {
	dir := installFakeSingBox(t, "crash")
	m := NewAt(dir)
	// Generous: the copied exe may be scanned by an antivirus before it runs.
	// Costs nothing when the process does exit — Start returns at once.
	setStartGrace(t, 30*time.Second)
	logs := captureLog(t)

	err := m.Start()
	if err == nil {
		m.Stop()
		t.Fatal("Start reported success for a process that exited at once")
	}
	if !strings.Contains(err.Error(), "FATAL[0000] start service: fake failure for the test") {
		t.Fatalf("error does not carry sing-box's output (with colour codes stripped): %q", err)
	}
	if strings.Contains(err.Error(), "\x1b") {
		t.Fatalf("ANSI escapes leaked into the error shown to the user: %q", err)
	}
	// Deterministic: Start clears the state itself before returning
	if m.IsRunning() {
		t.Fatal("IsRunning true after a failed start")
	}
	// Start clears m.cmd before the Wait goroutine logs: still a crash, not
	// taken for a stop
	if line := exitLogLine(t, logs); !strings.Contains(line, "ERROR") {
		t.Fatalf("a crash within the start grace not logged as an error: %q", line)
	}
}

// A process that outlives the start check and dies later "started fine" —
// the reason must still be available for the monitor's report
func TestLastExitKeepsTheReasonOfALateDeath(t *testing.T) {
	dir := installFakeSingBox(t, "die-late")
	m := NewAt(dir)
	t.Cleanup(func() { m.Stop() })
	setStartGrace(t, 200*time.Millisecond)
	logs := captureLog(t)

	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if m.LastExit() != nil {
		t.Fatalf("LastExit set while the process is alive: %v", m.LastExit())
	}

	if !eventually(15*time.Second, func() bool { return m.LastExit() != nil }) {
		t.Fatal("LastExit never reported the death")
	}
	if got := m.LastExit().Error(); !strings.Contains(got, "fake late failure") {
		t.Fatalf("LastExit does not carry sing-box's output: %q", got)
	}
	if line := exitLogLine(t, logs); !strings.Contains(line, "ERROR") {
		t.Fatalf("a crash not logged as an error: %q", line)
	}
	if m.IsRunning() {
		t.Fatal("IsRunning true after the process died")
	}

	// A new start attempt supersedes it even when that attempt fails: its own
	// error is then the news (the monitor's give-up report must not fall back
	// to the older death)
	configPath := filepath.Join(dir, config.SingBoxConfig)
	if err := os.Rename(configPath, configPath+".off"); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(); err == nil {
		t.Fatal("Start without config.json must fail")
	}
	if m.LastExit() != nil {
		t.Fatalf("LastExit survived a failed start attempt: %v", m.LastExit())
	}
}

// A requested stop is not a death worth reporting — neither through LastExit
// nor as an ERROR in the log (a real log showed one for every "Выключить")
func TestLastExitIsNotSetByStop(t *testing.T) {
	dir := installFakeSingBox(t, "run")
	m := NewAt(dir)
	t.Cleanup(func() { m.Stop() })
	logs := captureLog(t)

	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := m.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	// The Wait goroutine reports the exit asynchronously
	if line := exitLogLine(t, logs); !strings.Contains(line, "ended by stop") || strings.Contains(line, "ERROR") {
		t.Fatalf("a requested stop logged as %q", line)
	}
	if m.LastExit() != nil {
		t.Fatalf("LastExit set by a requested stop: %v", m.LastExit())
	}
}

// Two installations side by side: a sing-box.exe of ANOTHER directory must be
// neither adopted nor killed. This is the Manager-level guard against sliding
// back to image-name matching (which, run elevated, would kill a developer's
// live VPN without any test noticing).
func TestManagerIgnoresForeignInstallation(t *testing.T) {
	dirA := installFakeSingBox(t, "run")
	dirB := installFakeSingBox(t, "run")
	mA, mB := NewAt(dirA), NewAt(dirB)
	t.Cleanup(func() { mA.Stop(); mB.Stop() })

	if err := mA.Start(); err != nil {
		t.Fatalf("Start A: %v", err)
	}
	pidsA, _ := findProcesses(mA.singBoxPath())
	if len(pidsA) != 1 {
		t.Fatalf("want one process of A, got %v", pidsA)
	}

	if mB.IsRunning() {
		t.Fatal("B adopted A's process by image name")
	}
	if err := mB.Start(); err != nil {
		t.Fatalf("Start B: %v", err)
	}
	pidsB, _ := findProcesses(mB.singBoxPath())
	if len(pidsB) != 1 || pidsB[0] == pidsA[0] {
		t.Fatalf("B must have launched its own instance, got %v (A: %v)", pidsB, pidsA)
	}

	if err := mB.Stop(); err != nil {
		t.Fatalf("Stop B: %v", err)
	}
	if after, _ := findProcesses(mA.singBoxPath()); len(after) != 1 || after[0] != pidsA[0] {
		t.Fatalf("stopping B killed A's process: before %v, after %v", pidsA, after)
	}
	if !mA.IsRunning() {
		t.Fatal("A no longer running after B was stopped")
	}
}

// A copy reached through a junction (a portable folder moved to another
// drive and linked back): the image path the system reports is the target,
// the manager's path goes through the link — it must still find, adopt and
// stop its own sing-box (finalPath)
func TestManagerThroughAJunction(t *testing.T) {
	dir := installFakeSingBox(t, "run")
	link := filepath.Join(t.TempDir(), "link")
	cmd := exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe"), "/c", "mklink", "/J", link, dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cannot create a junction: %v %s", err, out)
	}
	t.Cleanup(func() { os.Remove(link) }) // the junction, not what it points at
	if got, want := finalPath(filepath.Join(link, config.SingBoxExe)), finalPath(filepath.Join(dir, config.SingBoxExe)); !strings.EqualFold(got, want) || strings.Contains(got, `\link\`) {
		t.Fatalf("finalPath through the junction = %q, want %q", got, want)
	}

	m := NewAt(link)
	t.Cleanup(func() { m.Stop() })
	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if found, _ := findProcesses(m.singBoxPath()); len(found) != 1 {
		t.Fatalf("own process not found through the junction: %v", found)
	}
	adopter := NewAt(link)
	if !adopter.IsRunning() {
		t.Fatal("a fresh manager does not see the running instance through the junction")
	}
	if err := adopter.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if found, _ := findProcesses(filepath.Join(dir, config.SingBoxExe)); len(found) != 0 {
		t.Fatalf("still running after a Stop through the junction: %v", found)
	}
}

// A sing-box.exe of the installation started by a non-elevated program —
// the installed one is executable by every user, with any config — is not
// the VPN: not adopted (the app would never start the real one), and ended
// by a start (it would hold the ports and the TUN interface name)
func TestManagerIgnoresUnelevatedInstance(t *testing.T) {
	dir := installFakeSingBox(t, "run")
	m := NewAt(dir)
	t.Cleanup(func() { m.Stop() })

	spoof := startBelowOwnIntegrity(t, m.singBoxPath(), "run")
	exited := make(chan struct{})
	go func() { spoof.Wait(); close(exited) }()
	if !eventually(10*time.Second, func() bool {
		found, _ := findProcesses(m.singBoxPath())
		return len(found) == 1
	}) {
		t.Fatal("the lower-integrity instance did not start")
	}
	found, _ := findProcesses(m.singBoxPath())
	if found[0].elevated {
		t.Fatal("a process below the trusted integrity level counted as elevated")
	}
	if m.IsRunning() {
		t.Fatal("an instance started by a non-elevated program was taken for the VPN")
	}

	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	select {
	case <-exited:
	case <-time.After(10 * time.Second):
		t.Fatal("Start left the non-elevated instance running")
	}
	found, _ = findProcesses(m.singBoxPath())
	if len(found) != 1 || !found[0].elevated || found[0].pid == uint32(spoof.Process.Pid) {
		t.Fatalf("want exactly the manager's own instance, got %v", found)
	}
}

// startBelowOwnIntegrity starts exe as the fake sing-box one integrity level
// below this process (Medium -> Low on a developer machine, High -> Medium
// on an elevated CI runner): what a non-elevated program's launch looks like
// to the elevated app
func startBelowOwnIntegrity(t *testing.T, exe string, args ...string) *exec.Cmd {
	t.Helper()
	var own windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY, &own); err != nil {
		t.Fatal(err)
	}
	defer own.Close()
	level, err := integrityLevel(own)
	if err != nil || level < 2*securityMandatoryLowRID {
		t.Skipf("own integrity level %#x (%v): nothing lower to start at", level, err)
	}
	var lower windows.Token
	if err := windows.DuplicateTokenEx(own, windows.MAXIMUM_ALLOWED, nil, windows.SecurityImpersonation, windows.TokenPrimary, &lower); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lower.Close() })
	sid, err := windows.StringToSid(fmt.Sprintf("S-1-16-%d", level-securityMandatoryLowRID))
	if err != nil {
		t.Fatal(err)
	}
	label := windows.Tokenmandatorylabel{Label: windows.SIDAndAttributes{Sid: sid, Attributes: windows.SE_GROUP_INTEGRITY}}
	if err := windows.SetTokenInformation(lower, windows.TokenIntegrityLevel, (*byte)(unsafe.Pointer(&label)), uint32(unsafe.Sizeof(label))+windows.GetLengthSid(sid)); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(exe, args...)
	cmd.Env = append(os.Environ(), fakeModeEnv+"=run")
	cmd.SysProcAttr = &syscall.SysProcAttr{Token: syscall.Token(lower), HideWindow: true, CreationFlags: CREATE_NO_WINDOW}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start at a lower integrity level: %v", err)
	}
	t.Cleanup(func() { cmd.Process.Kill() })
	return cmd
}

// `sing-box check` / `sing-box version` run the very same exe. They must not
// be taken for the VPN, and a Stop must not kill a config check in flight.
func TestHelperRunIsNotTheVPN(t *testing.T) {
	dir := installFakeSingBox(t, "run")
	m := NewAt(dir)

	helper := NewHiddenCommand(m.singBoxPath(), "run") // the fake sleeps: a long "check"
	done := make(chan error, 1)
	go func() {
		_, err := HelperOutput(helper)
		done <- err
	}()
	// Registered = started (checked under the registry lock, which also
	// orders the read of helper.Process below after its write)
	if !eventually(10*time.Second, func() bool {
		helperMu.Lock()
		defer helperMu.Unlock()
		return len(helperPIDs) > 0
	}) {
		t.Fatal("helper did not start")
	}
	t.Cleanup(func() { helper.Process.Kill() })

	if m.IsRunning() {
		t.Fatal("a helper run was taken for the VPN")
	}
	if err := m.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	select {
	case err := <-done:
		t.Fatalf("Stop killed the helper run: %v", err)
	case <-time.After(500 * time.Millisecond):
	}

	helper.Process.Kill()
	<-done
	if pids, _ := findProcesses(m.singBoxPath()); len(pids) != 0 {
		t.Fatalf("finished helper still listed or registry leaked: %v", pids)
	}
}

// The console log is bounded while sing-box keeps running: it cannot be
// renamed then, so it is truncated in place
func TestTrimConsoleLogWhileRunning(t *testing.T) {
	dir := installFakeSingBox(t, "chatty")
	m := NewAt(dir)
	t.Cleanup(func() { m.Stop() })

	old := consoleLogMaxBytes
	consoleLogMaxBytes = 2000
	t.Cleanup(func() { consoleLogMaxBytes = old })

	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	path := filepath.Join(dir, config.SingBoxConsoleLog)
	if !eventually(15*time.Second, func() bool {
		info, err := os.Stat(path)
		return err == nil && info.Size() > consoleLogMaxBytes
	}) {
		t.Fatal("fake sing-box did not fill the log")
	}

	m.TrimConsoleLog()

	info, err := os.Stat(path)
	if err != nil || info.Size() > consoleLogMaxBytes {
		t.Fatalf("log not trimmed: %v bytes (%v)", info.Size(), err)
	}
	if saved, err := os.Stat(path + ".old"); err != nil || saved.Size() <= consoleLogMaxBytes {
		t.Fatalf("old content not kept in .old: %v", err)
	}

	// The child keeps appending at the new end of file: no hole of NUL bytes
	time.Sleep(300 * time.Millisecond)
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		t.Fatalf("child stopped writing after the trim: %d bytes (%v)", len(data), err)
	}
	if strings.ContainsRune(string(data), 0) {
		t.Fatal("trimmed log contains NUL bytes: the child did not write in append mode")
	}
}

// setStartGrace overrides the start grace for one test
func setStartGrace(t *testing.T, d time.Duration) {
	t.Helper()
	old := startGrace
	startGrace = d
	t.Cleanup(func() { startGrace = old })
}

// captureLog collects the log output for the rest of the test
func captureLog(t *testing.T) *lockedBuffer {
	t.Helper()
	b := &lockedBuffer{}
	log.SetOutput(b)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return b
}

// lockedBuffer is written by the Wait goroutines and read by the test
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

var startedPID = regexp.MustCompile(`started successfully \(PID: (\d+)\)`)

// exitLogLine waits for what the Wait goroutine logs about the exit of the
// process started last. By PID: the goroutine of an earlier test may log
// into the buffer as well.
func exitLogLine(t *testing.T, logs *lockedBuffer) string {
	t.Helper()
	started := startedPID.FindAllStringSubmatch(logs.String(), -1)
	if len(started) == 0 {
		t.Fatalf("no start in the log:\n%s", logs)
	}
	marker := fmt.Sprintf("sing-box (PID %s) ", started[len(started)-1][1])
	var line string
	if !eventually(15*time.Second, func() bool {
		for _, l := range strings.Split(logs.String(), "\n") {
			if strings.Contains(l, marker) {
				line = l
				return true
			}
		}
		return false
	}) {
		t.Fatalf("the exit of %q was never logged:\n%s", marker, logs)
	}
	return line
}

// eventually polls cond until it holds or the timeout passes
func eventually(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// The setup errors are marked, so the user is told how to fix them
func TestStartWithoutBinary(t *testing.T) {
	dir := t.TempDir()
	m := NewAt(dir)
	if err := m.Start(); !errors.Is(err, domain.ErrSingBoxMissing) || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("want ErrSingBoxMissing, got %v", err)
	}

	dir = installFakeSingBox(t, "run")
	if err := os.Remove(filepath.Join(dir, config.SingBoxConfig)); err != nil {
		t.Fatal(err)
	}
	if err := NewAt(dir).Start(); !errors.Is(err, domain.ErrConfigMissing) {
		t.Fatalf("want ErrConfigMissing, got %v", err)
	}
}

// WaitForExit is the --wait-pid handshake after a self-update: the new exe
// must wait for its predecessor, and must not wait for a PID that is gone
func TestWaitForExit(t *testing.T) {
	dir := installFakeSingBox(t, "run")
	cmd := NewHiddenCommand(filepath.Join(dir, config.SingBoxExe), "run")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	pid := uint32(cmd.Process.Pid)

	if err := WaitForExit(pid, 300*time.Millisecond); err == nil {
		t.Fatal("WaitForExit returned before the process ended")
	}

	done := make(chan error, 1)
	go func() { done <- WaitForExit(pid, 10*time.Second) }()
	time.Sleep(200 * time.Millisecond)
	cmd.Process.Kill()
	cmd.Wait()
	if err := <-done; err != nil {
		t.Fatalf("WaitForExit after the exit: %v", err)
	}

	// Already gone (or never existed): no wait at all
	if err := WaitForExit(pid, time.Second); err != nil {
		t.Fatalf("WaitForExit on a dead PID: %v", err)
	}
}

// The check runs on every monitor tick, so it must not fail outside a
// shutting-down session
func TestIsSessionEndingDuringNormalOperation(t *testing.T) {
	if IsSessionEnding() {
		t.Fatal("session reported as ending during a normal test run")
	}
}

func TestAllowTaskbarCreated(t *testing.T) {
	if err := AllowTaskbarCreated(); err != nil {
		t.Fatalf("AllowTaskbarCreated: %v", err)
	}
}

// sing-box gets a built environment: nothing of the user's (PATH above all)
func TestSingBoxEnvIsBuilt(t *testing.T) {
	t.Setenv("PATH", `C:\Users\someone\AppData\Local\Microsoft\WindowsApps`)
	t.Setenv("GODEBUG", "x509sha1=1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("ENABLE_DEPRECATED_SPECIAL_OUTBOUNDS", "1")
	t.Setenv("ENABLE_DEPRECATED_WIREGUARD_OUTBOUND", "rm -rf")
	bin, data := t.TempDir(), t.TempDir()
	env := SingBoxEnv(bin, data)
	joined := strings.Join(env, "\n")
	for _, bad := range []string{"WindowsApps", "GODEBUG", "HTTPS_PROXY"} {
		if strings.Contains(joined, bad) {
			t.Errorf("%s leaked into sing-box's environment", bad)
		}
	}
	if !strings.Contains(joined, "ENABLE_DEPRECATED_SPECIAL_OUTBOUNDS=true") {
		t.Error("a boolean ENABLE_DEPRECATED_ switch was not passed through (normalized)")
	}
	if strings.Contains(joined, "WIREGUARD_OUTBOUND") {
		t.Error("an ENABLE_DEPRECATED_ switch with a non-boolean value was passed through")
	}
	var path string
	for _, kv := range env {
		if strings.HasPrefix(kv, "PATH=") {
			path = kv[len("PATH="):]
		}
	}
	if !strings.HasPrefix(path, bin+";") {
		t.Errorf("PATH %q does not start with the Bin dir", path)
	}
}
