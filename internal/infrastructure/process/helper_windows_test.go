//go:build windows

package process

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"tray-sing-box/internal/config"
)

// What the fake in mode "serve" writes into its working directory
const (
	serveStartedFile = "serve-started" // first thing it does: its PID
	serveStdinFile   = "serve-stdin"   // everything it read from stdin
	servePortFile    = "serve-port"    // the loopback port it listens on
)

// fakeServe plays the latency-test instance: `run -c stdin` with a Clash API
// on the loopback. The marker comes first — a process that runs at all
// writes it within moments, which is how the tests see that a helper did not
// run before it was resumed in its job.
func fakeServe() {
	os.WriteFile(serveStartedFile, []byte(strconv.Itoa(os.Getpid())), 0644)
	cfg, _ := io.ReadAll(os.Stdin)
	os.WriteFile(serveStdinFile, cfg, 0644)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		os.Exit(1)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go io.Copy(io.Discard, c)
		}
	}()
	os.WriteFile(servePortFile, []byte(strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)), 0644)
	time.Sleep(2 * time.Minute) // a leak ends by itself
}

// helperChildEnv turns the test binary into an app that starts a helper in
// another process (see helperChild): what happens when the app goes away, and
// what happens under a job of its own, can only be seen from outside
const (
	helperChildEnv    = "TRAY_TEST_HELPER_CHILD"
	helperChildDirEnv = "TRAY_TEST_HELPER_DIR"
)

// helperChild starts the fake of dir as a helper and then
//   - "abandon": prints its PID, waits for stdin to close and exits without
//     stopping it — as a crashed or killed tray app ends;
//   - "nested": runs in a job of its own first (Task Scheduler starts the app
//     in one), then reports whether the helper is in both jobs.
func helperChild(mode, dir string) {
	var outer windows.Handle
	if mode == "nested" {
		job, err := windows.CreateJobObject(nil, nil)
		if err == nil {
			err = windows.AssignProcessToJobObject(job, windows.CurrentProcess())
		}
		if err != nil {
			fmt.Println("outer job:", err)
			os.Exit(9)
		}
		outer = job
	}
	h, err := StartHelper(helperCommand(dir, nil))
	if err != nil {
		fmt.Println("StartHelper:", err)
		os.Exit(8)
	}
	switch mode {
	case "abandon":
		fmt.Println(h.PID())
		io.ReadAll(os.Stdin)
		os.Exit(0)
	case "nested":
		p, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, h.PID())
		if err != nil {
			fmt.Println("open helper:", err)
			os.Exit(10)
		}
		inOwn, errOwn := isProcessInJob(p, h.job)
		inOuter, errOuter := isProcessInJob(p, outer)
		fmt.Printf("own=%v outer=%v (%v, %v)\n", inOwn, inOuter, errOwn, errOuter)
		if err := h.Stop(10 * time.Second); err != nil {
			fmt.Println("Stop:", err)
			os.Exit(11)
		}
		os.Exit(0)
	}
	os.Exit(12)
}

var procIsProcessInJob = windows.NewLazySystemDLL("kernel32.dll").NewProc("IsProcessInJob")

// isProcessInJob: job 0 asks for any job
func isProcessInJob(process, job windows.Handle) (bool, error) {
	var result int32
	if r, _, err := procIsProcessInJob.Call(uintptr(process), uintptr(job), uintptr(unsafe.Pointer(&result))); r == 0 {
		return false, err
	}
	return result != 0, nil
}

// helperCommand: the fake of dir as the latency-test instance, the way the
// prober builds it (config on stdin, built environment, data dir as cwd)
func helperCommand(dir string, stdin []byte) *exec.Cmd {
	cmd := NewHiddenCommand(filepath.Join(dir, config.SingBoxExe), "run", "-c", "stdin")
	cmd.Dir = dir
	cmd.Env = append(SingBoxEnv(dir, dir), fakeModeEnv+"=serve")
	cmd.Stdin = bytes.NewReader(stdin)
	return cmd
}

func startHelper(t *testing.T, dir string, stdin []byte) *Helper {
	t.Helper()
	h, err := StartHelper(helperCommand(dir, stdin))
	if err != nil {
		t.Fatalf("StartHelper: %v", err)
	}
	t.Cleanup(func() { h.Stop(10 * time.Second) })
	return h
}

// installHelperFake is installFakeSingBox plus a guard: whatever still runs
// the fake when the test ends is ended by full path — a test must not leave a
// helper behind even when it fails half-way (the job would end it only with
// the test binary)
func installHelperFake(t *testing.T) (dir, exe string) {
	t.Helper()
	dir = installFakeSingBox(t, "run")
	exe = filepath.Join(dir, config.SingBoxExe)
	t.Cleanup(func() {
		if left := processesAt(t, exe); len(left) > 0 {
			t.Logf("ending what the test left running: %v", left)
			terminateAll(left, 5*time.Second)
		}
	})
	return dir, exe
}

// waitServing waits until the fake listens and returns its port
func waitServing(t *testing.T, dir string) int {
	t.Helper()
	var port int
	if !eventually(20*time.Second, func() bool {
		b, err := os.ReadFile(filepath.Join(dir, servePortFile))
		if err != nil {
			return false
		}
		port, err = strconv.Atoi(string(b))
		return err == nil && port > 0
	}) {
		t.Fatal("the helper never started serving")
	}
	return port
}

func registered(pid uint32) bool {
	helperMu.Lock()
	defer helperMu.Unlock()
	_, ok := helperPIDs[pid]
	return ok
}

// processesAt lists the processes running exe by full path — helpers
// included, which findProcesses leaves out
func processesAt(t *testing.T, exe string) []foundProcess {
	t.Helper()
	target := finalPath(exe)
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		t.Errorf("process snapshot: %v", err)
		return nil
	}
	defer windows.CloseHandle(snapshot)
	var found []foundProcess
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	for err = windows.Process32First(snapshot, &entry); err == nil; err = windows.Process32Next(snapshot, &entry) {
		if !strings.EqualFold(windows.UTF16ToString(entry.ExeFile[:]), filepath.Base(exe)) {
			continue
		}
		if path, elevated, err := processDetails(entry.ProcessID); err == nil && samePath(path, target) {
			found = append(found, foundProcess{pid: entry.ProcessID, path: path, elevated: elevated})
		}
	}
	return found
}

func setHelperStage(t *testing.T, f func(stage string, pid uint32, job windows.Handle)) {
	old := helperStage
	helperStage = f
	t.Cleanup(func() { helperStage = old })
}

// The latency-test instance runs the VPN's own exe, so by image path it is
// the VPN — and must not be taken for it: not adopted (the VPN would never be
// started), not killed by a Stop (the test would die with the VPN toggle),
// and a Start meanwhile starts the real VPN next to it
func TestHelperIsNotTheVPN(t *testing.T) {
	dir, exe := installHelperFake(t)
	m := NewAt(dir)
	t.Cleanup(func() { m.Stop() })
	h := startHelper(t, dir, nil)
	waitServing(t, dir)

	if m.IsRunning() || NewAt(dir).IsRunning() {
		t.Fatal("the helper was taken for the VPN")
	}
	if err := m.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	select {
	case <-h.Done():
		t.Fatalf("Stop killed the helper: %v", h.Err())
	case <-time.After(500 * time.Millisecond):
	}

	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	vpn, _ := findProcesses(exe)
	if len(vpn) != 1 || vpn[0].pid == h.PID() {
		t.Fatalf("Start adopted the helper instead of starting the VPN: %v (helper %d)", vpn, h.PID())
	}
	if !m.IsRunning() {
		t.Fatal("the VPN started next to the helper is not reported as running")
	}
	if all := processesAt(t, exe); len(all) != 2 {
		t.Fatalf("want the VPN and the helper side by side, got %v", all)
	}

	if err := m.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if left := processesAt(t, exe); len(left) != 1 || left[0].pid != h.PID() {
		t.Fatalf("after the VPN's Stop want only the helper %d, got %v", h.PID(), left)
	}

	if err := h.Stop(10 * time.Second); err != nil {
		t.Fatalf("helper Stop: %v", err)
	}
	if left := processesAt(t, exe); len(left) != 0 {
		t.Fatalf("still running after the helper's Stop: %v", left)
	}
	if err := h.Stop(time.Second); err != nil {
		t.Fatalf("a second Stop: %v", err)
	}
}

// Created suspended, resumed only in its job: there is no moment in which it
// runs outside it (and could outlive the app). The config written to stdin
// while it is suspended — far more than a pipe holds — arrives complete.
func TestHelperRunsOnlyInItsJob(t *testing.T) {
	dir, _ := installHelperFake(t)
	marker := filepath.Join(dir, serveStartedFile)
	var stages, problems []string
	setHelperStage(t, func(stage string, pid uint32, job windows.Handle) {
		stages = append(stages, stage)
		// Long enough for a process that runs to have written its marker:
		// it is the first thing it does
		if eventually(1500*time.Millisecond, func() bool {
			_, err := os.Stat(marker)
			return err == nil
		}) {
			problems = append(problems, stage+": the process ran before it was resumed in its job")
		}
		p, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: open: %v", stage, err))
			return
		}
		defer windows.CloseHandle(p)
		in, err := isProcessInJob(p, job)
		if err != nil || in != (stage == "assigned") {
			problems = append(problems, fmt.Sprintf("%s: in the job = %v (%v)", stage, in, err))
		}
	})

	cfg := bytes.Repeat([]byte(`{"secret":"0123456789abcdef"}`), 16<<10) // ~460 KB
	h := startHelper(t, dir, cfg)
	if !slices.Equal(stages, []string{"created", "assigned"}) {
		t.Fatalf("isolation stages %v", stages)
	}
	if len(problems) > 0 {
		t.Fatal(strings.Join(problems, "\n"))
	}

	// Resumed: it runs now
	waitServing(t, dir)
	if pid, err := os.ReadFile(marker); err != nil || string(pid) != strconv.Itoa(int(h.PID())) {
		t.Fatalf("marker %q (%v), want the helper's PID %d", pid, err, h.PID())
	}
	if got, err := os.ReadFile(filepath.Join(dir, serveStdinFile)); err != nil || !bytes.Equal(got, cfg) {
		t.Fatalf("stdin arrived as %d bytes (%v), want %d", len(got), err, len(cfg))
	}
}

// A helper that cannot be isolated is ended before it ran — still suspended:
// no listener, no connection, nothing read — and is not left registered
func TestHelperIsolationFailureEndsIt(t *testing.T) {
	injected := errors.New("injected failure")
	for _, step := range []string{"assign", "resume"} {
		t.Run(step, func(t *testing.T) {
			dir, exe := installHelperFake(t)
			var pid uint32
			setHelperStage(t, func(_ string, p uint32, _ windows.Handle) { pid = p })
			switch step {
			case "assign":
				old := assignToJob
				assignToJob = func(windows.Handle, windows.Handle) error { return injected }
				t.Cleanup(func() { assignToJob = old })
			case "resume":
				old := resumeHelper
				resumeHelper = func(uint32) error { return injected }
				t.Cleanup(func() { resumeHelper = old })
			}

			h, err := StartHelper(helperCommand(dir, nil))
			if err == nil {
				h.Stop(10 * time.Second)
				t.Fatal("StartHelper succeeded although the isolation failed")
			}
			if !errors.Is(err, ErrHelperNotIsolated) || !strings.Contains(err.Error(), injected.Error()) {
				t.Fatalf("error %v, want ErrHelperNotIsolated with the cause", err)
			}
			if pid == 0 {
				t.Fatal("the process was not even created: the failure path is not exercised")
			}
			if left := processesAt(t, exe); len(left) != 0 {
				t.Fatalf("left running: %v", left)
			}
			if registered(pid) {
				t.Fatal("left registered as a helper")
			}
			if _, err := os.Stat(filepath.Join(dir, serveStartedFile)); err == nil {
				t.Fatal("the process ran before it was ended")
			}
		})
	}
}

// The registration goes only after the exit: before it, a running helper
// would be seen as the VPN. And once Done is closed it is gone.
func TestHelperRegisteredUntilItExits(t *testing.T) {
	dir, _ := installHelperFake(t)
	h := startHelper(t, dir, nil)
	waitServing(t, dir)
	if !registered(h.PID()) {
		t.Fatal("a running helper is not registered")
	}

	p, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_TERMINATE, false, h.PID())
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(p)
	var early atomic.Bool
	stop, watched := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(watched)
		for {
			if !registered(h.PID()) {
				// Read in this order: unregistered first, then not yet exited
				// would be a registration removed too early
				if event, _ := windows.WaitForSingleObject(p, 0); event != windows.WAIT_OBJECT_0 {
					early.Store(true)
				}
				return
			}
			select {
			case <-stop:
				return
			default:
				runtime.Gosched()
			}
		}
	}()

	// Killed from outside, not by Stop: the helper's own wait sees the death.
	// With the registry held, the unregistration cannot happen — and Done,
	// which comes after it, must not either.
	helperMu.Lock()
	if err := windows.TerminateProcess(p, 1); err != nil {
		helperMu.Unlock()
		t.Fatal(err)
	}
	windows.WaitForSingleObject(p, 10000)
	select {
	case <-h.Done():
		helperMu.Unlock()
		t.Fatal("Done closed before the registration was removed")
	case <-time.After(500 * time.Millisecond):
	}
	helperMu.Unlock()
	select {
	case <-h.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("Done not closed after the helper died")
	}
	if registered(h.PID()) {
		t.Fatal("Done closed while the helper is still registered")
	}
	close(stop)
	<-watched
	if early.Load() {
		t.Fatal("the registration was removed while the helper was still running")
	}
	if h.Err() == nil {
		t.Fatal("Err is nil for a killed helper")
	}
}

// Closing the job — what Windows does with every handle of a process that
// ends — kills the helper
func TestHelperDiesWithItsJob(t *testing.T) {
	dir, _ := installHelperFake(t)
	h := startHelper(t, dir, nil)
	waitServing(t, dir)

	// As the end of the app does it: no TerminateJobObject, just the handle
	h.killOnce.Do(func() {})
	h.closeOnce.Do(func() { windows.CloseHandle(h.job) })
	select {
	case <-h.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("the helper outlived its job")
	}
}

// The real thing: the app that started the helper ends without stopping it
// (crash, kill, a self-update relaunch) — the helper must go with it, or the
// next instance of the app would adopt it as the VPN
func TestHelperDiesWithTheApp(t *testing.T) {
	dir, exe := installHelperFake(t)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(self)
	child.Env = append(os.Environ(), helperChildEnv+"=abandon", helperChildDirEnv+"="+dir)
	stdin, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { child.Process.Kill() })

	line, err := bufio.NewReader(stdout).ReadString('\n')
	pid, convErr := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || convErr != nil {
		t.Fatalf("the app did not report its helper: %q (%v)", line, err)
	}
	p, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		t.Fatalf("open the helper: %v", err)
	}
	defer windows.CloseHandle(p)
	if path, _, err := processDetails(uint32(pid)); err != nil || !samePath(path, finalPath(exe)) {
		t.Fatalf("PID %d runs %q (%v), not the fake", pid, path, err)
	}

	stdin.Close() // the app exits now, without Stop
	if err := child.Wait(); err != nil {
		t.Fatalf("app exit: %v", err)
	}
	if event, err := windows.WaitForSingleObject(p, 10000); err != nil || event != windows.WAIT_OBJECT_0 {
		t.Fatalf("the helper outlived the app that started it (%#x, %v)", event, err)
	}
}

// The app may itself run in a job (whoever started it may use one — Task
// Scheduler, a terminal, a deployment tool), and every child of the app
// starts in it: the helper's job is then nested in that one (Windows 8+). The
// isolation must work there too (U4 of the latency-test design).
func TestHelperUnderAJobOfTheApp(t *testing.T) {
	if in, err := isProcessInJob(windows.CurrentProcess(), 0); err == nil {
		t.Logf("the test process itself runs in a job: %v", in)
	}
	dir, _ := installHelperFake(t)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(self)
	child.Env = append(os.Environ(), helperChildEnv+"=nested", helperChildDirEnv+"="+dir)
	out, err := child.Output()
	if err != nil {
		t.Fatalf("app in a job: %v\n%s", err, out)
	}
	if !strings.HasPrefix(string(out), "own=true outer=true") {
		t.Fatalf("the helper of an app in a job: %s", out)
	}
}

// What the prober's dial check sees right after its dial (no waiting: it
// must not send anything before the check): the other end of a connection to
// the helper's port belongs to the helper, and this end to this process
func TestHelperOwnsItsListener(t *testing.T) {
	dir, _ := installHelperFake(t)
	h := startHelper(t, dir, nil)
	port := waitServing(t, dir)

	c, err := net.Dial("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	api := c.RemoteAddr().(*net.TCPAddr).AddrPort()
	us := c.LocalAddr().(*net.TCPAddr).AddrPort()
	if owner, err := ConnOwnerPID(api, us); err != nil || owner != h.PID() {
		t.Fatalf("the helper's end of the connection is owned by %d (%v), want the helper %d", owner, err, h.PID())
	}
	if owner, err := ConnOwnerPID(us, api); err != nil || owner != uint32(os.Getpid()) {
		t.Fatalf("this end is owned by %d (%v), want this process %d", owner, err, os.Getpid())
	}
}
