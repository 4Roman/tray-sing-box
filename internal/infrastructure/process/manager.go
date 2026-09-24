package process

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"tray-sing-box/internal/config"
	"tray-sing-box/internal/domain"
)

// startGrace is how long a freshly started process must survive; a variable
// so that tests of the failure path do not depend on how fast a process
// starts and dies on a loaded machine
var startGrace = config.StartGraceMs * time.Millisecond

// consoleLogMaxBytes bounds sing-box-console.log (a variable for tests)
var consoleLogMaxBytes int64 = config.LogMaxSizeMB << 20

// ansiEscapes matches the terminal colour codes sing-box prints even when its
// output is redirected
var ansiEscapes = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// Manager manages the sing-box VPN process
type Manager struct {
	cmd      *exec.Cmd
	proc     *startedProcess // cmd's bookkeeping (valid with cmd)
	mu       sync.Mutex
	binDir   string // sing-box.exe
	dataDir  string // config.json, console log, working directory of sing-box
	running  bool
	lastExit error // why the last owned process died on its own, see LastExit
}

// New creates the process manager for an installation: sing-box.exe in
// binDir, config.json and the logs in dataDir (the same directory in the
// portable layout). Starts the console-log trimming loop.
func New(binDir, dataDir string) *Manager {
	m := &Manager{binDir: binDir, dataDir: dataDir}
	go m.trimConsoleLogLoop()
	return m
}

// NewAt creates a process manager for a single-directory installation
// without background goroutines (tests)
func NewAt(dir string) *Manager {
	return &Manager{binDir: dir, dataDir: dir}
}

func (m *Manager) singBoxPath() string {
	return filepath.Join(m.binDir, config.SingBoxExe)
}

// startedProcess is a sing-box instance launched by this manager
type startedProcess struct {
	cmd       *exec.Cmd
	done      chan struct{} // closed when the process has exited
	exitErr   error         // valid once done is closed
	logPath   string        // console capture file ("" when unavailable)
	logOffset int64         // where this run's output starts in logPath
	stopping  bool          // Stop is ending it: its exit is expected (Manager.mu)
}

// Start starts the sing-box process. A process that dies within
// StartGraceMs — bad config, busy port, TUN adapter not released yet — is a
// failed start, reported with the tail of what sing-box printed; without the
// check every such start looked like a success ("VPN restarted").
func (m *Manager) Start() error {
	proc, err := m.startLocked()
	if err != nil || proc == nil {
		return err // proc == nil: attached to an already running instance
	}

	// Waited for without the lock: status checks must not stall, and the
	// exit bookkeeping below needs the lock itself. Until the grace is over
	// the process does not count as running (m.running stays false), so a
	// start that fails does not flash "running" in the UI first.
	select {
	case <-proc.done:
		// Cleared here as well as by the Wait goroutine (which closes done
		// BEFORE it gets the lock): IsRunning must not report true for a
		// process this call is about to declare dead
		m.mu.Lock()
		if m.cmd == proc.cmd {
			m.cmd = nil
			m.running = false
		}
		m.mu.Unlock()
		return fmt.Errorf("sing-box exited right after start (%s)%s", exitReason(proc), outputTail(proc))
	case <-time.After(startGrace):
		m.mu.Lock()
		if m.cmd == proc.cmd {
			m.running = true
		}
		m.mu.Unlock()
		return nil
	}
}

func exitReason(proc *startedProcess) string {
	if proc.exitErr != nil {
		return proc.exitErr.Error()
	}
	return "exit code 0"
}

// startLocked launches the process; nil, nil means an instance is already
// running and was adopted instead
func (m *Manager) startLocked() (*startedProcess, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	log.Println("=== startVPN called ===")

	// Whatever happens next supersedes the previous process's death: if this
	// start fails, ITS error is the news, not the older exit
	m.lastExit = nil

	singBoxPath := m.singBoxPath()
	configPath := filepath.Join(m.dataDir, config.SingBoxConfig)

	log.Printf("sing-box path: %s", singBoxPath)
	log.Printf("config path: %s", configPath)

	// Check if files exist
	if _, err := os.Stat(singBoxPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("%w at: %s", domain.ErrSingBoxMissing, singBoxPath)
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("%w at: %s", domain.ErrConfigMissing, configPath)
	}

	// Check if sing-box is already running
	if m.isRunning() {
		log.Println("sing-box.exe is already running, not starting new instance")
		m.running = true
		return nil, nil
	}
	m.endUnelevated()

	log.Println("sing-box.exe is not running, starting new instance")

	// Working directory = data dir: relative paths in the config (cache.db,
	// rule sets, log.output) resolve there
	cmd := exec.Command(singBoxPath, "run", "-c", configPath)
	cmd.Dir = m.dataDir
	cmd.Env = SingBoxEnv(m.binDir, m.dataDir)

	// sing-box writes straight into its own file, not through pipes read by
	// this app: the output survives the tray app (sing-box is meant to outlive
	// it, and a pipe dies with its reader), nothing is lost when the process
	// exits faster than a reader goroutine gets scheduled, and the tray log
	// stays small. Without the file the output goes nowhere — not an error.
	proc := &startedProcess{cmd: cmd, done: make(chan struct{})}
	if console := m.openConsoleLog(); console != nil {
		defer console.Close() // the child has its own handle once started
		cmd.Stdout = console
		cmd.Stderr = console
		proc.logPath = console.Name()
		if info, err := console.Stat(); err == nil {
			proc.logOffset = info.Size()
		}
	}

	// Hide the console window on Windows. Normal priority explicitly: when
	// Task Scheduler launched this app below normal, sing-box would inherit it
	hideConsoleWindow(cmd)
	useNormalPriority(cmd)

	log.Println("Starting sing-box process...")
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start sing-box: %w", err)
	}

	log.Printf("sing-box process started successfully (PID: %d)", cmd.Process.Pid)

	m.cmd = cmd
	m.proc = proc
	m.running = false // set by Start once the grace is over

	// Monitor the process. m.cmd may be replaced or nilled (Stop, restart)
	// while this goroutine is still waiting, and state must only be cleared
	// if it still belongs to this process.
	go func() {
		proc.exitErr = cmd.Wait()
		close(proc.done) // before the lock: Start's grace wait must see it at once

		// Read before taking the lock (file I/O)
		exit := fmt.Errorf("sing-box exited (%s)%s", exitReason(proc), outputTail(proc))

		m.mu.Lock()
		defer m.mu.Unlock()

		pid := cmd.Process.Pid
		// Ended on request: not an error (the exit code is TerminateProcess's),
		// and no reason to keep. m.cmd is normally cleared by Stop already —
		// still set only when the stop timed out and the process went later.
		if proc.stopping {
			log.Printf("sing-box (PID %d) ended by stop (%s)", pid, exitReason(proc))
			if m.cmd == cmd {
				m.cmd = nil
				m.running = false
			}
			return
		}
		if proc.exitErr != nil {
			log.Printf("ERROR: sing-box (PID %d) exited with error: %v (was running: %v)", pid, proc.exitErr, m.running)
		} else {
			log.Printf("sing-box (PID %d) exited normally (was running: %v)", pid, m.running)
		}
		// Still ours = not superseded (a death within the start grace is
		// Start's to report, and Start has cleared m.cmd already): it died on
		// its own, and the reason is worth keeping
		if m.cmd == cmd {
			m.running = false
			m.cmd = nil
			m.lastExit = exit
		}
	}()

	return proc, nil
}

// openConsoleLog opens the file that captures sing-box's stdout/stderr,
// rotating an oversized one first. Only called while no sing-box of ours is
// running, so nothing holds the file. Best effort: nil when it cannot be
// opened.
func (m *Manager) openConsoleLog() *os.File {
	path := filepath.Join(m.dataDir, config.SingBoxConsoleLog)
	if info, err := os.Stat(path); err == nil && info.Size() > consoleLogMaxBytes {
		if err := os.Rename(path, path+".old"); err != nil {
			log.Printf("Warning: failed to rotate %s: %v", path, err)
		}
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Warning: sing-box output will not be captured: %v", err)
		return nil
	}
	fmt.Fprintf(f, "=== sing-box started by tray-sing-box at %s ===\n", time.Now().Format("2006-01-02 15:04:05"))
	return f
}

// outputTail returns what this run of sing-box printed (the end of it),
// formatted for appending to an error message
func outputTail(proc *startedProcess) string {
	if proc.logPath == "" {
		return ""
	}
	f, err := os.Open(proc.logPath)
	if err != nil {
		return ""
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return ""
	}
	offset := proc.logOffset
	cut := false
	if size := info.Size(); size-offset > config.StartErrorTailBytes {
		offset = size - config.StartErrorTailBytes
		cut = true
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return ""
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return ""
	}
	if cut {
		// The cut lands mid-line (possibly mid-rune or mid-escape)
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			data = data[i+1:]
		}
	}
	// This text ends up in message boxes and web UI errors
	tail := strings.TrimSpace(ansiEscapes.ReplaceAllString(string(data), ""))
	if tail == "" {
		return ""
	}
	return ":\n" + tail
}

// LastExit reports why the last sing-box started by this manager died on its
// own (nil when it was stopped on request, or a new one has been started
// since). Start only catches deaths within the grace period; this is how the
// reason of a later one — typically TUN or route setup failing a few seconds
// in — still reaches the user.
func (m *Manager) LastExit() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastExit
}

// TrimConsoleLog bounds sing-box-console.log while sing-box keeps running.
// The file cannot be renamed then (the child holds it, and Go opens files
// without FILE_SHARE_DELETE), but it can be truncated in place: the child's
// handle is append-only (O_APPEND -> FILE_APPEND_DATA, duplicated as is), so
// every write lands at the current end of file and no hole appears. The old
// content is copied to ".old" first; lines written between the copy and the
// truncate are lost.
func (m *Manager) TrimConsoleLog() {
	path := filepath.Join(m.dataDir, config.SingBoxConsoleLog)
	info, err := os.Stat(path)
	if err != nil || info.Size() <= consoleLogMaxBytes {
		return
	}

	if err := copyFile(path, path+".old"); err != nil {
		log.Printf("Warning: failed to save %s before trimming: %v", path, err)
	}
	if err := os.Truncate(path, 0); err != nil {
		log.Printf("Warning: failed to trim %s: %v", path, err)
		return
	}
	log.Printf("%s exceeded %d MB and was moved to .old", path, config.LogMaxSizeMB)
}

func (m *Manager) trimConsoleLogLoop() {
	for range time.Tick(config.ConsoleLogTrimMinutes * time.Minute) {
		m.TrimConsoleLog()
	}
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// Stop stops the sing-box process. Idempotent: with nothing running it
// succeeds — the caller wants it down (and the user's "stop" must still be
// recorded).
func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	log.Println("=== stopVPN called ===")

	// Only the instances of OUR sing-box.exe (full path), by PID — never
	// "taskkill /IM", which kills every sing-box.exe on the machine
	found, err := findProcesses(m.singBoxPath())
	if err != nil {
		return fmt.Errorf("failed to stop sing-box: %w", err)
	}
	if len(found) == 0 {
		log.Println("sing-box.exe is not running, nothing to stop")
	}
	// Its Wait goroutine logs the exit that follows as requested, not as a
	// crash (the log would show an ERROR for every "Выключить")
	if m.cmd != nil {
		m.proc.stopping = true
	}

	var (
		firstErr   error
		unelevated []foundProcess
		ownSeen    bool
	)
	for _, p := range found {
		if m.cmd != nil && m.cmd.Process != nil && p.pid == uint32(m.cmd.Process.Pid) {
			ownSeen = true
		}
		if !p.elevated {
			unelevated = append(unelevated, p)
			continue
		}
		log.Printf("Terminating sing-box (PID: %d)...", p.pid)
		if err := terminateProcess(p, config.StopWaitTimeout*time.Second); err != nil {
			log.Printf("Failed to stop sing-box: %v", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	// The process this manager started is ended through its own handle even
	// when the path match missed it — a Stop that reports success must not
	// leave the VPN running
	if m.cmd != nil && m.cmd.Process != nil && !ownSeen {
		log.Printf("Terminating sing-box started by this app (PID: %d), not found by path", m.cmd.Process.Pid)
		m.cmd.Process.Kill()
		select {
		case <-m.proc.done:
		case <-time.After(config.StopWaitTimeout * time.Second):
			if firstErr == nil {
				firstErr = fmt.Errorf("process %d is still running after it was killed", m.cmd.Process.Pid)
			}
		}
	}
	// A non-elevated instance is not the VPN (see endUnelevated): ended too,
	// but one that cannot be ended — another user's, or frozen — must not
	// make the user's "stop" fail or wait
	if len(unelevated) > 0 {
		log.Printf("Terminating %d sing-box instance(s) not started by this app", len(unelevated))
		if _, err := terminateAll(unelevated, unownedStopWait); err != nil {
			log.Printf("Warning: %v", err)
		}
	}
	if firstErr != nil {
		return fmt.Errorf("failed to stop sing-box: %w", firstErr)
	}

	m.cmd = nil
	m.running = false
	m.lastExit = nil
	log.Println("stopVPN completed")

	return nil
}

// IsRunning checks if the process is currently running
func (m *Manager) IsRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	// When we own a live process handle, trust the Wait() monitor.
	// Otherwise (attached to an external instance, or not started by us)
	// consult the system so the status reflects reality in both directions:
	// an externally killed sing-box and an externally started one.
	if m.cmd == nil || m.cmd.Process == nil {
		actuallyRunning := m.isRunning()
		if m.running != actuallyRunning {
			log.Printf("MONITOR: VPN state updated from system: %v -> %v", m.running, actuallyRunning)
			m.running = actuallyRunning
		}
	}

	return m.running
}

// isRunning checks if our sing-box.exe is running in the system (must be
// called with lock held). Called on every monitor tick while the process is
// not owned, so it must stay cheap and must not log per call. When the check
// itself fails the last known state is kept: reporting "stopped" would make
// the monitor take a live VPN for a crashed one. Only an elevated instance
// counts: every sing-box this app starts is elevated, one started by a
// non-elevated program is not the VPN (see endUnelevated).
func (m *Manager) isRunning() bool {
	found, err := findProcesses(m.singBoxPath())
	if err != nil {
		log.Printf("ERROR: Failed to check for sing-box process: %v", err)
		return m.running
	}
	for _, p := range found {
		if p.elevated {
			return true
		}
	}
	return false
}

// unownedStopWait bounds the wait for sing-box instances this app did not
// start (see terminateAll): all of them together, not each
const unownedStopWait = 2 * time.Second

// endUnelevated terminates instances of our sing-box.exe that a
// non-elevated program started (must be called with lock held, before a
// start). The installed sing-box.exe is executable by every user: such an
// instance runs a config of its own, and it is in the way of the real VPN —
// same ports, same TUN interface name. Best effort, with one short wait for
// all of them: one that cannot be ended (another user's, or frozen by a
// debugger) makes the start fail with sing-box's own error, which the user
// then sees.
func (m *Manager) endUnelevated() {
	found, err := findProcesses(m.singBoxPath())
	if err != nil {
		return
	}
	var procs []foundProcess
	var pids []uint32
	for _, p := range found {
		if !p.elevated {
			procs = append(procs, p)
			pids = append(pids, p.pid)
		}
	}
	if len(procs) == 0 {
		return
	}
	log.Printf("Warning: %s runs without elevation (PIDs %v) — started by another program, not by this app; terminating it", m.singBoxPath(), pids)
	if _, err := terminateAll(procs, unownedStopWait); err != nil {
		log.Printf("Warning: %v", err)
	}
}

// WaitForExplorer waits for the Windows shell (system tray) to be ready.
// It polls for the Shell_TrayWnd window, which explorer.exe creates once the
// taskbar exists — the actual precondition for registering a tray icon.
func WaitForExplorer() {
	log.Println("Waiting for Windows shell (system tray) to be ready...")

	for i := 0; i < config.ExplorerWaitTimeout; i++ {
		if isTrayReady() {
			log.Printf("System tray is ready (attempt %d/%d)", i+1, config.ExplorerWaitTimeout)
			return
		}
		if i > 0 && i%60 == 0 {
			log.Printf("Still waiting for the system tray (%d s)...", i)
		}
		time.Sleep(time.Second)
	}

	log.Println("Timeout waiting for system tray, proceeding anyway...")
}
