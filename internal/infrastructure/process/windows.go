//go:build windows
// +build windows

package process

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32                        = windows.NewLazySystemDLL("user32.dll")
	procFindWindowW               = user32.NewProc("FindWindowW")
	procGetSystemMetrics          = user32.NewProc("GetSystemMetrics")
	procRegisterWindowMessageW    = user32.NewProc("RegisterWindowMessageW")
	procChangeWindowMessageFilter = user32.NewProc("ChangeWindowMessageFilter")
)

// isTrayReady reports whether the taskbar notification area exists.
// Shell_TrayWnd is created by explorer.exe once the shell is initialized,
// which is the actual precondition for registering a tray icon.
func isTrayReady() bool {
	className, err := windows.UTF16PtrFromString("Shell_TrayWnd")
	if err != nil {
		return false
	}
	hwnd, _, _ := procFindWindowW.Call(uintptr(unsafe.Pointer(className)), 0)
	return hwnd != 0
}

// AllowTaskbarCreated lets explorer.exe deliver the "TaskbarCreated" broadcast
// to this elevated process. UIPI drops messages from the medium-integrity
// shell to a high-integrity window unless they are explicitly allowed, and
// systray re-adds the tray icon only when it receives that message — without
// this call the icon is gone for good after any explorer.exe restart.
// Process-wide, so it works before systray creates its window.
func AllowTaskbarCreated() error {
	name, err := windows.UTF16PtrFromString("TaskbarCreated")
	if err != nil {
		return err
	}
	msg, _, callErr := procRegisterWindowMessageW.Call(uintptr(unsafe.Pointer(name)))
	if msg == 0 {
		return fmt.Errorf("RegisterWindowMessage: %w", callErr)
	}
	const msgfltAdd = 1
	if ok, _, callErr := procChangeWindowMessageFilter.Call(msg, msgfltAdd); ok == 0 {
		return fmt.Errorf("ChangeWindowMessageFilter: %w", callErr)
	}
	return nil
}

// AcquireSingleInstance reports whether this is the only running instance of
// the app. Two instances mean two tray icons and two monitors that both
// auto-restart sing-box and both edit config.json. The mutex is never
// released explicitly: Windows frees it when the process ends, however it
// ends. It lives in the app's private namespace (see objectName), where only
// an elevated administrator can create anything, so an existing mutex is
// always a genuine instance's. Fails open — a problem with the mutex itself
// must never keep the app from starting at logon.
func AcquireSingleInstance() bool {
	name, err := objectName(instanceMutexName, true)
	if err != nil {
		log.Printf("Warning: single-instance check unavailable, continuing: %v", err)
		return true
	}
	h, err := windows.CreateMutex(objectAttributes(), false, name)
	switch {
	case err == nil:
		return true // the handle stays open for the life of the process
	case errors.Is(err, windows.ERROR_ALREADY_EXISTS):
		// A losing instance must not keep the mutex alive: it may sit in
		// the "already running" box for hours, and `--quit` (the installer)
		// waits for the mutex to disappear
		windows.CloseHandle(h)
		return false
	default:
		if h != 0 {
			windows.CloseHandle(h)
		}
		log.Printf("Warning: single-instance check failed, continuing: %v", err)
		return true
	}
}

// WaitForExit waits until the process with the given PID has ended (or the
// timeout passes). A PID that cannot be opened counts as already gone.
// Used by a freshly updated exe (--wait-pid) to let its predecessor finish.
func WaitForExit(pid uint32, timeout time.Duration) error {
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, pid)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(h)

	event, err := windows.WaitForSingleObject(h, uint32(timeout/time.Millisecond))
	if err != nil {
		return fmt.Errorf("wait for process %d: %w", pid, err)
	}
	if event != windows.WAIT_OBJECT_0 {
		return fmt.Errorf("process %d is still running after %v", pid, timeout)
	}
	return nil
}

// IsSessionEnding reports whether the current Windows session is shutting
// down or logging off
func IsSessionEnding() bool {
	const smShuttingDown = 0x2000
	ret, _, _ := procGetSystemMetrics.Call(smShuttingDown)
	return ret != 0
}

// NormalizePriority raises this process back to normal CPU, I/O and memory
// priority when it was launched below normal. Task Scheduler starts tasks
// with the default <Priority>7</Priority> as BELOW_NORMAL with low I/O and
// memory priority, and sing-box inherits all of it. The task definition now
// asks for priority 4, but a task registered by an older version still
// launches the app the old way until it is re-registered.
func NormalizePriority() {
	self := windows.CurrentProcess()
	class, err := windows.GetPriorityClass(self)
	if err != nil {
		log.Printf("Warning: failed to read process priority: %v", err)
		return
	}
	if class != windows.BELOW_NORMAL_PRIORITY_CLASS && class != windows.IDLE_PRIORITY_CLASS {
		return
	}

	log.Printf("Process was started with low priority (class %#x), raising to normal", class)
	if err := windows.SetPriorityClass(self, windows.NORMAL_PRIORITY_CLASS); err != nil {
		log.Printf("Warning: failed to raise CPU priority: %v", err)
	}
	ioPriority := uint32(2) // IoPriorityNormal
	if err := windows.NtSetInformationProcess(self, windows.ProcessIoPriority, unsafe.Pointer(&ioPriority), uint32(unsafe.Sizeof(ioPriority))); err != nil {
		log.Printf("Warning: failed to raise I/O priority: %v", err)
	}
	pagePriority := uint32(5) // MEMORY_PRIORITY_NORMAL
	if err := windows.NtSetInformationProcess(self, windows.ProcessPagePriority, unsafe.Pointer(&pagePriority), uint32(unsafe.Sizeof(pagePriority))); err != nil {
		log.Printf("Warning: failed to raise memory priority: %v", err)
	}
}

// Short-lived runs of the very same sing-box.exe that are NOT the VPN:
// `sing-box check` on every config save, `sing-box version` for the updater.
// By image path they are indistinguishable from the VPN process, so without
// this registry a status check during a config save reported "running", a
// Start at that moment adopted the helper and started nothing, and a Stop
// killed the check (the save then failed with an empty error).
var (
	helperMu   sync.Mutex
	helperPIDs = map[uint32]struct{}{}
)

// HelperOutput runs a short-lived helper command (see helperPIDs) and returns
// its combined output, like exec.Cmd.CombinedOutput
func HelperOutput(cmd *exec.Cmd) ([]byte, error) {
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output

	// Start and register under the lock findProcesses takes before its
	// snapshot, so the helper is never seen unregistered
	helperMu.Lock()
	err := cmd.Start()
	if err == nil {
		helperPIDs[uint32(cmd.Process.Pid)] = struct{}{}
	}
	helperMu.Unlock()
	if err != nil {
		return nil, err
	}

	err = cmd.Wait()

	helperMu.Lock()
	delete(helperPIDs, uint32(cmd.Process.Pid))
	helperMu.Unlock()
	return output.Bytes(), err
}

// trustedIntegrity: an instance of the app's sing-box.exe counts as the
// app's own only when it runs at this integrity level or above. The app is
// elevated, and so is every sing-box it starts (High, or System); the
// installed sing-box.exe is executable by every user, and one started by a
// non-elevated program — with a config of its own — must not be taken for
// the VPN (the app would then never start the real one). A variable for the
// tests, which run below High.
var trustedIntegrity uint32 = securityMandatoryHighRID

// Integrity levels: the last sub-authority of a token's label SID
// (S-1-16-<level>); not in x/sys/windows
const (
	securityMandatoryLowRID    = 0x1000
	securityMandatoryMediumRID = 0x2000
	securityMandatoryHighRID   = 0x3000
)

// foundProcess is a running instance of an exe (see findProcesses)
type foundProcess struct {
	pid  uint32
	path string // its image path, as the system reports it
	// elevated: runs at trustedIntegrity or above — started by this app or
	// another elevated administrator's program. False also when the level
	// cannot be read (another user's process whose token is closed to us).
	elevated bool
}

// findProcesses returns the processes running the given exe.
// Matching is by FULL image path, not by image name: another sing-box.exe on
// the machine (a different client's copy) is neither adopted nor killed.
// A native snapshot instead of tasklist.exe: no child process (and no WMI,
// which is slow right after logon) on every status check.
func findProcesses(exePath string) ([]foundProcess, error) {
	// The image paths the system reports are final paths: a copy reached
	// through a junction (possibly onto another volume), a SUBST drive or a
	// \\?\ spelling must be compared in that form
	target := finalPath(exePath)

	// Held from BEFORE the snapshot: every helper run visible in it is then
	// guaranteed to be registered, and one started later is not in it
	helperMu.Lock()
	defer helperMu.Unlock()

	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("process snapshot: %w", err)
	}
	defer windows.CloseHandle(snapshot)

	imageName := filepath.Base(exePath)
	var found []foundProcess

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snapshot, &entry); err != nil {
		return nil, fmt.Errorf("process snapshot: %w", err)
	}
	for {
		// Cheap name filter first; the path needs a handle to the process
		_, isHelper := helperPIDs[entry.ProcessID]
		if !isHelper && strings.EqualFold(windows.UTF16ToString(entry.ExeFile[:]), imageName) {
			if path, elevated, err := processDetails(entry.ProcessID); err == nil && samePath(path, target) {
				found = append(found, foundProcess{pid: entry.ProcessID, path: path, elevated: elevated})
			}
			// A process that cannot be opened (another user's, protected) or
			// has just exited is not ours
		}
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
				return found, nil
			}
			return nil, fmt.Errorf("process snapshot: %w", err)
		}
	}
}

// processDetails returns the full path of the exe a process runs and whether
// it runs at trustedIntegrity or above — both read through one handle, so
// they describe the same process even if the PID is reused meanwhile
func processDetails(pid uint32) (path string, elevated bool, err error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", false, err
	}
	defer windows.CloseHandle(h)

	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return "", false, err
	}
	path = windows.UTF16ToString(buf[:size])

	var token windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token); err != nil {
		return path, false, nil
	}
	defer token.Close()
	level, err := integrityLevel(token)
	return path, err == nil && level >= trustedIntegrity, nil
}

// integrityLevel returns the mandatory integrity level (the RID of the
// label, e.g. SECURITY_MANDATORY_HIGH_RID) of a token
func integrityLevel(token windows.Token) (uint32, error) {
	var size uint32
	windows.GetTokenInformation(token, windows.TokenIntegrityLevel, nil, 0, &size)
	if size == 0 {
		return 0, errors.New("integrity level: empty answer")
	}
	buf := make([]byte, size)
	if err := windows.GetTokenInformation(token, windows.TokenIntegrityLevel, &buf[0], size, &size); err != nil {
		return 0, fmt.Errorf("integrity level: %w", err)
	}
	label := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&buf[0]))
	sid := label.Label.Sid
	if sid == nil || sid.SubAuthorityCount() == 0 {
		return 0, errors.New("integrity level: no label")
	}
	return sid.SubAuthority(uint32(sid.SubAuthorityCount()) - 1), nil
}

// finalPath returns the path Windows reports for the file behind path —
// through junctions, symbolic links, SUBST drives and a \\?\ spelling: the
// form QueryFullProcessImageName gives for a process started from it. The
// path itself when the file cannot be opened.
func finalPath(path string) string {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return path
	}
	h, err := windows.CreateFile(p, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return path
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), 0) // normalized, drive letter
	if err != nil || n == 0 || int(n) >= len(buf) {
		return path
	}
	final := windows.UTF16ToString(buf[:n])
	if rest, ok := strings.CutPrefix(final, `\\?\UNC\`); ok {
		return `\\` + rest
	}
	return strings.TrimPrefix(final, `\\?\`)
}

// samePath reports whether a process image path names the file at target (a
// finalPath). The textual check covers the normal case; os.SameFile also sees
// through 8.3 names and hard links — but only on the same volume: it opens
// both files, and the image path of another process may be a network share
// (UNC, WebDAV) that a program of the user serves and stalls for half a
// minute per access, while the caller holds the process locks.
func samePath(a, b string) bool {
	if strings.EqualFold(filepath.Clean(a), filepath.Clean(b)) {
		return true
	}
	if !strings.EqualFold(filepath.VolumeName(a), filepath.VolumeName(b)) {
		return false
	}
	infoA, errA := os.Stat(a)
	infoB, errB := os.Stat(b)
	return errA == nil && errB == nil && os.SameFile(infoA, infoB)
}

// terminateProcess kills one process and waits until it is really gone: a
// Start() right after (restart, binary swap) must not see the dying instance,
// and the updater needs the exe file unlocked. A process that has already
// exited is a success.
func terminateProcess(p foundProcess, timeout time.Duration) error {
	pid := p.pid
	h, gone, err := openToTerminate(p)
	if gone {
		return nil
	}
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)

	if err := windows.TerminateProcess(h, 1); err != nil && !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		// ACCESS_DENIED is what TerminateProcess returns for a process that
		// is already terminating — the wait below settles it either way
		return fmt.Errorf("terminate process %d: %w", pid, err)
	}

	event, err := windows.WaitForSingleObject(h, uint32(timeout/time.Millisecond))
	if err != nil {
		return fmt.Errorf("wait for process %d: %w", pid, err)
	}
	if event != windows.WAIT_OBJECT_0 {
		return fmt.Errorf("process %d is still running %v after it was killed", pid, timeout)
	}
	return nil
}

// terminateAll kills processes that are not this app's own (a non-elevated
// instance of its sing-box) and waits for them together, at most timeout in
// total. Not one by one: a process frozen by a debugger is not signalled
// after TerminateProcess until its debugger answers, and per-process waits
// would let whoever runs such processes hold the app's locks for as long as
// it likes. Returns how many ended within the time, and the first error.
func terminateAll(procs []foundProcess, timeout time.Duration) (int, error) {
	var (
		handles  []windows.Handle
		ended    int
		firstErr error
	)
	for _, p := range procs {
		h, gone, err := openToTerminate(p)
		if gone {
			ended++
			continue
		}
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		// ACCESS_DENIED: already terminating (see terminateProcess)
		if err := windows.TerminateProcess(h, 1); err != nil && !errors.Is(err, windows.ERROR_ACCESS_DENIED) && firstErr == nil {
			firstErr = fmt.Errorf("terminate process %d: %w", p.pid, err)
		}
		handles = append(handles, h)
	}
	deadline := time.Now().Add(timeout)
	for _, h := range handles {
		remaining := max(time.Until(deadline), 0)
		event, err := windows.WaitForSingleObject(h, uint32(remaining/time.Millisecond))
		windows.CloseHandle(h)
		if err == nil && event == windows.WAIT_OBJECT_0 {
			ended++
		} else if firstErr == nil {
			firstErr = fmt.Errorf("a process is still running %v after it was killed", timeout)
		}
	}
	return ended, firstErr
}

// openToTerminate opens a found process for termination. The PID is opened
// anew, so it is checked to still run the image it was found with: the
// process may have exited since the snapshot and its PID gone to another
// one — which the elevated app must not kill. gone: exited (or replaced).
func openToTerminate(p foundProcess) (h windows.Handle, gone bool, err error) {
	h, err = windows.OpenProcess(windows.PROCESS_TERMINATE|windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, p.pid)
	if err != nil {
		if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
			return 0, true, nil // no such process any more
		}
		return 0, false, fmt.Errorf("open process %d: %w", p.pid, err)
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if windows.QueryFullProcessImageName(h, 0, &buf[0], &size) == nil && !strings.EqualFold(windows.UTF16ToString(buf[:size]), p.path) {
		windows.CloseHandle(h)
		return 0, true, nil
	}
	return h, false, nil
}

const (
	CREATE_NO_WINDOW   = 0x08000000
	DETACHED_PROCESS   = 0x00000008
	CREATE_NEW_CONSOLE = 0x00000010
)

// hideConsoleWindow hides the console window for the child process
func hideConsoleWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: CREATE_NO_WINDOW | DETACHED_PROCESS,
	}
}

// useNormalPriority starts the child with normal CPU priority even when this
// process runs below normal (a child inherits BELOW_NORMAL/IDLE otherwise).
// Must be called after hideConsoleWindow.
func useNormalPriority(cmd *exec.Cmd) {
	cmd.SysProcAttr.CreationFlags |= windows.NORMAL_PRIORITY_CLASS
}

// NewHiddenCommand creates a new exec.Cmd with hidden console window
func NewHiddenCommand(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	hideConsoleWindow(cmd)
	return cmd
}

// NewHiddenCommandContext is NewHiddenCommand bound to ctx: the child is
// killed when ctx ends, and Wait gives up on its pipes shortly after
func NewHiddenCommandContext(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	hideConsoleWindow(cmd)
	cmd.WaitDelay = 5 * time.Second
	return cmd
}
