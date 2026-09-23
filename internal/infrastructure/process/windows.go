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
// ends. Fails open — a problem with the mutex itself must never keep the app
// from starting at logon.
func AcquireSingleInstance() bool {
	name, err := windows.UTF16PtrFromString(instanceMutexName)
	if err != nil {
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
		genuine := trustedObjectOwner(h)
		windows.CloseHandle(h)
		if !genuine {
			log.Printf("Warning: %s exists but was not created by an instance of this app — ignored", instanceMutexName)
			return true
		}
		return false
	case errors.Is(err, windows.ERROR_ACCESS_DENIED):
		// A genuine instance runs elevated and its mutex grants
		// Administrators (another admin user's instance included), so
		// "access denied" means a non-administrator created the object —
		// squatting on the name must not keep the VPN from being restored
		log.Printf("Warning: %s is held by a non-administrator — ignored", instanceMutexName)
		return true
	case errors.Is(err, windows.ERROR_INVALID_OWNER):
		// Not elevated (a non-elevated run of the exe, which the manifest
		// normally prevents): no Administrators owner possible — take it
		// with the default descriptor. Tests swap objectSDDL instead.
		h, err = windows.CreateMutex(nil, false, name)
		if err == nil {
			return true
		}
		if h != 0 {
			windows.CloseHandle(h)
		}
		return !errors.Is(err, windows.ERROR_ALREADY_EXISTS)
	default:
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

// findProcesses returns the PIDs of the processes running the given exe.
// Matching is by FULL image path, not by image name: another sing-box.exe on
// the machine (a different client's copy) is neither adopted nor killed.
// A native snapshot instead of tasklist.exe: no child process (and no WMI,
// which is slow right after logon) on every status check.
func findProcesses(exePath string) ([]uint32, error) {
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
	var pids []uint32

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snapshot, &entry); err != nil {
		return nil, fmt.Errorf("process snapshot: %w", err)
	}
	for {
		// Cheap name filter first; the path needs a handle to the process
		_, isHelper := helperPIDs[entry.ProcessID]
		if !isHelper && strings.EqualFold(windows.UTF16ToString(entry.ExeFile[:]), imageName) {
			if path, err := processImagePath(entry.ProcessID); err == nil && samePath(path, exePath) {
				pids = append(pids, entry.ProcessID)
			}
			// A process that cannot be opened (another user's, protected) or
			// has just exited is not ours
		}
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
				return pids, nil
			}
			return nil, fmt.Errorf("process snapshot: %w", err)
		}
	}
}

// processImagePath returns the full path of the exe a process runs
func processImagePath(pid uint32) (string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)

	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:size]), nil
}

// samePath reports whether two paths name the same file. The textual check
// covers the normal case; os.SameFile also sees through 8.3 names, links and
// differently spelled prefixes.
func samePath(a, b string) bool {
	if strings.EqualFold(filepath.Clean(a), filepath.Clean(b)) {
		return true
	}
	infoA, errA := os.Stat(a)
	infoB, errB := os.Stat(b)
	return errA == nil && errB == nil && os.SameFile(infoA, infoB)
}

// terminateProcess kills one process and waits until it is really gone: a
// Start() right after (restart, binary swap) must not see the dying instance,
// and the updater needs the exe file unlocked. A process that has already
// exited is a success.
func terminateProcess(pid uint32, timeout time.Duration) error {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, pid)
	if err != nil {
		if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
			return nil // no such process any more
		}
		return fmt.Errorf("open process %d: %w", pid, err)
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
