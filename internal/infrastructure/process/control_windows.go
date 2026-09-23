//go:build windows

package process

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"tray-sing-box/internal/config"
)

// The kernel objects that let another process talk to the running instance
// — the single-instance mutex (see AcquireSingleInstance), the "please quit"
// event of the installer and `tray-sing-box.exe --quit`, the installation
// marker — live in a private namespace, not under Global\ names: any user
// may create a Global\ name first, and the installer could then not ask the
// app to quit. Two gates, both verified by probes on Windows 11:
//   - creating: the boundary names Administrators and the High integrity
//     level, and the kernel creates the namespace only for a token that
//     satisfies both — an elevated administrator or SYSTEM. A non-elevated
//     program (of this user, whose Administrators group is then deny-only,
//     or of another) cannot create it first, with a descriptor of its own
//     (the MS16-118 squatting).
//   - opening an existing one: the kernel does NOT check the boundary then,
//     only the namespace's descriptor, objectSDDL: owner Administrators,
//     access for SYSTEM and Administrators. A deny-only Administrators group
//     matches neither an allow entry nor the owner.
//
// Variables so that the tests can use a namespace of their own: a test must
// never signal the quit event of a real instance running on the machine.
var (
	namespaceName     = "SingBoxTray"            // boundary name and alias prefix
	boundarySIDs      = []string{"S-1-5-32-544"} // BUILTIN\Administrators
	boundaryIntegrity = "S-1-16-12288"           // High mandatory level; "" = none

	instanceMutexName = "single-instance"
	quitEventName     = "quit"
	markerPrefix      = "instance-"

	// objectSDDL: the namespace and the objects in it — owner
	// Administrators, access for SYSTEM and Administrators only. For the
	// namespace this is what keeps non-elevated programs from opening it.
	objectSDDL = "O:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)"
)

var (
	modkernel32                               = windows.NewLazySystemDLL("kernel32.dll")
	procCreateBoundaryDescriptorW             = modkernel32.NewProc("CreateBoundaryDescriptorW")
	procAddSIDToBoundaryDescriptor            = modkernel32.NewProc("AddSIDToBoundaryDescriptor")
	procAddIntegrityLabelToBoundaryDescriptor = modkernel32.NewProc("AddIntegrityLabelToBoundaryDescriptor")
	procDeleteBoundaryDescriptor              = modkernel32.NewProc("DeleteBoundaryDescriptor")
	procCreatePrivateNamespaceW               = modkernel32.NewProc("CreatePrivateNamespaceW")
	procOpenPrivateNamespaceW                 = modkernel32.NewProc("OpenPrivateNamespaceW")
	procClosePrivateNamespace                 = modkernel32.NewProc("ClosePrivateNamespace")
)

// errNoNamespace: nobody has created the namespace, i.e. no instance runs
var errNoNamespace = errors.New("the app's namespace does not exist")

// namespace is this process's handle to the private namespace. Kept open for
// the life of the process: an alias can be registered once per process, and
// the namespace lives as long as ANY process holds it (verified — the
// documentation suggests it ends with its creator's handle).
var namespace struct {
	sync.Mutex
	handle uintptr
}

// objectName returns the name of one of the app's kernel objects inside the
// namespace. The namespace is opened on first use; create (the instance
// itself, not the helpers asking about it) also creates it when it does not
// exist yet.
func objectName(name string, create bool) (*uint16, error) {
	namespace.Lock()
	defer namespace.Unlock()
	if namespace.handle == 0 {
		h, err := openNamespace(create)
		if err != nil {
			return nil, err
		}
		namespace.handle = h
	}
	return windows.UTF16PtrFromString(namespaceName + `\` + name)
}

func openNamespace(create bool) (uintptr, error) {
	boundary, err := newBoundary()
	if err != nil {
		return 0, err
	}
	defer procDeleteBoundaryDescriptor.Call(boundary)
	alias, err := windows.UTF16PtrFromString(namespaceName)
	if err != nil {
		return 0, err
	}
	for attempt := 0; attempt < 3; attempt++ {
		h, _, err := procOpenPrivateNamespaceW.Call(boundary, uintptr(unsafe.Pointer(alias)))
		if h != 0 {
			return h, nil
		}
		if !errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return 0, fmt.Errorf("open namespace: %w", err)
		}
		if !create {
			return 0, errNoNamespace
		}
		h, _, err = procCreatePrivateNamespaceW.Call(uintptr(unsafe.Pointer(objectAttributes())), boundary, uintptr(unsafe.Pointer(alias)))
		if h != 0 {
			return h, nil
		}
		if !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return 0, fmt.Errorf("create namespace: %w", err)
		}
		// Another process created it in between: open that one
	}
	return 0, errors.New("create namespace: it keeps appearing and vanishing")
}

// newBoundary builds the namespace's boundary descriptor (to be freed with
// DeleteBoundaryDescriptor)
func newBoundary() (uintptr, error) {
	name, err := windows.UTF16PtrFromString(namespaceName)
	if err != nil {
		return 0, err
	}
	boundary, _, callErr := procCreateBoundaryDescriptorW.Call(uintptr(unsafe.Pointer(name)), 0)
	if boundary == 0 {
		return 0, fmt.Errorf("boundary descriptor: %w", callErr)
	}
	add := func(proc *windows.LazyProc, sidString string) error {
		sid, err := windows.StringToSid(sidString)
		if err != nil {
			return err
		}
		// The descriptor may be reallocated: the call takes its address
		if ok, _, callErr := proc.Call(uintptr(unsafe.Pointer(&boundary)), uintptr(unsafe.Pointer(sid))); ok == 0 {
			return fmt.Errorf("boundary descriptor %s: %w", sidString, callErr)
		}
		return nil
	}
	for _, s := range boundarySIDs {
		if err := add(procAddSIDToBoundaryDescriptor, s); err != nil {
			procDeleteBoundaryDescriptor.Call(boundary)
			return 0, err
		}
	}
	if boundaryIntegrity != "" {
		if err := add(procAddIntegrityLabelToBoundaryDescriptor, boundaryIntegrity); err != nil {
			procDeleteBoundaryDescriptor.Call(boundary)
			return 0, err
		}
	}
	return boundary, nil
}

// objectAttributes builds the security attributes for the app's kernel
// objects; nil when the descriptor cannot be built (then the default one)
func objectAttributes() *windows.SecurityAttributes {
	sd, err := windows.SecurityDescriptorFromString(objectSDDL)
	if err != nil {
		return nil
	}
	return &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
}

// WatchQuitRequest creates the quit event and calls onQuit (once, from its
// own goroutine) when another process signals it. The installer uses this
// to replace the exe of a running copy; a killed tray app would leave the
// VPN in whatever state a running operation was in, this lets it finish.
func WatchQuitRequest(onQuit func()) error {
	name, err := objectName(quitEventName, true)
	if err != nil {
		return fmt.Errorf("quit event: %w", err)
	}
	// Manual-reset: stays signalled, so a request that arrives a moment
	// before the wait starts is not lost
	event, err := windows.CreateEvent(objectAttributes(), 1, 0, name)
	if err != nil {
		if event != 0 {
			windows.CloseHandle(event)
		}
		return fmt.Errorf("create quit event: %w", err)
	}
	go func() {
		windows.WaitForSingleObject(event, windows.INFINITE)
		log.Println("Quit requested by another process")
		onQuit()
	}()
	return nil
}

// RequestQuit signals the running instance to exit. ok is false when no
// instance is running (nothing to quit).
func RequestQuit() (ok bool, err error) {
	name, err := objectName(quitEventName, false)
	if errors.Is(err, errNoNamespace) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	event, err := windows.OpenEvent(windows.EVENT_MODIFY_STATE, false, name)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return false, nil
		}
		return false, fmt.Errorf("open quit event: %w", err)
	}
	defer windows.CloseHandle(event)
	if err := windows.SetEvent(event); err != nil {
		return false, fmt.Errorf("signal quit event: %w", err)
	}
	return true, nil
}

// InstanceRunning reports whether some instance holds the single-instance
// mutex. An instance that is still starting up holds it before it creates
// the quit event, so "no quit event" alone does not mean "no instance".
func InstanceRunning() bool {
	name, err := objectName(instanceMutexName, false)
	if err != nil {
		return false // no namespace: no instance (the callers are elevated)
	}
	h, err := windows.OpenMutex(windows.SYNCHRONIZE, false, name)
	if err != nil {
		return false
	}
	windows.CloseHandle(h)
	return true
}

// installationMarker is the name of the object the running instance of the
// installation in dir holds for its lifetime: the quit event is global, and
// "a process of that directory exists" is not the same as "the running
// instance is that directory's" (a second instance may sit in the "already
// running" box)
func installationMarker(dir string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(filepath.Clean(dir))))
	return markerPrefix + hex.EncodeToString(sum[:8])
}

var markerHandle windows.Handle // kept for the life of the process

// MarkInstallation is called by the instance that won the single-instance
// mutex, with its Bin directory
func MarkInstallation(dir string) error {
	name, err := objectName(installationMarker(dir), true)
	if err != nil {
		return fmt.Errorf("installation marker: %w", err)
	}
	h, err := windows.CreateEvent(objectAttributes(), 1, 0, name)
	if err != nil {
		if h != 0 {
			windows.CloseHandle(h)
		}
		return fmt.Errorf("installation marker: %w", err)
	}
	markerHandle = h
	return nil
}

// InstallationRunning reports whether the running instance is the one of
// the installation in dir (its marker exists)
func InstallationRunning(dir string) bool {
	name, err := objectName(installationMarker(dir), false)
	if err != nil {
		return false
	}
	h, err := windows.OpenEvent(windows.SYNCHRONIZE, false, name)
	if err != nil {
		return false
	}
	windows.CloseHandle(h)
	return true
}

// WaitForInstanceExit waits until no instance holds the single-instance
// mutex any more
func WaitForInstanceExit(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for InstanceRunning() {
		if time.Now().After(deadline) {
			return fmt.Errorf("the running instance did not exit within %v", timeout)
		}
		time.Sleep(200 * time.Millisecond)
	}
	return nil
}

// EndInstallation ends the tray app and the sing-box of the installation in
// dir, gracefully where possible: a running tray app of a build with the
// quit event is asked to exit (it finishes its current operation first),
// then whatever is left — the tray app of an older build, sing-box — is
// terminated by full path. Used by the takeover of a portable installation.
func EndInstallation(dir string) (int, error) {
	// Graceful only when the running instance is provably that directory's
	// (the quit event would end whichever instance runs); an older build
	// without the marker is terminated by path below
	if InstallationRunning(dir) {
		if ok, err := RequestQuit(); err != nil {
			log.Printf("Warning: could not ask the tray app in %s to quit: %v", dir, err)
		} else if ok {
			log.Printf("Asked the tray app in %s to quit", dir)
			if err := WaitForInstanceExit(config.StopWaitTimeout * 6 * time.Second); err != nil {
				log.Printf("Warning: %v", err)
			}
		}
	}
	return StopInstallation(dir)
}

// StopInstallation terminates the tray app and the sing-box of the
// installation in dir — matched by full path, so any other copy on the
// machine is untouched. Used by the uninstaller and when a previous
// portable installation is taken over. Returns how many processes it ended.
func StopInstallation(dir string) (int, error) {
	return StopProcessesOf(dir, config.AppExeName, config.SingBoxExe)
}

// StopProcessesOf terminates every running instance of the given exe names
// located in dir, one name after the other in the given order — the tray app
// first: until it is gone it may start another sing-box, which a snapshot
// taken before would miss. The instances of one name end together, with one
// bounded wait (see terminateAll: anyone may start the installation's
// sing-box.exe, and a debugger can keep a terminated one from ending).
func StopProcessesOf(dir string, exes ...string) (int, error) {
	stopped := 0
	var firstErr error
	for _, exe := range exes {
		found, err := findProcesses(filepath.Join(dir, exe))
		if err != nil {
			return stopped, err
		}
		var procs []foundProcess
		for _, p := range found {
			if p.pid == windows.GetCurrentProcessId() {
				// `--uninstall-cleanup` runs from the installation it cleans
				// up: the helper itself is not what has to be stopped
				continue
			}
			log.Printf("Stopping %s (PID %d) of the installation in %s", exe, p.pid, dir)
			procs = append(procs, p)
		}
		if len(procs) == 0 {
			continue
		}
		n, err := terminateAll(procs, config.StopWaitTimeout*time.Second)
		stopped += n
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return stopped, firstErr
}
