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
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"tray-sing-box/internal/config"
)

// Names of the kernel objects that let another process talk to the running
// instance: the single-instance mutex (see AcquireSingleInstance) and the
// "please quit" event used by the installer and `tray-sing-box.exe --quit`.
// Variables so that the tests can use private names: a test must never
// signal the quit event of a real instance running on the machine
var (
	instanceMutexName = `Global\SingBoxTray-single-instance`
	quitEventName     = `Global\SingBoxTray-quit`
	markerPrefix      = `Global\SingBoxTray-instance-`

	// objectSDDL: owner Administrators — which only an elevated token can
	// set, so a genuine instance's objects are told apart from a squatter's
	// (even the same user's non-elevated programs) — and access for
	// SYSTEM and Administrators only
	objectSDDL = "O:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)"

	// trustCurrentUser: tests only (a non-elevated test process cannot set
	// the Administrators owner)
	trustCurrentUser = false
)

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
	name, err := windows.UTF16PtrFromString(quitEventName)
	if err != nil {
		return err
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
	name, err := windows.UTF16PtrFromString(quitEventName)
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
	name, err := windows.UTF16PtrFromString(instanceMutexName)
	if err != nil {
		return false
	}
	h, err := windows.OpenMutex(windows.SYNCHRONIZE|windows.READ_CONTROL, false, name)
	if err != nil {
		// Not found — or ACCESS_DENIED: a genuine instance's mutex grants
		// Administrators, so that is a non-administrator's object squatting
		// the name (see AcquireSingleInstance), not an instance. The callers
		// (--quit, the installer) are elevated.
		return false
	}
	defer windows.CloseHandle(h)
	return trustedObjectOwner(h)
}

// trustedObjectOwner reports whether a kernel object was created by an
// instance of this app: owned by Administrators or SYSTEM. Instances set the
// owner explicitly (objectSDDL), so this holds under any owner policy, and a
// non-elevated program — of another user or of this one — cannot produce it.
func trustedObjectOwner(h windows.Handle) bool {
	sd, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return false
	}
	if owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) || owner.IsWellKnown(windows.WinLocalSystemSid) {
		return true
	}
	if trustCurrentUser {
		if user, err := windows.GetCurrentProcessToken().GetTokenUser(); err == nil && user.User.Sid != nil {
			return owner.Equals(user.User.Sid)
		}
	}
	return false
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
	name, err := windows.UTF16PtrFromString(installationMarker(dir))
	if err != nil {
		return err
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
// the installation in dir (its marker exists and is genuine)
func InstallationRunning(dir string) bool {
	name, err := windows.UTF16PtrFromString(installationMarker(dir))
	if err != nil {
		return false
	}
	h, err := windows.OpenEvent(windows.SYNCHRONIZE|windows.READ_CONTROL, false, name)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	return trustedObjectOwner(h)
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
// located in dir
func StopProcessesOf(dir string, exes ...string) (int, error) {
	stopped := 0
	var firstErr error
	for _, exe := range exes {
		pids, err := findProcesses(filepath.Join(dir, exe))
		if err != nil {
			return stopped, err
		}
		for _, pid := range pids {
			if pid == windows.GetCurrentProcessId() {
				// `--uninstall-cleanup` runs from the installation it cleans
				// up: the helper itself is not what has to be stopped
				continue
			}
			log.Printf("Stopping %s (PID %d) of the installation in %s", exe, pid, dir)
			if err := terminateProcess(pid, config.StopWaitTimeout*time.Second); err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			stopped++
		}
	}
	return stopped, firstErr
}
