//go:build windows
// +build windows

package process

import (
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32          = windows.NewLazySystemDLL("user32.dll")
	procFindWindowW = user32.NewProc("FindWindowW")
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

// NewHiddenCommand creates a new exec.Cmd with hidden console window
func NewHiddenCommand(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	hideConsoleWindow(cmd)
	return cmd
}
