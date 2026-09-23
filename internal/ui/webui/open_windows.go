//go:build windows

package webui

import (
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"tray-sing-box/internal/config"
	"tray-sing-box/internal/infrastructure/paths"
)

var procCreateProcessWithTokenW = windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateProcessWithTokenW")

// openBrowser opens the URL in the default browser.
//
// The app runs elevated, and the program a URL opens with comes from the
// file associations — which include HKCU\Software\Classes, writable by any
// program of the user without elevation. Resolved in the elevated process,
// a per-user override of the browser's "open" command would turn the
// "Настройки" click into running anything as administrator (the pattern of
// the fodhelper/eventvwr UAC bypasses). So the elevated app never resolves
// it: rundll32 from System32 is started with the shell's own, non-elevated
// token, and the association is looked up at medium integrity, where it
// grants nothing new. If that is impossible, the URL is shown instead —
// never opened elevated.
func openBrowser(url string) error {
	rundll := paths.System32("rundll32.exe")
	if !windows.GetCurrentProcessToken().IsElevated() {
		cmd := exec.Command(rundll, "url.dll,FileProtocolHandler", url)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("failed to open browser: %w", err)
		}
		return nil
	}
	cmdline := `"` + rundll + `" url.dll,FileProtocolHandler ` + url
	if err := startAsShellUser(rundll, cmdline); err != nil {
		return fmt.Errorf("не удалось открыть браузер без прав администратора (%v). Откройте адрес вручную "+
			"(ссылка одноразовая, действует %d с): %s", err, config.WebLoginCodeSeconds, url)
	}
	return nil
}

// startAsShellUser starts app with the token of the desktop shell
// (explorer.exe of this session): the non-elevated user
func startAsShellUser(app, cmdline string) error {
	hwnd := windows.GetShellWindow()
	if hwnd == 0 {
		return errors.New("no desktop shell window")
	}
	var pid uint32
	if _, err := windows.GetWindowThreadProcessId(hwnd, &pid); err != nil || pid == 0 {
		return fmt.Errorf("shell process: %v", err)
	}
	proc, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return fmt.Errorf("open shell process: %w", err)
	}
	defer windows.CloseHandle(proc)

	// The shell window must belong to the real explorer, not to something
	// that registered itself as the shell
	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(proc, 0, &buf[0], &size); err != nil {
		return fmt.Errorf("shell image: %w", err)
	}
	image := windows.UTF16ToString(buf[:size])
	if want := filepath.Join(paths.SystemFolders().Windows, "explorer.exe"); !strings.EqualFold(image, want) {
		return fmt.Errorf("the shell is %s, not %s", image, want)
	}

	var shellToken windows.Token
	if err := windows.OpenProcessToken(proc, windows.TOKEN_DUPLICATE, &shellToken); err != nil {
		return fmt.Errorf("shell token: %w", err)
	}
	defer shellToken.Close()
	var primary windows.Token
	if err := windows.DuplicateTokenEx(shellToken,
		windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE|windows.TOKEN_ASSIGN_PRIMARY|windows.TOKEN_ADJUST_DEFAULT|windows.TOKEN_ADJUST_SESSIONID,
		nil, windows.SecurityImpersonation, windows.TokenPrimary, &primary); err != nil {
		return fmt.Errorf("duplicate shell token: %w", err)
	}
	defer primary.Close()

	appPtr, err := windows.UTF16PtrFromString(app)
	if err != nil {
		return err
	}
	cmdPtr, err := windows.UTF16PtrFromString(cmdline)
	if err != nil {
		return err
	}
	si := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{}))}
	var pi windows.ProcessInformation
	// CreateProcessWithTokenW needs SeImpersonatePrivilege, which an
	// elevated administrator token has enabled by default
	r, _, callErr := procCreateProcessWithTokenW.Call(
		uintptr(primary), 0,
		uintptr(unsafe.Pointer(appPtr)), uintptr(unsafe.Pointer(cmdPtr)),
		0, 0, 0,
		uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi)))
	if r == 0 {
		return fmt.Errorf("CreateProcessWithTokenW: %w", callErr)
	}
	windows.CloseHandle(pi.Thread)
	windows.CloseHandle(pi.Process)
	return nil
}
