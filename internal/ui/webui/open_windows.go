//go:build windows

package webui

import (
	"fmt"
	"os/exec"
	"syscall"
)

// openBrowser opens the URL in the default browser without showing a console
func openBrowser(url string) error {
	cmd := exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to open browser: %w", err)
	}
	return nil
}
