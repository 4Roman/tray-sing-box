//go:build windows

package clipboard

import (
	"os/exec"
	"testing"
)

// setClipboard puts text into the real Windows clipboard via PowerShell
func setClipboard(t *testing.T, text string) {
	t.Helper()
	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		"Set-Clipboard -Value ([Console]::In.ReadToEnd())")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Skipf("powershell unavailable: %v", err)
	}
	// PowerShell reads stdin as UTF-8 only with BOM-less detection issues;
	// ASCII test data avoids encoding ambiguity in the transport
	stdin.Write([]byte(text))
	stdin.Close()
	if err := cmd.Wait(); err != nil {
		t.Skipf("Set-Clipboard failed: %v", err)
	}
}

func TestReadTextFromRealClipboard(t *testing.T) {
	original, _ := ReadText()
	defer func() {
		if original != "" {
			setClipboard(t, original)
		}
	}()

	want := "vless://test-uuid@example.com:443?security=tls#clipboard-test"
	setClipboard(t, want)

	got, err := ReadText()
	if err != nil {
		t.Fatalf("ReadText: %v", err)
	}
	// Set-Clipboard may append a trailing newline
	if got != want && got != want+"\r\n" && got != want+"\n" {
		t.Fatalf("ReadText = %q, want %q", got, want)
	}
}
