package autostart

import (
	"encoding/xml"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf16"

	"golang.org/x/sys/windows"

	"tray-sing-box/internal/config"
)

const (
	CREATE_NO_WINDOW = 0x08000000
	DETACHED_PROCESS = 0x00000008
)

// newHiddenCommand creates a new exec.Cmd with hidden console window
func newHiddenCommand(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: CREATE_NO_WINDOW | DETACHED_PROCESS,
	}
	return cmd
}

// Scheduler manages Windows Task Scheduler for autostart functionality
type Scheduler struct {
	exePath string
}

// New creates a new scheduler instance
func New() (*Scheduler, error) {
	exePath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("failed to get executable path: %w", err)
	}

	return &Scheduler{
		exePath: exePath,
	}, nil
}

// IsEnabled checks if autostart is enabled
func (s *Scheduler) IsEnabled() bool {
	cmd := newHiddenCommand("schtasks", "/Query", "/TN", config.AppName)
	err := cmd.Run()
	return err == nil
}

// currentUserID returns an identifier for the current user suitable for the
// task XML. The SID is preferred over COMPUTERNAME\USERNAME because the
// environment username does not always match the account name Task Scheduler
// expects (e.g. Microsoft accounts on Windows 11).
func currentUserID() string {
	token := windows.GetCurrentProcessToken()
	if tokenUser, err := token.GetTokenUser(); err == nil && tokenUser.User.Sid != nil {
		return tokenUser.User.Sid.String()
	}

	username := os.Getenv("USERNAME")
	if username == "" {
		username = os.Getenv("USER")
	}
	return fmt.Sprintf("%s\\%s", os.Getenv("COMPUTERNAME"), username)
}

// xmlEscape escapes a string for safe embedding in XML content
func xmlEscape(s string) string {
	var b strings.Builder
	if err := xml.EscapeText(&b, []byte(s)); err != nil {
		return s
	}
	return b.String()
}

// encodeUTF16LE converts a string to UTF-16 little-endian bytes with BOM,
// matching the encoding declared in the task XML header. schtasks on
// Windows 11 rejects XML whose actual encoding does not match the declaration.
func encodeUTF16LE(s string) []byte {
	codes := utf16.Encode([]rune(s))
	buf := make([]byte, 0, 2+len(codes)*2)
	buf = append(buf, 0xFF, 0xFE) // UTF-16LE BOM
	for _, c := range codes {
		buf = append(buf, byte(c), byte(c>>8))
	}
	return buf
}

// taskXML builds the Task Scheduler definition for starting the app at logon
func (s *Scheduler) taskXML() string {
	userID := currentUserID()
	workingDir := filepath.Dir(s.exePath)

	xmlTemplate := `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Sing-Box VPN Tray Manager - Auto-start at login</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>%s</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>%s</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>%s</Command>
      <WorkingDirectory>%s</WorkingDirectory>
    </Exec>
  </Actions>
</Task>`

	return fmt.Sprintf(xmlTemplate,
		xmlEscape(userID),
		xmlEscape(userID),
		xmlEscape(s.exePath),
		xmlEscape(workingDir),
	)
}

// Enable enables autostart via Task Scheduler
func (s *Scheduler) Enable() error {
	xmlContent := s.taskXML()

	xmlFile, err := os.CreateTemp("", "singbox-task-*.xml")
	if err != nil {
		return fmt.Errorf("failed to create XML file: %w", err)
	}
	xmlPath := xmlFile.Name()
	defer os.Remove(xmlPath)

	if _, err := xmlFile.Write(encodeUTF16LE(xmlContent)); err != nil {
		xmlFile.Close()
		return fmt.Errorf("failed to write XML file: %w", err)
	}
	if err := xmlFile.Close(); err != nil {
		return fmt.Errorf("failed to close XML file: %w", err)
	}

	// Create scheduled task from XML
	cmd := newHiddenCommand("schtasks", "/Create", "/TN", config.AppName, "/XML", xmlPath, "/F")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to create scheduled task: %w\nOutput: %s", err, string(output))
	}

	log.Printf("Autostart enabled via Task Scheduler: %s", string(output))
	return nil
}

// Disable disables autostart
func (s *Scheduler) Disable() error {
	cmd := newHiddenCommand("schtasks", "/Delete", "/TN", config.AppName, "/F")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to delete scheduled task: %w\nOutput: %s", err, string(output))
	}

	log.Printf("Autostart disabled: %s", string(output))
	return nil
}
