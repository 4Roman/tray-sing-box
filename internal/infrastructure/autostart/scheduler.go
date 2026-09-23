package autostart

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf16"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"tray-sing-box/internal/config"
	"tray-sing-box/internal/infrastructure/paths"
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

// taskVersion is stamped into the task definition (RegistrationInfo/Version).
// Bump it whenever taskXML changes: a task registered for this exe with
// another (or no) version is re-registered on the next start.
const taskVersion = "2"

// taskInfo is what the app needs to know about the registered task
type taskInfo struct {
	command  string // exe the task launches
	enabled  bool   // Settings/Enabled (absent means true)
	version  string // RegistrationInfo/Version, "" for tasks of older builds
	userID   string // Principals/Principal/UserId: SID, or DOMAIN\user (older builds)
	runLevel string // Principals/Principal/RunLevel
}

// parseTaskXML extracts taskInfo from a task definition (already decoded to
// a Go string, as stored by Task Scheduler or exported by schtasks)
func parseTaskXML(content string) (taskInfo, error) {
	// The prolog declares UTF-16, which the decoder would refuse for a
	// string that is UTF-8 by now
	content = strings.TrimPrefix(content, "\uFEFF")
	if strings.HasPrefix(content, "<?xml") {
		if end := strings.Index(content, "?>"); end >= 0 {
			content = content[end+2:]
		}
	}

	var def struct {
		RegistrationInfo struct {
			Version string `xml:"Version"`
		} `xml:"RegistrationInfo"`
		Settings struct {
			Enabled *bool `xml:"Enabled"`
		} `xml:"Settings"`
		Principals struct {
			Principal struct {
				UserID   string `xml:"UserId"`
				RunLevel string `xml:"RunLevel"`
			} `xml:"Principal"`
		} `xml:"Principals"`
		Actions struct {
			Exec struct {
				Command string `xml:"Command"`
			} `xml:"Exec"`
		} `xml:"Actions"`
	}
	if err := xml.Unmarshal([]byte(content), &def); err != nil {
		return taskInfo{}, fmt.Errorf("failed to parse task XML: %w", err)
	}

	return taskInfo{
		command:  strings.Trim(strings.TrimSpace(def.Actions.Exec.Command), `"`),
		enabled:  def.Settings.Enabled == nil || *def.Settings.Enabled,
		version:  strings.TrimSpace(def.RegistrationInfo.Version),
		userID:   strings.TrimSpace(def.Principals.Principal.UserID),
		runLevel: strings.TrimSpace(def.Principals.Principal.RunLevel),
	}, nil
}

// decodeTaskFile converts a stored task definition to a string. Task
// Scheduler writes UTF-16LE with BOM.
func decodeTaskFile(data []byte) string {
	if len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE {
		data = data[2:]
		codes := make([]uint16, 0, len(data)/2)
		for i := 0; i+1 < len(data); i += 2 {
			codes = append(codes, uint16(data[i])|uint16(data[i+1])<<8)
		}
		return string(utf16.Decode(codes))
	}
	return string(data)
}

// registeredTask reads the definition of the registered autostart task.
// The stored task file is used rather than "schtasks /Query /XML": it has a
// reliable encoding (piped schtasks output depends on the console code page,
// which garbles non-ASCII paths). ok=false when the task does not exist or
// its definition cannot be read.
func (s *Scheduler) registeredTask() (info taskInfo, ok bool) {
	// Not %SystemRoot%: a user variable would override it for the elevated
	// app and point this at a fake definition (RegisteredExe drives the
	// takeover, which copies and runs what it finds)
	root := paths.SystemFolders().Windows
	if root == "" {
		root = `C:\Windows`
	}
	// Every user may create files in System32\Tasks: a definition counts
	// only when an administrator (the Task Scheduler) owns the file and the
	// task is really registered (TaskCache in HKLM, writable by admins only)
	f, err := paths.OpenTrustedFile(filepath.Join(root, "System32", "Tasks", config.AppName))
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Printf("Warning: autostart task definition ignored: %v", err)
		}
		return taskInfo{}, false
	}
	data, err := io.ReadAll(io.LimitReader(f, 1<<20))
	f.Close()
	if err != nil {
		return taskInfo{}, false
	}
	if !taskRegistered(config.AppName) {
		log.Printf("Warning: a %s task file exists but no such task is registered — ignored", config.AppName)
		return taskInfo{}, false
	}
	info, err = parseTaskXML(decodeTaskFile(data))
	if err != nil {
		log.Printf("Warning: %v", err)
		return taskInfo{}, false
	}
	return info, true
}

// RegisteredExe returns the exe the autostart task currently launches
// ("" when there is no readable task). A previous installation is found
// through it.
func (s *Scheduler) RegisteredExe() string {
	info, ok := s.registeredTask()
	if !ok {
		return ""
	}
	return info.command
}

// taskRegistered reports whether the Task Scheduler knows a root task of
// that name. Its cache lives in HKLM and is readable by administrators only:
// false only when the cache positively has no such task. A caller that may
// not read it (not elevated — never the app itself) gets true, and the owner
// check of the definition file still applies.
func taskRegistered(name string) bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\`+name, registry.QUERY_VALUE)
	if err == nil {
		k.Close()
		return true
	}
	return !errors.Is(err, registry.ErrNotExist)
}

// TakeoverSource returns the exe of the registered task when it may serve
// as the source of a takeover — whose sing-box.exe and DLLs end up in
// Program Files and run elevated. The task name proves nothing: a standard
// user may create tasks in the root folder, under any free name. Required:
// the task runs as the current user at the highest run level. Another
// account cannot register a task for this user, and this user's own
// non-elevated programs cannot register HighestAvailable (access denied
// without elevation). "" when there is no such task.
func (s *Scheduler) TakeoverSource() (exe string, enabled bool) {
	info, ok := s.registeredTask()
	if !ok || !trustedPrincipal(info, currentUserSID()) {
		return "", false
	}
	return info.command, info.enabled
}

func currentUserSID() *windows.SID {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil
	}
	return user.User.Sid
}

func trustedPrincipal(info taskInfo, me *windows.SID) bool {
	if me == nil || !strings.EqualFold(info.runLevel, "HighestAvailable") {
		return false
	}
	sid, err := windows.StringToSid(info.userID)
	if err != nil {
		// Builds before June 2026 wrote COMPUTERNAME\USERNAME
		if sid, _, _, err = windows.LookupSID("", info.userID); err != nil {
			return false
		}
	}
	return sid.Equals(me)
}

// ownsTask reports whether the registered task launches this very exe
func (s *Scheduler) ownsTask(info taskInfo) bool {
	return strings.EqualFold(filepath.Clean(info.command), filepath.Clean(s.exePath))
}

// IsEnabled checks if autostart is enabled for this copy of the app: the
// task exists, is not disabled and launches this exe. A task that points at
// another copy (or was disabled in the Task Scheduler UI) shows as "off", so
// clicking the checkbox re-registers it for this exe.
func (s *Scheduler) IsEnabled() bool {
	if info, ok := s.registeredTask(); ok {
		return info.enabled && s.ownsTask(info)
	}
	// Definition not readable: fall back to the plain existence check
	return s.taskExists()
}

// OwnsTask reports whether the registered task launches this exe, enabled or
// not: the uninstaller removes a task the user merely disabled in the Task
// Scheduler, too — it would otherwise survive pointing at a deleted exe.
// An unreadable definition falls back to the plain existence check, like
// IsEnabled.
func (s *Scheduler) OwnsTask() bool {
	if info, ok := s.registeredTask(); ok {
		return s.ownsTask(info)
	}
	return s.taskExists()
}

func (s *Scheduler) taskExists() bool {
	cmd := newHiddenCommand(paths.System32("schtasks.exe"), "/Query", "/TN", config.AppName)
	return cmd.Run() == nil
}

// RefreshIfOutdated re-registers the autostart task when it belongs to this
// exe but was created from an older task definition (heals tasks of previous
// versions), or when the exe it launches no longer exists (the app folder was
// moved). A task that launches another existing copy is left alone: simply
// running a second copy — e.g. a dev build from the repo — must not silently
// repoint autostart at it. Disabled tasks are never touched.
func (s *Scheduler) RefreshIfOutdated() error {
	info, ok := s.registeredTask()
	if !ok {
		return nil
	}

	refresh, reason := s.needsRefresh(info, func(path string) bool {
		_, err := os.Stat(path)
		return !os.IsNotExist(err)
	})
	if reason != "" {
		log.Printf("Autostart task: %s", reason)
	}
	if !refresh {
		return nil
	}
	return s.Enable()
}

// needsRefresh decides whether the registered task must be re-registered for
// this exe; reason is a log line ("" when there is nothing worth logging)
func (s *Scheduler) needsRefresh(info taskInfo, exeExists func(path string) bool) (refresh bool, reason string) {
	if !info.enabled {
		return false, ""
	}

	if s.ownsTask(info) {
		if info.version == taskVersion {
			return false, ""
		}
		return true, fmt.Sprintf("definition is outdated (version %q, want %q), re-registering", info.version, taskVersion)
	}

	if !exeExists(info.command) {
		return true, fmt.Sprintf("it launches a missing exe (%s), re-registering for %s", info.command, s.exePath)
	}
	return false, fmt.Sprintf("it launches another copy of the app (%s), leaving it alone", info.command)
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
    <Version>%s</Version>
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
    <Priority>4</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>%s</Command>
      <WorkingDirectory>%s</WorkingDirectory>
    </Exec>
  </Actions>
</Task>`

	return fmt.Sprintf(xmlTemplate,
		taskVersion,
		xmlEscape(userID),
		xmlEscape(userID),
		xmlEscape(s.exePath),
		xmlEscape(workingDir),
	)
}

// Enable enables autostart via Task Scheduler
func (s *Scheduler) Enable() error {
	xmlContent := s.taskXML()

	// Not the user's %TEMP%: a non-elevated program could rewrite the file
	// between this write and schtasks reading it and so register a task of
	// its own that runs elevated at every logon. Files an administrator
	// creates in %SystemRoot%\Temp are not writable by users.
	xmlFile, err := os.CreateTemp(filepath.Join(paths.SystemFolders().Windows, "Temp"), "singbox-task-*.xml")
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
	cmd := newHiddenCommand(paths.System32("schtasks.exe"), "/Create", "/TN", config.AppName, "/XML", xmlPath, "/F")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to create scheduled task: %w\nOutput: %s", err, string(output))
	}

	log.Printf("Autostart enabled via Task Scheduler: %s", string(output))
	return nil
}

// Disable disables autostart
func (s *Scheduler) Disable() error {
	cmd := newHiddenCommand(paths.System32("schtasks.exe"), "/Delete", "/TN", config.AppName, "/F")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to delete scheduled task: %w\nOutput: %s", err, string(output))
	}

	log.Printf("Autostart disabled: %s", string(output))
	return nil
}
