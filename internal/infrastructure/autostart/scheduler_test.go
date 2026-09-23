package autostart

import (
	"os"
	"strings"
	"testing"
)

func TestEncodeUTF16LE(t *testing.T) {
	got := encodeUTF16LE("A")
	want := []byte{0xFF, 0xFE, 0x41, 0x00}
	if len(got) != len(want) {
		t.Fatalf("length = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("byte %d = %#x, want %#x", i, got[i], want[i])
		}
	}
}

func TestXMLEscape(t *testing.T) {
	if got := xmlEscape(`C:\Tools & Apps\app.exe`); !strings.Contains(got, "&amp;") {
		t.Fatalf("ampersand not escaped: %q", got)
	}
}

func TestCurrentUserIDIsSID(t *testing.T) {
	id := currentUserID()
	if !strings.HasPrefix(id, "S-1-") {
		t.Logf("warning: fell back to name-based id: %q", id)
	}
	if id == "" || id == "\\" {
		t.Fatalf("empty user id: %q", id)
	}
}

// Task Scheduler's default priority 7 runs the app — and the sing-box child
// that inherits it — below normal (CPU, I/O and memory priority). 4..6 is the
// normal class; 3 and lower would be above normal.
func TestTaskXMLRunsAtNormalPriority(t *testing.T) {
	s := &Scheduler{exePath: `C:\Apps\tray-sing-box.exe`}
	if !strings.Contains(s.taskXML(), "<Priority>4</Priority>") {
		t.Fatal("task must be registered with <Priority>4</Priority>")
	}
}

// What the app registers must read back as its own, current-version task
func TestParseTaskXMLRoundTrip(t *testing.T) {
	s := &Scheduler{exePath: `C:\Tools & Apps\Прокси\tray-sing-box.exe`}

	info, err := parseTaskXML(decodeTaskFile(encodeUTF16LE(s.taskXML())))
	if err != nil {
		t.Fatalf("parseTaskXML: %v", err)
	}
	if info.command != s.exePath {
		t.Fatalf("command = %q, want %q", info.command, s.exePath)
	}
	if !info.enabled || info.version != taskVersion {
		t.Fatalf("info = %+v, want enabled with version %q", info, taskVersion)
	}
	if !s.ownsTask(info) {
		t.Fatal("task must be recognized as launching this exe")
	}
}

// A task registered by a build older than the versioned definition, as
// exported from a real machine: no Version, no Settings/Enabled (absent means
// enabled), no WorkingDirectory
const legacyTaskXML = `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Sing-Box VPN Tray Manager - Auto-start at login</Description>
    <URI>\SingBoxTray</URI>
  </RegistrationInfo>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-21-1-2-3-1001</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
  </Settings>
  <Triggers>
    <LogonTrigger>
      <Enabled>false</Enabled>
      <UserId>PC\user</UserId>
    </LogonTrigger>
  </Triggers>
  <Actions Context="Author">
    <Exec>
      <Command>"C:\Users\user\soft\sing-box\tray-sing-box.exe"</Command>
    </Exec>
  </Actions>
</Task>`

func TestParseLegacyTaskXML(t *testing.T) {
	info, err := parseTaskXML(legacyTaskXML)
	if err != nil {
		t.Fatalf("parseTaskXML: %v", err)
	}
	if info.version != "" {
		t.Fatalf("legacy task must have no version, got %q", info.version)
	}
	// The trigger's <Enabled>false</Enabled> must not be taken for the task's
	if !info.enabled {
		t.Fatal("a task without Settings/Enabled is enabled")
	}

	same := &Scheduler{exePath: `c:\users\USER\soft\sing-box\tray-sing-box.exe`}
	if !same.ownsTask(info) {
		t.Fatalf("quoted / differently cased path not matched: %q", info.command)
	}
	other := &Scheduler{exePath: `C:\repo\bin\tray-sing-box.exe`}
	if other.ownsTask(info) {
		t.Fatal("a task of another copy must not be taken for our own")
	}
}

func TestParseDisabledTaskXML(t *testing.T) {
	disabled := strings.Replace(legacyTaskXML, "<Settings>", "<Settings>\n    <Enabled>false</Enabled>", 1)
	info, err := parseTaskXML(disabled)
	if err != nil {
		t.Fatalf("parseTaskXML: %v", err)
	}
	if info.enabled {
		t.Fatal("Settings/Enabled=false not detected")
	}
}

// The start-time refresh must heal our own outdated task and adopt a task
// whose exe is gone, but never touch a disabled task or hijack a task that
// launches another existing copy (e.g. the installed app while a dev build
// from the repo is being run).
func TestNeedsRefreshDecisionMatrix(t *testing.T) {
	const self = `C:\Apps\SingBox\tray-sing-box.exe`
	const other = `C:\repo\bin\tray-sing-box.exe`
	s := &Scheduler{exePath: self}

	exists := func(string) bool { return true }
	missing := func(string) bool { return false }

	cases := []struct {
		name      string
		info      taskInfo
		exeExists func(string) bool
		want      bool
	}{
		{"own task, current version", taskInfo{command: self, enabled: true, version: taskVersion}, exists, false},
		{"own task of an older build (no version)", taskInfo{command: self, enabled: true}, exists, true},
		{"own task, other version", taskInfo{command: self, enabled: true, version: "1"}, exists, true},
		{"own outdated task, disabled by the user", taskInfo{command: self, enabled: false}, exists, false},
		{"another existing copy", taskInfo{command: other, enabled: true}, exists, false},
		{"another copy that no longer exists (folder moved)", taskInfo{command: other, enabled: true, version: taskVersion}, missing, true},
		{"missing exe but task disabled", taskInfo{command: other, enabled: false}, missing, false},
	}
	for _, c := range cases {
		if got, _ := s.needsRefresh(c.info, c.exeExists); got != c.want {
			t.Errorf("%s: needsRefresh = %v, want %v", c.name, got, c.want)
		}
	}
}

// The live legacy task from a real machine must heal once the new build is
// deployed to the same path, and must be left alone by any other copy
func TestLegacyTaskHealsOnlyForItsOwnExe(t *testing.T) {
	info, err := parseTaskXML(legacyTaskXML)
	if err != nil {
		t.Fatalf("parseTaskXML: %v", err)
	}
	exists := func(string) bool { return true }

	deployed := &Scheduler{exePath: `C:\Users\user\soft\sing-box\tray-sing-box.exe`}
	if refresh, _ := deployed.needsRefresh(info, exists); !refresh {
		t.Fatal("legacy task of this exe must be re-registered")
	}
	devBuild := &Scheduler{exePath: `C:\repo\bin\tray-sing-box.exe`}
	if refresh, _ := devBuild.needsRefresh(info, exists); refresh {
		t.Fatal("a dev build must not hijack the installed copy's autostart")
	}
}

// TestSchtasksAcceptsTaskXML registers a throwaway task with the real
// schtasks.exe to verify the generated XML (encoding, schema, user id) is
// accepted by the OS, then removes it.
func TestSchtasksAcceptsTaskXML(t *testing.T) {
	const testTask = "SingBoxTrayXMLTest"

	s, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	xmlFile, err := os.CreateTemp("", "singbox-task-test-*.xml")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	xmlPath := xmlFile.Name()
	defer os.Remove(xmlPath)

	taskXML := s.taskXML()
	if _, err := xmlFile.Write(encodeUTF16LE(taskXML)); err != nil {
		t.Fatalf("write XML: %v", err)
	}
	xmlFile.Close()

	create := newHiddenCommand("schtasks", "/Create", "/TN", testTask, "/XML", xmlPath, "/F")
	output, err := create.CombinedOutput()
	outStr := string(output)
	if err != nil && (strings.Contains(outStr, "Access is denied") || strings.Contains(outStr, "0x80070005")) {
		// Not elevated: HighestAvailable registration needs admin. Register
		// the same XML with LeastPrivilege instead — this still validates
		// what historically broke on Windows 11: encoding, schema and user id.
		t.Logf("not elevated, retrying with LeastPrivilege run level")
		downgraded := strings.Replace(taskXML, "<RunLevel>HighestAvailable</RunLevel>", "<RunLevel>LeastPrivilege</RunLevel>", 1)
		if err := os.WriteFile(xmlPath, encodeUTF16LE(downgraded), 0644); err != nil {
			t.Fatalf("rewrite XML: %v", err)
		}
		create = newHiddenCommand("schtasks", "/Create", "/TN", testTask, "/XML", xmlPath, "/F")
		output, err = create.CombinedOutput()
		outStr = string(output)
	}
	if err != nil {
		t.Fatalf("schtasks /Create rejected the XML: %v\nOutput: %s", err, outStr)
	}

	del := newHiddenCommand("schtasks", "/Delete", "/TN", testTask, "/F")
	if delOut, err := del.CombinedOutput(); err != nil {
		t.Errorf("cleanup failed, delete task %q manually: %v\n%s", testTask, err, delOut)
	}
}

// A takeover source must be an elevated task of this very user: the task
// name alone could have been registered by anyone
func TestTrustedPrincipal(t *testing.T) {
	me := currentUserSID()
	if me == nil {
		t.Fatal("no current user SID")
	}
	mine := taskInfo{userID: me.String(), runLevel: "HighestAvailable"}
	if !trustedPrincipal(mine, me) {
		t.Fatal("an elevated task of the current user must be trusted")
	}
	for name, info := range map[string]taskInfo{
		"least privilege": {userID: me.String(), runLevel: "LeastPrivilege"},
		"no run level":    {userID: me.String()},
		"other user":      {userID: "S-1-5-21-1-2-3-1001", runLevel: "HighestAvailable"},
		"garbage":         {userID: "no such account \\ at all", runLevel: "HighestAvailable"},
	} {
		if trustedPrincipal(info, me) {
			t.Errorf("%s: trusted", name)
		}
	}

	// The legacy definition's principal is parsed
	info, err := parseTaskXML(legacyTaskXML)
	if err != nil {
		t.Fatal(err)
	}
	if info.userID != "S-1-5-21-1-2-3-1001" || info.runLevel != "HighestAvailable" {
		t.Fatalf("principal not parsed: %q %q", info.userID, info.runLevel)
	}
}
