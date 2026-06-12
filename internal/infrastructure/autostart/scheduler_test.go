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
