//go:build windows

package paths

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The folders come from the known-folder API, not from the environment the
// user controls
func TestSystemFoldersIgnoreTheEnvironment(t *testing.T) {
	fake := t.TempDir()
	t.Setenv("ProgramData", fake)
	t.Setenv("ProgramFiles", fake)
	t.Setenv("SystemRoot", fake)
	t.Setenv("SystemDrive", fake)
	t.Setenv("ALLUSERSPROFILE", fake)
	f := SystemFolders()
	for name, got := range map[string]string{"ProgramData": f.ProgramData, "ProgramFiles": f.ProgramFiles, "Windows": f.Windows, "System32": f.System32} {
		if got == "" || strings.EqualFold(got, fake) || Under(got, fake) {
			t.Errorf("%s = %q, taken from the environment (%s)", name, got, fake)
		}
	}
}

// An executable counts as admin-only only under Program Files, with owner
// and DACL of the file and every folder up to the root checked
func TestCheckAdminOnlyFile(t *testing.T) {
	f := SystemFolders()
	matches, _ := filepath.Glob(filepath.Join(f.ProgramFiles, "*", "*.exe"))
	checked := 0
	for _, exe := range matches {
		if err := CheckAdminOnlyFile(exe); err == nil {
			checked++
			break
		}
	}
	if len(matches) > 0 && checked == 0 {
		t.Errorf("no executable directly in a Program Files subfolder passed (tried %d, e.g. %s: %v)", len(matches), matches[0], CheckAdminOnlyFile(matches[0]))
	}
	// Outside Program Files — the user's temp dir, or %WINDIR% (it has
	// user-writable subfolders)
	tmp := filepath.Join(t.TempDir(), "docker.exe")
	if err := os.WriteFile(tmp, []byte("x"), 0755); err != nil {
		t.Fatal(err)
	}
	if CheckAdminOnlyFile(tmp) == nil {
		t.Error("a file in the user's temp directory passed")
	}
	if CheckAdminOnlyFile(System32("schtasks.exe")) == nil {
		t.Error("a file outside Program Files passed")
	}
}

// A file a user owns is refused; an administrator's is opened
func TestOpenTrustedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "SingBoxTray")
	if err := os.WriteFile(path, []byte("<Task/>"), 0644); err != nil {
		t.Fatal(err)
	}
	if !elevated() {
		if f, err := OpenTrustedFile(path); err == nil {
			f.Close()
			t.Fatal("a file owned by the (non-elevated) user was trusted")
		}
	}
	trustMe(t)
	f, err := OpenTrustedFile(path)
	if err != nil {
		t.Fatalf("OpenTrustedFile: %v", err)
	}
	f.Close()
	// A second hard link: refused whoever owns it
	if err := os.Link(path, path+".link"); err == nil {
		if f, err := OpenTrustedFile(path); err == nil {
			f.Close()
			t.Fatal("a file with two hard links was trusted")
		}
	}
}

// trustMe lets the test process's own SID pass the administrator checks
func trustMe(t *testing.T) {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	extraTrustedSID = user.User.Sid
	t.Cleanup(func() { extraTrustedSID = nil })
}

func elevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// Ensure of an installed layout: the directory ends up owned by
// Administrators with a protected DACL, and a directory a user created
// beforehand is moved aside. Needs elevation (setting the owner).
func TestEnsureLocksTheDataDirectory(t *testing.T) {
	if !elevated() {
		t.Skip("needs an elevated test process")
	}
	root := adminOwnedDir(t)
	data := filepath.Join(root, "SingBoxTray")
	l := Layout{Bin: t.TempDir(), Data: data}
	if _, err := l.Ensure(); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if ok, reason := inspectDataDir(data, nil); !ok {
		t.Fatalf("fresh data dir not trusted: %s", reason)
	}
	sd, err := windows.GetNamedSecurityInfo(data, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sd.String(), "D:P") {
		t.Fatalf("DACL not protected: %s", sd.String())
	}
	// Idempotent on a trusted directory, files kept
	if err := os.WriteFile(filepath.Join(data, "config.json"), []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Ensure(); err != nil {
		t.Fatalf("second Ensure: %v", err)
	}
	if _, err := os.Stat(filepath.Join(data, "config.json")); err != nil {
		t.Fatalf("config.json lost on a second Ensure: %v", err)
	}
}

// A link (junction or symlink) planted where the data directory should be
// is not followed
func TestEnsureMovesALinkAside(t *testing.T) {
	if !elevated() {
		t.Skip("needs an elevated test process")
	}
	root := adminOwnedDir(t)
	target := t.TempDir()
	data := filepath.Join(root, "SingBoxTray")
	if err := os.Symlink(target, data); err != nil {
		t.Skipf("cannot create a link here: %v", err)
	}
	l := Layout{Bin: t.TempDir(), Data: data}
	if w, err := l.Ensure(); err != nil || w == "" {
		t.Fatalf("Ensure = %q, %v (want a warning about the link)", w, err)
	}
	attrs, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(data))
	if err != nil {
		t.Fatal(err)
	}
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		t.Fatal("the link is still in place")
	}
	matches, _ := filepath.Glob(data + ".untrusted-*")
	if len(matches) != 1 {
		t.Fatalf("link not moved aside: %v", matches)
	}
}

// Without elevation: the directory is created in one step with a protected
// DACL (nothing inherited from the parent, where users could create files),
// a second call accepts it, and nothing inside is readable by Users
func TestSecureDirCreatesAProtectedDirectory(t *testing.T) {
	trustMe(t)
	me := extraTrustedSID.String()
	sddl := "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + me + ")"
	dir := filepath.Join(t.TempDir(), "SingBoxTray")
	if w, err := secureDirSD(dir, sddl); err != nil || w != "" {
		t.Fatalf("secureDirSD = %q, %v", w, err)
	}
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatal(err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("DACL not protected: %s", sd.String())
	}
	if strings.Contains(sd.String(), ";;;BU)") {
		t.Fatalf("Users have access: %s", sd.String())
	}
	f := filepath.Join(dir, "config.json")
	if err := os.WriteFile(f, []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	// Existing, ours, protected: accepted as is, content kept
	if w, err := secureDirSD(dir, sddl); err != nil || w != "" {
		t.Fatalf("second secureDirSD = %q, %v", w, err)
	}
	if _, err := os.Stat(f); err != nil {
		t.Fatalf("config.json lost: %v", err)
	}
}

// An existing directory without the protected DACL (anyone could have put
// files into it) is moved aside and replaced
func TestSecureDirMovesALooseDirectoryAside(t *testing.T) {
	trustMe(t)
	me := extraTrustedSID.String()
	sddl := "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + me + ")"
	dir := filepath.Join(t.TempDir(), "SingBoxTray")
	if err := os.Mkdir(dir, 0755); err != nil { // inherits the temp dir's DACL
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte("planted"), 0644); err != nil {
		t.Fatal(err)
	}
	w, err := secureDirSD(dir, sddl)
	if err != nil || w == "" {
		t.Fatalf("secureDirSD = %q, %v (want a warning)", w, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "config.json")); !os.IsNotExist(err) {
		t.Fatalf("the planted config.json is still in the data directory: %v", err)
	}
	if matches, _ := filepath.Glob(dir + ".untrusted-*"); len(matches) != 1 {
		t.Fatalf("loose directory not moved aside: %v", matches)
	}
}

// A junction (any user can create one in a folder they may write) is never
// used as the data directory
func TestSecureDirMovesAJunctionAside(t *testing.T) {
	trustMe(t)
	me := extraTrustedSID.String()
	sddl := "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + me + ")"
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0755); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "SingBoxTray")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", dir, target).CombinedOutput(); err != nil {
		t.Skipf("mklink /J: %v %s", err, out)
	}
	if w, err := secureDirSD(dir, sddl); err != nil || w == "" {
		t.Fatalf("secureDirSD = %q, %v (want a warning)", w, err)
	}
	h, err := openNoFollow(dir, windows.READ_CONTROL)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		t.Fatal(err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		t.Fatal("the junction is still the data directory")
	}
}

func TestForeignAccess(t *testing.T) {
	cases := []struct {
		sddl string
		mask windows.ACCESS_MASK
		want string // "" = nobody else; otherwise a substring of the trustee
	}{
		{"D:(A;;FA;;;BU)", anyAccess, "S-1-5-32-545"},
		{"D:(A;OICIIO;GA;;;BU)", anyAccess, ""},        // inherit-only: not effective here
		{"D:(A;;0x20000;;;OW)", anyAccess, ""},         // OWNER RIGHTS limited to READ_CONTROL
		{"D:(A;;0x1200a9;;;OW)", anyAccess, "S-1-3-4"}, // ...but read access is access
		{"D:(A;;0x1200a9;;;OW)", writeAccess, ""},
		{"D:(A;;FA;;;OW)", writeAccess, "S-1-3-4"},
		{"D:(A;;0x40;;;BU)", dirWriteAccess, "S-1-5-32-545"}, // FILE_DELETE_CHILD
		{"D:(A;;0x40;;;BU)", writeAccess, ""},
		{"D:(A;;FA;;;SY)(A;;FA;;;BA)", anyAccess, ""},
		{"D:(D;;FA;;;BU)", anyAccess, ""}, // deny ACEs only restrict
		{"D:NO_ACCESS_CONTROL", anyAccess, "everyone"},
	}
	for _, c := range cases {
		sd, err := windows.SecurityDescriptorFromString(c.sddl)
		if err != nil {
			t.Fatalf("%s: %v", c.sddl, err)
		}
		got, err := foreignAccess(sd, c.mask)
		if err != nil {
			t.Fatalf("%s: %v", c.sddl, err)
		}
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("foreignAccess(%s, %#x) = %q, want %q", c.sddl, uint32(c.mask), got, c.want)
		}
	}
}

// checkAdminOnlyEntry on a file the test controls (its SID trusted)
func TestCheckAdminOnlyEntry(t *testing.T) {
	trustMe(t)
	me := extraTrustedSID.String()
	dir := t.TempDir()
	file := filepath.Join(dir, "tool.exe")
	if err := os.WriteFile(file, []byte("x"), 0755); err != nil {
		t.Fatal(err)
	}
	setDACL := func(sddl string) {
		t.Helper()
		sd, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			t.Fatal(err)
		}
		dacl, _, err := sd.DACL()
		if err != nil {
			t.Fatal(err)
		}
		if err := windows.SetNamedSecurityInfo(file, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
			t.Fatal(err)
		}
	}
	setDACL("D:P(A;;FA;;;" + me + ")(A;;FA;;;BA)(A;;0x1200a9;;;BU)")
	if err := checkAdminOnlyEntry(file, false); err != nil {
		t.Fatalf("clean file rejected: %v", err)
	}
	setDACL("D:P(A;;FA;;;" + me + ")(A;;FW;;;BU)")
	if err := checkAdminOnlyEntry(file, false); err == nil {
		t.Fatal("a file Users may write passed")
	}
	setDACL("D:P(A;;FA;;;" + me + ")")
	if err := checkAdminOnlyEntry(dir, false); err == nil {
		t.Fatal("a directory passed as a file")
	}
	if err := os.Link(file, file+".2"); err == nil {
		if err := checkAdminOnlyEntry(file, false); err == nil {
			t.Fatal("a file with two hard links passed")
		}
	}
}

// adminOwnedDir: a parent like %ProgramData% as checkParentDir wants it —
// owned by Administrators, nobody else may delete or re-permission entries
// (elevated tests only: setting the owner needs elevation)
func adminOwnedDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "machine")
	sd, err := windows.SecurityDescriptorFromString("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		t.Fatal(err)
	}
	name, _ := windows.UTF16PtrFromString(dir)
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	if err := windows.CreateDirectory(name, sa); err != nil {
		t.Fatalf("create %s: %v", dir, err)
	}
	return dir
}

// The real %ProgramData% passes the parent check; a user's folder does not
func TestCheckParentDir(t *testing.T) {
	if err := checkParentDir(SystemFolders().ProgramData); err != nil {
		t.Fatalf("the machine's ProgramData refused: %v", err)
	}
	if !elevated() {
		if err := checkParentDir(t.TempDir()); err == nil {
			t.Fatal("a folder the user owns passed")
		}
	}
}
