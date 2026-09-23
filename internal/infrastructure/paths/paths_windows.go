//go:build windows

package paths

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// SystemFolders returns the machine folders from the known-folder API and
// the system directory calls — never from environment variables, which the
// user can override for the elevated process (see the package comment)
func SystemFolders() Folders {
	var f Folders
	f.ProgramFiles = knownFolder(windows.FOLDERID_ProgramFiles)
	f.ProgramFilesX86 = knownFolder(windows.FOLDERID_ProgramFilesX86)
	// Not FOLDERID_ProgramData: the known-folder API expands the stored
	// "%SystemDrive%\ProgramData" with the process's own %SystemDrive% —
	// which a user variable can override for the elevated app
	f.ProgramData = programDataFolder()
	f.Windows, _ = windows.GetSystemWindowsDirectory()
	f.System32, _ = windows.GetSystemDirectory()
	return f
}

// programDataFolder reads the machine's ProgramData location from the
// profile list (HKLM) unexpanded and expands only %SystemDrive%, with the
// drive of the Windows directory (which no environment variable affects).
// "" when the value is anything else.
func programDataFolder() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, err := k.GetStringValue("ProgramData") // REG_EXPAND_SZ: returned unexpanded
	if err != nil {
		return ""
	}
	const token = "%systemdrive%"
	if strings.HasPrefix(strings.ToLower(v), token) {
		win, err := windows.GetSystemWindowsDirectory()
		if err != nil {
			return ""
		}
		v = filepath.VolumeName(win) + v[len(token):]
	}
	if strings.Contains(v, "%") || !filepath.IsAbs(v) {
		return ""
	}
	return filepath.Clean(v)
}

func knownFolder(id *windows.KNOWNFOLDERID) string {
	path, err := windows.KnownFolderPath(id, 0)
	if err != nil {
		return ""
	}
	return path
}

// System32 returns the full path of a tool in the system directory
// (schtasks.exe, rundll32.exe): the elevated app never lets PATH pick them
func System32(name string) string {
	return filepath.Join(SystemFolders().System32, name)
}

// dataDirSDDL: owner Administrators; a protected DACL (nothing inherited
// from %ProgramData%, where every user may create files) granting SYSTEM and
// Administrators full control and nobody else anything — the directory holds
// credentials (config.json with server keys, subscription URLs with access
// tokens), and every reader of it runs elevated. OWNER RIGHTS gets
// READ_CONTROL only: under a non-default "object creator" owner policy the
// files the elevated app creates are owned by the user's SID, and without
// that ACE the owner — also the user's non-elevated programs — would have
// the implicit right to rewrite their DACL (and RX would let them read).
// Everything below inherits it.
const dataDirSDDL = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x20000;;;OW)"

// extraTrustedSID is for the tests only: a non-elevated test process can
// neither make Administrators the owner of what it creates nor pass the
// checks below with its own SID
var extraTrustedSID *windows.SID

// trustedInstallerSID owns most of Program Files and Windows
var trustedInstallerSID, _ = windows.StringToSid("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")

// adminSID: SYSTEM, Administrators, TrustedInstaller
func adminSID(sid *windows.SID) bool {
	if sid == nil {
		return false
	}
	if sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return true
	}
	if trustedInstallerSID != nil && sid.Equals(trustedInstallerSID) {
		return true
	}
	return extraTrustedSID != nil && sid.Equals(extraTrustedSID)
}

func secureDir(dir string) (warning string, err error) {
	return secureDirSD(dir, dataDirSDDL)
}

// secureDirSD is secureDir with the descriptor as a parameter: the tests use
// one without the Administrators owner, which only an elevated process may
// set. The directory is either created here, in one step, with the final
// descriptor, or it must already be a real directory owned by an
// administrator with a protected DACL — checked on an open handle to the
// object itself (not the path: no reparse point is followed, and what was
// checked is what gets used). Anything else is moved aside and the creation
// retried; a user who keeps re-creating it gets an error, not a directory.
func secureDirSD(dir, sddl string) (warning string, err error) {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return "", err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return "", err
	}
	if dir == "" || !filepath.IsAbs(dir) {
		return "", fmt.Errorf("the data directory is unknown (ProgramData could not be determined)")
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0755); err != nil {
		return "", err
	}
	// The parent (ProgramData) must be the machine's: a user who could
	// rename or re-permission it could swap the data directory afterwards
	if err := checkParentDir(filepath.Dir(dir)); err != nil {
		return "", err
	}
	name, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return "", err
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}

	var moved []string
	defer func() {
		if len(moved) > 0 {
			warning = fmt.Sprintf("%s was not trusted: moved aside (%s), starting with an empty data directory", dir, strings.Join(moved, "; "))
		}
	}()
	for attempt := 0; attempt < 3; attempt++ {
		err := windows.CreateDirectory(name, sa)
		if err == nil {
			return "", nil
		}
		if !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return "", fmt.Errorf("create %s: %w", dir, err)
		}
		trusted, reason := inspectDataDir(dir, dacl)
		if trusted {
			return "", nil
		}
		aside := fmt.Sprintf("%s.untrusted-%d-%d", dir, time.Now().Unix(), attempt)
		if err := os.Rename(dir, aside); err != nil {
			return "", fmt.Errorf("%s is not trusted (%s) and could not be moved aside: %w", dir, reason, err)
		}
		moved = append(moved, fmt.Sprintf("%s: %s", filepath.Base(aside), reason))
	}
	return "", fmt.Errorf("%s keeps being re-created by someone else", dir)
}

// inspectDataDir: an existing data directory is trusted when it is a real
// directory (not a junction or symlink), owned by an administrator, with a
// protected DACL — then no one else could ever have created anything in it.
// A DACL that still grants something to non-administrators (an older build
// let Users read) is replaced, on the same handle.
func inspectDataDir(dir string, want *windows.ACL) (bool, string) {
	h, err := openNoFollow(dir, windows.READ_CONTROL|windows.WRITE_DAC)
	if err != nil {
		return false, "cannot be opened: " + err.Error()
	}
	defer windows.CloseHandle(h)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return false, err.Error()
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return false, "a junction or symbolic link"
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return false, "a file, not a directory"
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, "security descriptor unreadable: " + err.Error()
	}
	owner, _, err := sd.Owner()
	if err != nil || !adminSID(owner) {
		return false, "not owned by an administrator"
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return false, "created without the protected DACL (anyone could create files in it)"
	}
	if who, err := foreignAccess(sd, anyAccess); err != nil || who != "" {
		if err := windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, want, nil); err != nil {
			return false, "DACL could not be tightened: " + err.Error()
		}
	}
	return true, ""
}

// checkParentDir: a real directory owned by an administrator in which no one
// else may delete, rename or re-permission entries (creating new ones is
// fine — that is what %ProgramData% allows every user)
func checkParentDir(dir string) error {
	h, err := openNoFollow(dir, windows.READ_CONTROL)
	if err != nil {
		return fmt.Errorf("%s: %w", dir, err)
	}
	defer windows.CloseHandle(h)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return fmt.Errorf("%s: %w", dir, err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return fmt.Errorf("%s is not a real directory", dir)
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("%s: %w", dir, err)
	}
	owner, _, err := sd.Owner()
	if err != nil || !adminSID(owner) {
		return fmt.Errorf("%s is not owned by an administrator", dir)
	}
	who, err := foreignAccess(sd, windows.DELETE|windows.WRITE_DAC|windows.WRITE_OWNER|fileDeleteChild|windows.GENERIC_ALL)
	if err != nil {
		return fmt.Errorf("%s: %w", dir, err)
	}
	if who != "" {
		return fmt.Errorf("%s lets %s delete or re-permission its entries", dir, who)
	}
	return nil
}

// openNoFollow opens a file or directory itself, never what a reparse point
// leads to
func openNoFollow(path string, access uint32) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return windows.CreateFile(name, access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
}

const (
	accessAllowedCallbackACEType = 9
	anyAccess                    = ^windows.ACCESS_MASK(0)
	// Rights that let someone change what a file contains or what gets there
	writeAccess = windows.ACCESS_MASK(windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA |
		windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_WRITE | windows.GENERIC_ALL)
	// ...and for a directory, removing or replacing its entries
	dirWriteAccess  = writeAccess | fileDeleteChild
	fileDeleteChild = 0x40 // FILE_DELETE_CHILD
)

// foreignAccess returns the first non-administrator trustee that an
// effective (not inherit-only) allow ACE grants any of mask; OWNER RIGHTS
// with nothing but READ_CONTROL is not counted (it only restricts the
// owner). A missing DACL grants everyone everything.
func foreignAccess(sd *windows.SECURITY_DESCRIPTOR, mask windows.ACCESS_MASK) (string, error) {
	dacl, _, err := sd.DACL()
	if err != nil {
		return "", err
	}
	if dacl == nil {
		return "everyone (no DACL)", nil
	}
	ownerRights, _ := windows.StringToSid("S-1-3-4")
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return "", err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE && ace.Header.AceType != accessAllowedCallbackACEType {
			continue
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Mask&mask == 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if adminSID(sid) {
			continue
		}
		// OWNER RIGHTS limited to READ_CONTROL is what the data directory
		// itself uses; anything more is somebody's access
		if ownerRights != nil && sid.Equals(ownerRights) && (ace.Mask&^windows.READ_CONTROL)&mask == 0 {
			continue
		}
		return sid.String(), nil
	}
	return "", nil
}

// CheckAdminOnlyFile verifies that only administrators could have put the
// executable at path there and could change it: it lies under Program Files,
// and it and every directory up to that root are real (no reparse point),
// owned by SYSTEM, Administrators or TrustedInstaller, and give no one else
// the right to write, delete or re-permission them. The elevated app runs a
// third-party tool (docker) only after this check — a folder tree is not
// admin-only just by its name (installers loosen ACLs, and %WINDIR% has
// user-writable subfolders).
func CheckAdminOnlyFile(path string) error {
	f := SystemFolders()
	path = filepath.Clean(path)
	root := ""
	for _, r := range []string{f.ProgramFiles, f.ProgramFilesX86} {
		if r != "" && under(path, r) {
			root = filepath.Clean(r)
			break
		}
	}
	if root == "" {
		return fmt.Errorf("%s is not under Program Files", path)
	}
	isDir := false
	for cur := path; ; {
		if err := checkAdminOnlyEntry(cur, isDir); err != nil {
			return err
		}
		if strings.EqualFold(cur, root) {
			return nil
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return fmt.Errorf("%s: walked past %s", path, root)
		}
		cur, isDir = parent, true
	}
}

func checkAdminOnlyEntry(path string, isDir bool) error {
	h, err := openNoFollow(path, windows.READ_CONTROL)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	defer windows.CloseHandle(h)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%s is a junction or symbolic link", path)
	}
	if isDir != (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) {
		return fmt.Errorf("%s: unexpected file type", path)
	}
	if !isDir && info.NumberOfLinks > 1 {
		return fmt.Errorf("%s has several hard links", path)
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if !adminSID(owner) {
		return fmt.Errorf("%s is owned by %s, not by an administrator", path, owner.String())
	}
	mask := writeAccess
	if isDir {
		mask = dirWriteAccess
	}
	who, err := foreignAccess(sd, mask)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if who != "" {
		return fmt.Errorf("%s is writable by %s", path, who)
	}
	return nil
}

// OpenTrustedFile opens a file for reading only when an administrator
// (SYSTEM, Administrators, TrustedInstaller) owns it and it is neither a
// link nor one of several hard links — checked on the opened handle, which
// is then what is read. For files in folders where every user may create
// files, such as %WINDIR%\System32\Tasks: a planted file is owned by the
// user who planted it.
func OpenTrustedFile(path string) (*os.File, error) {
	h, err := openNoFollow(path, windows.GENERIC_READ|windows.READ_CONTROL)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	fail := func(err error) (*os.File, error) {
		windows.CloseHandle(h)
		return nil, err
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return fail(err)
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return fail(fmt.Errorf("%s is not a regular file", path))
	}
	if info.NumberOfLinks > 1 {
		return fail(fmt.Errorf("%s has several hard links", path))
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fail(err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fail(err)
	}
	if !adminSID(owner) {
		return fail(fmt.Errorf("%s is owned by %s, not by an administrator", path, owner.String()))
	}
	return os.NewFile(uintptr(h), path), nil
}
