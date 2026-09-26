package subscription

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"tray-sing-box/internal/domain"
)

// The list is written into the data directory and renamed there: it carries
// the directory's inheritable permissions (in the installed layout
// administrators only), not those of wherever it was written first nor
// whatever the file it replaces was given
func TestStoreSaveKeepsTheDirectoryPermissions(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	me := user.User.Sid.String()
	setDACL := func(path, sddl string) {
		t.Helper()
		sd, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			t.Fatal(err)
		}
		dacl, _, err := sd.DACL()
		if err != nil {
			t.Fatal(err)
		}
		if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
			t.Fatal(err)
		}
	}

	dir := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	setDACL(dir, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;"+me+")")
	path := filepath.Join(dir, "subscriptions.json")
	if err := os.WriteFile(path, []byte("[]"), 0644); err != nil {
		t.Fatal(err)
	}
	setDACL(path, "D:P(A;;FA;;;WD)(A;;FA;;;"+me+")") // loosened: Everyone

	if err := NewStore(path).Save([]domain.Subscription{{URL: "https://p.example/a"}}); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	sddl := sd.String()
	if strings.Contains(sddl, ";;;WD)") || strings.Contains(sddl, ";;;BU)") || strings.Contains(sddl, ";;;AU)") {
		t.Fatalf("the saved list is open to others: %s", sddl)
	}
	// How SDDL names the current user: the SID, or the alias of a
	// well-known account (a CI runner's built-in Administrator is "LA")
	mine, err := windows.SecurityDescriptorFromString("D:(A;;FA;;;" + me + ")")
	if err != nil {
		t.Fatal(err)
	}
	s := mine.String()
	me = s[strings.LastIndex(s, ";")+1 : len(s)-1]
	for _, sid := range []string{"SY", "BA", me} {
		if !strings.Contains(sddl, "(A;ID;FA;;;"+sid+")") {
			t.Fatalf("the saved list does not carry the directory's permissions (%s): %s", sid, sddl)
		}
	}
}
