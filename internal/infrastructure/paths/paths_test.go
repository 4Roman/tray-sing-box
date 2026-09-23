package paths

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveLayouts(t *testing.T) {
	pf := `C:\Program Files`
	pf86 := `C:\Program Files (x86)`
	pd := `C:\ProgramData`
	none := func(string) bool { return false }

	cases := []struct {
		name     string
		exe      string
		exists   func(string) bool
		portable bool
		data     string
	}{
		{"historical folder", `C:\Users\user\soft\sing-box\tray-sing-box.exe`, none, true, `C:\Users\user\soft\sing-box`},
		{"dev build in the repo", `C:\repo\bin\tray-sing-box.exe`, none, true, `C:\repo\bin`},
		{"installed, fresh", `C:\Program Files\SingBoxTray\tray-sing-box.exe`, none, false, `C:\ProgramData\SingBoxTray`},
		{"installed, case differs", `c:\program files\SingBoxTray\tray-sing-box.exe`, none, false, `C:\ProgramData\SingBoxTray`},
		{"installed under x86", `C:\Program Files (x86)\SingBoxTray\tray-sing-box.exe`, none, false, `C:\ProgramData\SingBoxTray`},
		{"config next to an exe under Program Files stays portable", `C:\Program Files\SingBoxTray\tray-sing-box.exe`,
			func(p string) bool { return strings.EqualFold(p, `C:\Program Files\SingBoxTray\config.json`) }, true, `C:\Program Files\SingBoxTray`},
		{"sibling of Program Files is not inside it", `C:\Program Files Extra\tray-sing-box.exe`, none, true, `C:\Program Files Extra`},
	}
	for _, c := range cases {
		l := resolve(c.exe, pf, pf86, pd, c.exists)
		if l.Portable != c.portable || !strings.EqualFold(l.Data, c.data) || l.Bin != filepath.Dir(c.exe) {
			t.Errorf("%s: got %+v, want portable=%v data=%s", c.name, l, c.portable, c.data)
		}
	}
}

// Without the environment (odd shells, tests) there is no installed mode
func TestResolveWithoutEnvironmentIsPortable(t *testing.T) {
	l := resolve(`C:\Program Files\SingBoxTray\tray-sing-box.exe`, "", "", "", func(string) bool { return false })
	if !l.Portable {
		t.Fatalf("got %+v", l)
	}
}

func TestLayoutPaths(t *testing.T) {
	l := Layout{Bin: `C:\bin`, Data: `C:\data`}
	if l.SingBoxExe() != `C:\bin\sing-box.exe` || l.ConfigFile() != `C:\data\config.json` || l.Subscriptions() != `C:\data\subscriptions.json` {
		t.Fatalf("paths: %s %s %s", l.SingBoxExe(), l.ConfigFile(), l.Subscriptions())
	}
	if l.DPIParams() != `C:\data\dpi-params.txt` || l.IconFallbackDir() != `C:\bin\assets\icons` {
		t.Fatalf("paths: %s %s", l.DPIParams(), l.IconFallbackDir())
	}
}

func TestEnsureOfAPortableLayoutTouchesNothing(t *testing.T) {
	bin := t.TempDir()
	l := Layout{Bin: bin, Data: bin, Portable: true}
	if _, err := l.Ensure(); err != nil {
		t.Fatal(err)
	}
}

func TestUnder(t *testing.T) {
	cases := []struct {
		dir, root string
		want      bool
	}{
		{`C:\Program Files\SingBoxTray`, `C:\Program Files`, true},
		{`c:\program files\singboxtray\`, `C:\Program Files`, true},
		{`C:\Program Files`, `C:\Program Files`, true},
		{`C:\Program Files Extra\x`, `C:\Program Files`, false},
		{`C:\Users\x\AppData`, `C:\Program Files`, false},
		{`C:\anything`, ``, false},
	}
	for _, c := range cases {
		if got := Under(c.dir, c.root); got != c.want {
			t.Errorf("Under(%q, %q) = %v, want %v", c.dir, c.root, got, c.want)
		}
	}
}

// Installed under Program Files, but ProgramData unknown: not silently
// portable — the data directory is unknown and Ensure fails
func TestResolveInstalledWithoutProgramData(t *testing.T) {
	l := resolve(`C:\Program Files\SingBoxTray\tray-sing-box.exe`, `C:\Program Files`, "", "", func(string) bool { return false })
	if l.Portable || l.Data != "" {
		t.Fatalf("layout = %+v, want installed with an unknown data directory", l)
	}
	if _, err := l.Ensure(); err == nil {
		t.Fatal("Ensure must fail without a data directory")
	}
}
