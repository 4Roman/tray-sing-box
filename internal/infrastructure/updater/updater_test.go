//go:build windows

package updater

import (
	"archive/zip"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tray-sing-box/internal/config"
	"tray-sing-box/internal/domain"
)

func TestExtractFromZip(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "release.zip")

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	entry, _ := w.Create("sing-box-1.0.0-windows-amd64/sing-box.exe")
	entry.Write([]byte("binary-bytes"))
	w.Close()
	f.Close()

	dest := filepath.Join(dir, "staged.exe")
	if err := extractFromZip(zipPath, "sing-box.exe", dest); err != nil {
		t.Fatalf("extractFromZip: %v", err)
	}
	data, _ := os.ReadFile(dest)
	if string(data) != "binary-bytes" {
		t.Fatalf("extracted content wrong: %q", data)
	}

	if err := extractFromZip(zipPath, "missing.exe", dest); err == nil {
		t.Fatal("missing entry must be an error")
	}
}

func TestInstallSwapsWithBackup(t *testing.T) {
	exeDir := t.TempDir()
	target := filepath.Join(exeDir, "sing-box.exe")
	if err := os.WriteFile(target, []byte("old-binary"), 0755); err != nil {
		t.Fatal(err)
	}

	stagedDir := t.TempDir()
	staged := filepath.Join(stagedDir, "sing-box.exe")
	if err := os.WriteFile(staged, []byte("new-binary"), 0755); err != nil {
		t.Fatal(err)
	}

	if err := New(exeDir, exeDir).Install(staged); err != nil {
		t.Fatalf("Install: %v", err)
	}

	data, _ := os.ReadFile(target)
	if string(data) != "new-binary" {
		t.Fatalf("binary not replaced: %q", data)
	}
	backup, _ := os.ReadFile(target + ".old")
	if string(backup) != "old-binary" {
		t.Fatalf("backup wrong: %q", backup)
	}
}

func TestInstallFreshWithoutPrevious(t *testing.T) {
	exeDir := t.TempDir()
	stagedDir := t.TempDir()
	staged := filepath.Join(stagedDir, "sing-box.exe")
	if err := os.WriteFile(staged, []byte("new-binary"), 0755); err != nil {
		t.Fatal(err)
	}

	if err := New(exeDir, exeDir).Install(staged); err != nil {
		t.Fatalf("Install: %v", err)
	}
	data, _ := os.ReadFile(filepath.Join(exeDir, "sing-box.exe"))
	if string(data) != "new-binary" {
		t.Fatalf("binary not installed: %q", data)
	}
}

// writeFiles creates name -> content in dir
func writeFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0755); err != nil {
			t.Fatal(err)
		}
	}
}

// checkFiles fails unless every name has the content ("" = must not exist)
func checkFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, want := range files {
		data, err := os.ReadFile(filepath.Join(dir, name))
		switch {
		case want == "" && !errors.Is(err, fs.ErrNotExist):
			t.Errorf("%s must not exist (content %q, err %v)", name, data, err)
		case want != "" && string(data) != want:
			t.Errorf("%s = %q (err %v), want %q", name, data, err, want)
		}
	}
}

// stage creates a staging directory in exeDir the way Download does
func stage(t *testing.T, exeDir string, files map[string]string) string {
	t.Helper()
	dir, err := os.MkdirTemp(exeDir, stagingPrefix)
	if err != nil {
		t.Fatal(err)
	}
	writeFiles(t, dir, files)
	return filepath.Join(dir, config.SingBoxExe)
}

// A new version that does not start is rolled back: the previous binary and
// the library it replaced come back from .old, the library the release
// added goes
func TestRollbackRestoresThePreviousVersion(t *testing.T) {
	exeDir := t.TempDir()
	writeFiles(t, exeDir, map[string]string{"sing-box.exe": "old-binary", "libcronet.dll": "old-lib"})
	staged := stage(t, exeDir, map[string]string{
		"sing-box.exe": "new-binary", "libcronet.dll": "new-lib", "libnew.dll": "added-lib",
	})
	u := New(exeDir, exeDir)

	if err := u.Install(staged); err != nil {
		t.Fatalf("Install: %v", err)
	}
	checkFiles(t, exeDir, map[string]string{
		"sing-box.exe": "new-binary", "sing-box.exe.old": "old-binary",
		"libcronet.dll": "new-lib", "libcronet.dll.old": "old-lib", "libnew.dll": "added-lib",
	})
	if _, err := os.Stat(filepath.Dir(staged)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("staging dir left behind: %v", err)
	}

	if err := u.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	checkFiles(t, exeDir, map[string]string{
		"sing-box.exe": "old-binary", "sing-box.exe.old": "",
		"libcronet.dll": "old-lib", "libcronet.dll.old": "", "libnew.dll": "",
	})

	// One Install, one Rollback: a second one has nothing to go back to
	if err := u.Rollback(); err == nil {
		t.Fatal("a second Rollback succeeded")
	}
}

// A stale .old of a library the release adds is no backup of this install:
// the rollback removes the added library and leaves that file alone
func TestRollbackDoesNotResurrectAStaleBackup(t *testing.T) {
	exeDir := t.TempDir()
	writeFiles(t, exeDir, map[string]string{"sing-box.exe": "old-binary", "libnew.dll.old": "ancient-lib"})
	staged := stage(t, exeDir, map[string]string{"sing-box.exe": "new-binary", "libnew.dll": "added-lib"})
	u := New(exeDir, exeDir)

	if err := u.Install(staged); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if err := u.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	checkFiles(t, exeDir, map[string]string{
		"sing-box.exe": "old-binary", "libnew.dll": "", "libnew.dll.old": "ancient-lib",
	})
}

// Without a previous binary there is nothing to go back to: an error, and
// the installed binary stays — a leftover .old of some earlier update (its
// binary deleted since) is not brought back
func TestRollbackWithoutPreviousBinary(t *testing.T) {
	exeDir := t.TempDir()
	writeFiles(t, exeDir, map[string]string{"sing-box.exe.old": "ancient-binary"})
	staged := stage(t, exeDir, map[string]string{"sing-box.exe": "new-binary"})
	u := New(exeDir, exeDir)

	if err := u.Rollback(); err == nil {
		t.Fatal("Rollback without any Install succeeded")
	}
	if err := u.Install(staged); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if err := u.Rollback(); err == nil {
		t.Fatal("Rollback of a fresh install succeeded")
	}
	checkFiles(t, exeDir, map[string]string{"sing-box.exe": "new-binary", "sing-box.exe.old": "ancient-binary"})
}

// A refused update discards its download: the staging directory in Bin, and
// nothing that is not one
func TestDiscardRemovesOnlyAStagingDir(t *testing.T) {
	exeDir := t.TempDir()
	writeFiles(t, exeDir, map[string]string{"sing-box.exe": "old-binary"})
	u := New(exeDir, exeDir)

	staged := stage(t, exeDir, map[string]string{"sing-box.exe": "new-binary"})
	if err := u.Discard(staged); err != nil {
		t.Fatalf("Discard: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(staged)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("staging dir not removed: %v", err)
	}

	// The installed binary (its dir is Bin itself), another folder in Bin
	// and a staging-named dir outside Bin are not a download of this updater
	other := filepath.Join(exeDir, "other")
	if err := os.Mkdir(other, 0755); err != nil {
		t.Fatal(err)
	}
	writeFiles(t, other, map[string]string{"sing-box.exe": "kept"})
	elsewhere := stage(t, t.TempDir(), map[string]string{"sing-box.exe": "foreign"})
	for _, path := range []string{filepath.Join(exeDir, "sing-box.exe"), filepath.Join(other, "sing-box.exe"), elsewhere} {
		if err := u.Discard(path); err == nil {
			t.Errorf("Discard(%s) accepted", path)
		}
	}
	checkFiles(t, exeDir, map[string]string{"sing-box.exe": "old-binary"})
	checkFiles(t, other, map[string]string{"sing-box.exe": "kept"})
	checkFiles(t, filepath.Dir(elsewhere), map[string]string{"sing-box.exe": "foreign"})
}

// Nothing to check without a config.json (a fresh install downloads its
// first sing-box); a missing binary is ErrSingBoxMissing
func TestCheckConfigWithoutConfigOrBinary(t *testing.T) {
	binDir, dataDir := t.TempDir(), t.TempDir()
	u := New(binDir, dataDir)

	for _, binary := range []string{"", filepath.Join(binDir, "missing.exe")} {
		if err := u.CheckConfig(binary); err != nil {
			t.Fatalf("CheckConfig(%q) without a config = %v", binary, err)
		}
	}

	writeFiles(t, dataDir, map[string]string{config.SingBoxConfig: `{}`})
	for _, binary := range []string{"", filepath.Join(binDir, "missing.exe")} {
		if err := u.CheckConfig(binary); !errors.Is(err, domain.ErrSingBoxMissing) {
			t.Fatalf("CheckConfig(%q) without the binary = %v, want ErrSingBoxMissing", binary, err)
		}
	}
}

// Against the real sing-box (SINGBOX_REAL_DIR, only `check` is run): the
// config in the data dir is accepted or refused with sing-box's own message.
// The configs live in a temp data dir, never in a real installation.
func TestCheckConfigRealBinary(t *testing.T) {
	realDir := os.Getenv("SINGBOX_REAL_DIR")
	if realDir == "" {
		t.Skip("SINGBOX_REAL_DIR not set")
	}
	binary := filepath.Join(realDir, config.SingBoxExe)
	if _, err := os.Stat(binary); err != nil {
		t.Skipf("sing-box.exe not found in %s", realDir)
	}
	dataDir := t.TempDir()
	// The real dir as Bin: CheckConfig("") is the installed binary
	u := New(realDir, dataDir)

	writeFiles(t, dataDir, map[string]string{config.SingBoxConfig: `{"outbounds": [{"type": "direct", "tag": "direct"}]}`})
	for _, b := range []string{"", binary} {
		if err := u.CheckConfig(b); err != nil {
			t.Fatalf("CheckConfig(%q) refused a valid config: %v", b, err)
		}
	}

	writeFiles(t, dataDir, map[string]string{config.SingBoxConfig: `{"outbounds": [{"type": "no-such-type", "tag": "x"}]}`})
	err := u.CheckConfig(binary)
	if err == nil {
		t.Fatal("an invalid config was accepted")
	}
	if !strings.Contains(err.Error(), "no-such-type") || strings.Contains(err.Error(), "\x1b[") {
		t.Fatalf("error = %q, want sing-box's message without colour codes", err)
	}
	t.Logf("sing-box check refused: %v", err)
}

// End-to-end against real GitHub and the real local install: checks the
// current version, queries the latest release and downloads + verifies the
// staged binary. Never touches the real installation. Enabled by
// SINGBOX_REAL_DIR (and network availability).
func TestEndToEndDownload(t *testing.T) {
	realDir := os.Getenv("SINGBOX_REAL_DIR")
	if realDir == "" {
		t.Skip("SINGBOX_REAL_DIR not set")
	}
	if testing.Short() {
		t.Skip("short mode")
	}

	// A copy: Download stages next to the binary, and the real installation
	// must stay untouched
	tmp := t.TempDir()
	data, err := os.ReadFile(filepath.Join(realDir, config.SingBoxExe))
	if err != nil {
		t.Fatalf("read the real sing-box.exe: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmp, config.SingBoxExe), data, 0755); err != nil {
		t.Fatal(err)
	}
	u := New(tmp, tmp)

	current, err := u.CurrentVersion()
	if err != nil {
		t.Fatalf("CurrentVersion: %v", err)
	}
	t.Logf("current version: %q", current)

	latest, err := u.LatestRelease()
	if err != nil {
		t.Skipf("GitHub unreachable: %v", err)
	}
	t.Logf("latest release: %q (%s)", latest.Version, latest.AssetURL)
	if latest.Version == "" || latest.AssetURL == "" {
		t.Fatalf("incomplete release info: %+v", latest)
	}

	cmp := domain.CompareVersions(current, latest.Version)
	t.Logf("compare(current, latest) = %d", cmp)

	staged, err := u.Download(latest)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	defer os.RemoveAll(filepath.Dir(staged))

	version, err := binaryVersion(staged, filepath.Dir(staged))
	if err != nil {
		t.Fatalf("staged binary does not run: %v", err)
	}
	if version != latest.Version {
		t.Fatalf("staged version %q != release %q", version, latest.Version)
	}
	t.Logf("staged binary verified: %s", version)
}
