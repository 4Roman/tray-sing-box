//go:build windows

package updater

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"

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

	if err := New(exeDir).Install(staged); err != nil {
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

	if err := New(exeDir).Install(staged); err != nil {
		t.Fatalf("Install: %v", err)
	}
	data, _ := os.ReadFile(filepath.Join(exeDir, "sing-box.exe"))
	if string(data) != "new-binary" {
		t.Fatalf("binary not installed: %q", data)
	}
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

	u := New(realDir)

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

	version, err := binaryVersion(staged)
	if err != nil {
		t.Fatalf("staged binary does not run: %v", err)
	}
	if version != latest.Version {
		t.Fatalf("staged version %q != release %q", version, latest.Version)
	}
	t.Logf("staged binary verified: %s", version)
}
