//go:build windows

// Package updater downloads sing-box releases from the official GitHub
// repository (SagerNet/sing-box) and swaps the local binary safely.
package updater

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"tray-sing-box/internal/config"
	"tray-sing-box/internal/domain"
	"tray-sing-box/internal/infrastructure/nettrust"
	"tray-sing-box/internal/infrastructure/process"
)

const defaultAPIURL = "https://api.github.com/repos/SagerNet/sing-box/releases/latest"

// versionLine matches the first line of `sing-box version` output
var versionLine = regexp.MustCompile(`sing-box version (\S+)`)

// Updater implements domain.BinaryRepository against GitHub releases
type Updater struct {
	exeDir  string
	dataDir string // TEMP of the `sing-box version` runs (SingBoxEnv)
	apiURL  string
	client  *http.Client
}

// New creates an updater for the sing-box binary located in binDir (the
// app's Bin directory; the parameter keeps its historical name)
func New(exeDir, dataDir string) *Updater {
	return &Updater{
		exeDir:  exeDir,
		dataDir: dataDir,
		apiURL:  defaultAPIURL,
		client:  nettrust.Client(10 * time.Minute),
	}
}

// CurrentVersion reports the version of the installed sing-box binary.
// Returns "" without error when the binary is not installed yet.
func (u *Updater) CurrentVersion() (string, error) {
	path := filepath.Join(u.exeDir, config.SingBoxExe)
	if _, err := os.Stat(path); err != nil {
		return "", nil
	}
	return binaryVersion(path, u.dataDir)
}

// binaryVersion runs `<binary> version` and parses the version out;
// dataDir holds its TEMP (SingBoxEnv)
func binaryVersion(path, dataDir string) (string, error) {
	// HelperOutput: not the VPN process, see process.HelperOutput
	cmd := process.NewHiddenCommand(path, "version")
	cmd.Env = process.SingBoxEnv(filepath.Dir(path), dataDir)
	output, err := process.HelperOutput(cmd)
	if err != nil {
		return "", fmt.Errorf("failed to run %s version: %w", filepath.Base(path), err)
	}
	match := versionLine.FindSubmatch(output)
	if match == nil {
		return "", fmt.Errorf("unexpected version output: %q", strings.TrimSpace(string(output)))
	}
	return string(match[1]), nil
}

// githubRelease is the subset of the GitHub release API response we use
type githubRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

// LatestRelease queries GitHub for the latest stable sing-box release and
// picks the windows zip asset matching this machine's architecture.
func (u *Updater) LatestRelease() (domain.ReleaseInfo, error) {
	req, err := http.NewRequest(http.MethodGet, u.apiURL, nil)
	if err != nil {
		return domain.ReleaseInfo{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", config.AppName)

	resp, err := u.client.Do(req)
	if err != nil {
		return domain.ReleaseInfo{}, fmt.Errorf("GitHub API request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return domain.ReleaseInfo{}, fmt.Errorf("GitHub API returned status %s", resp.Status)
	}

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return domain.ReleaseInfo{}, fmt.Errorf("failed to parse GitHub response: %w", err)
	}

	version := strings.TrimPrefix(release.TagName, "v")
	if version == "" {
		return domain.ReleaseInfo{}, fmt.Errorf("GitHub response has no release tag")
	}

	wantAsset := fmt.Sprintf("sing-box-%s-windows-%s.zip", version, runtime.GOARCH)
	for _, asset := range release.Assets {
		if asset.Name == wantAsset {
			return domain.ReleaseInfo{Version: version, AssetURL: asset.BrowserDownloadURL}, nil
		}
	}
	return domain.ReleaseInfo{}, fmt.Errorf("release %s has no asset %q", release.TagName, wantAsset)
}

// Download fetches the release zip, extracts sing-box.exe into a temp
// directory and verifies the staged binary actually runs and reports the
// expected version.
func (u *Updater) Download(release domain.ReleaseInfo) (stagedPath string, err error) {
	if release.AssetURL == "" {
		return "", fmt.Errorf("release has no download URL")
	}

	req, err := http.NewRequest(http.MethodGet, release.AssetURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", config.AppName)

	resp, err := u.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download returned status %s", resp.Status)
	}

	// Staged next to the binary it replaces, not in the user's %TEMP%: the
	// elevated app runs the staged exe (verification) and copies it into
	// Bin, and a non-elevated program could swap a file in %TEMP% in
	// between. In the installed layout Bin is admin-only; a portable Bin is
	// the user's folder anyway.
	// Leftovers of an update that never got to Install (sing-box could not
	// be stopped) — updates are serialized by the app's opMu
	if stale, _ := filepath.Glob(filepath.Join(u.exeDir, stagingPrefix+"*")); len(stale) > 0 {
		for _, dir := range stale {
			os.RemoveAll(dir)
		}
	}
	stagedDir, err := os.MkdirTemp(u.exeDir, stagingPrefix)
	if err != nil {
		return "", err
	}
	defer func() {
		if stagedPath == "" {
			os.RemoveAll(stagedDir)
		}
	}()

	zipFile, err := os.CreateTemp(stagedDir, "download-*.zip")
	if err != nil {
		return "", err
	}
	zipPath := zipFile.Name()
	defer os.Remove(zipPath)

	if _, err := io.Copy(zipFile, resp.Body); err != nil {
		zipFile.Close()
		return "", fmt.Errorf("download interrupted: %w", err)
	}
	if err := zipFile.Close(); err != nil {
		return "", err
	}

	staged := filepath.Join(stagedDir, config.SingBoxExe)
	if err := extractFromZip(zipPath, config.SingBoxExe, staged); err != nil {
		return "", err
	}
	// The DLLs next to the binary in the release (libcronet.dll for the naive
	// outbound): installed together, so sing-box finds them in its own folder
	// and never goes looking elsewhere
	if err := extractDLLs(zipPath, stagedDir); err != nil {
		return "", err
	}

	// The staged binary must run and report the version we asked for
	// The staging dir as both: PATH finds the release's DLLs next to the
	// staged exe, and the temp dir goes away with it
	stagedVersion, err := binaryVersion(staged, stagedDir)
	if err != nil {
		return "", fmt.Errorf("downloaded binary failed verification: %w", err)
	}
	if stagedVersion != release.Version {
		return "", fmt.Errorf("downloaded binary reports version %s, expected %s", stagedVersion, release.Version)
	}

	return staged, nil
}

// extractDLLs extracts every *.dll of the archive (base names only) into dir
func extractDLLs(zipPath, dir string) error {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("failed to open downloaded archive: %w", err)
	}
	defer reader.Close()
	for _, file := range reader.File {
		name := filepath.Base(file.Name)
		if file.FileInfo().IsDir() || !strings.EqualFold(filepath.Ext(name), ".dll") || name != filepath.Clean(name) {
			continue
		}
		if err := extractFromZip(zipPath, name, filepath.Join(dir, name)); err != nil {
			return err
		}
	}
	return nil
}

// extractFromZip extracts the archive entry whose base name matches name
func extractFromZip(zipPath, name, destPath string) error {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("failed to open downloaded archive: %w", err)
	}
	defer reader.Close()

	for _, file := range reader.File {
		if filepath.Base(file.Name) != name || file.FileInfo().IsDir() {
			continue
		}
		src, err := file.Open()
		if err != nil {
			return err
		}
		defer src.Close()

		dst, err := os.OpenFile(destPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0755)
		if err != nil {
			return err
		}
		if _, err := io.Copy(dst, src); err != nil {
			dst.Close()
			return fmt.Errorf("failed to extract %s: %w", name, err)
		}
		return dst.Close()
	}
	return fmt.Errorf("archive does not contain %s", name)
}

// Install replaces the working sing-box.exe with the staged binary. The
// previous binary is kept as sing-box.exe.old and restored if the swap fails.
func (u *Updater) Install(stagedPath string) error {
	// Whatever happens, the staging directory goes (never Bin itself)
	if dir := filepath.Dir(stagedPath); strings.HasPrefix(filepath.Base(dir), stagingPrefix) {
		defer os.RemoveAll(dir)
	}
	target := filepath.Join(u.exeDir, config.SingBoxExe)
	backup := target + ".old"

	hadPrevious := false
	if _, err := os.Stat(target); err == nil {
		hadPrevious = true
		os.Remove(backup)
		if err := os.Rename(target, backup); err != nil {
			return fmt.Errorf("failed to back up the current binary: %w", err)
		}
	}

	// The release's DLLs first (the old ones kept as .old until the binary is
	// in place): a new binary must not start with the old libraries
	restoreDLLs, err := u.installDLLs(filepath.Dir(stagedPath))
	if err != nil {
		if hadPrevious {
			os.Rename(backup, target)
		}
		return fmt.Errorf("failed to install the libraries: %w", err)
	}

	// Copy instead of rename: the staging dir may be on another volume
	if err := copyFile(stagedPath, target); err != nil {
		restoreDLLs()
		if hadPrevious {
			os.Remove(target)
			if restoreErr := os.Rename(backup, target); restoreErr != nil {
				return fmt.Errorf("install failed (%v) and restore failed: %w", err, restoreErr)
			}
		}
		return fmt.Errorf("failed to install the new binary: %w", err)
	}

	return nil
}

// installDLLs copies the staged *.dll into Bin, keeping replaced ones as
// .old; the returned func undoes it
func (u *Updater) installDLLs(stagedDir string) (func(), error) {
	dlls, _ := filepath.Glob(filepath.Join(stagedDir, "*.dll"))
	var done []string
	undo := func() {
		for _, name := range done {
			target := filepath.Join(u.exeDir, name)
			os.Remove(target)
			os.Rename(target+".old", target)
		}
	}
	for _, src := range dlls {
		name := filepath.Base(src)
		target := filepath.Join(u.exeDir, name)
		if _, err := os.Stat(target); err == nil {
			os.Remove(target + ".old")
			if err := os.Rename(target, target+".old"); err != nil {
				undo()
				return func() {}, err
			}
		}
		done = append(done, name)
		if err := copyFile(src, target); err != nil {
			undo()
			return func() {}, err
		}
	}
	return undo, nil
}

// stagingPrefix names the download directories inside Bin
const stagingPrefix = ".sing-box-update-"

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
