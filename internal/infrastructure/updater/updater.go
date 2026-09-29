//go:build windows

// Package updater downloads sing-box releases from the official GitHub
// repository (SagerNet/sing-box) and swaps the local binary safely.
package updater

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
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

// ansiEscapes matches terminal color codes in sing-box output
var ansiEscapes = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// Updater implements domain.BinaryRepository against GitHub releases
type Updater struct {
	exeDir  string
	dataDir string // config.json; TEMP of the sing-box runs (SingBoxEnv)
	apiURL  string
	client  *http.Client

	// What the last successful Install replaced, for Rollback. No lock:
	// updates are serialized by the app's opMu
	last *installRecord
}

// installRecord is what an Install changed in Bin
type installRecord struct {
	hadPrevious  bool     // sing-box.exe was replaced (kept as .old), not installed fresh
	replacedDLLs []string // libraries that replaced one kept as .old
	addedDLLs    []string // libraries that were not there before
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

// CheckConfig runs `sing-box check` on the current config.json with binary:
// a download staged by Download, or the installed sing-box.exe when binary
// is "". Without a config.json there is nothing to check ("Скачать sing-box"
// on a fresh install); without the binary the answer wraps
// domain.ErrSingBoxMissing. A refusal is what sing-box printed.
func (u *Updater) CheckConfig(binary string) error {
	if binary == "" {
		binary = filepath.Join(u.exeDir, config.SingBoxExe)
	}
	configPath := filepath.Join(u.dataDir, config.SingBoxConfig)
	if _, err := os.Stat(configPath); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if _, err := os.Stat(binary); err != nil {
		return fmt.Errorf("%w at: %s", domain.ErrSingBoxMissing, binary)
	}

	// Run as the VPN runs: the binary's own folder on PATH (a staged exe
	// finds the release's libraries next to it) and the data dir as the
	// working directory (relative paths in the config resolve there).
	// HelperOutput: not the VPN process, see process.HelperOutput
	cmd := process.NewHiddenCommand(binary, "check", "-c", configPath)
	cmd.Env = process.SingBoxEnv(filepath.Dir(binary), u.dataDir)
	cmd.Dir = u.dataDir
	output, err := process.HelperOutput(cmd)
	if err != nil {
		message := strings.TrimSpace(ansiEscapes.ReplaceAllString(string(output), ""))
		if message == "" {
			message = err.Error()
		}
		return errors.New(message)
	}
	return nil
}

// Discard removes a download that will not be installed: the staging
// directory Download created, nothing else
func (u *Updater) Discard(stagedPath string) error {
	dir, ok := u.stagingDir(stagedPath)
	if !ok {
		return fmt.Errorf("not a staged download: %s", stagedPath)
	}
	return os.RemoveAll(dir)
}

// stagingDir is the directory of a staged download when it is one of
// Download's staging directories in Bin
func (u *Updater) stagingDir(stagedPath string) (string, bool) {
	dir := filepath.Dir(stagedPath)
	if !strings.HasPrefix(filepath.Base(dir), stagingPrefix) ||
		!strings.EqualFold(filepath.Dir(dir), filepath.Clean(u.exeDir)) {
		return "", false
	}
	return dir, true
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
// previous binary is kept as sing-box.exe.old and restored if the swap fails;
// what was replaced is recorded for Rollback.
func (u *Updater) Install(stagedPath string) error {
	// Whatever happens, the staging directory goes (never Bin itself)
	if dir, ok := u.stagingDir(stagedPath); ok {
		defer os.RemoveAll(dir)
	}
	u.last = nil
	target := filepath.Join(u.exeDir, config.SingBoxExe)
	backup := target + ".old"

	record := &installRecord{}
	if _, err := os.Stat(target); err == nil {
		record.hadPrevious = true
		os.Remove(backup)
		if err := os.Rename(target, backup); err != nil {
			return fmt.Errorf("failed to back up the current binary: %w", err)
		}
	}

	// The release's DLLs first (the old ones kept as .old until the binary is
	// in place): a new binary must not start with the old libraries
	if err := u.installDLLs(filepath.Dir(stagedPath), record); err != nil {
		if record.hadPrevious {
			os.Rename(backup, target)
		}
		return fmt.Errorf("failed to install the libraries: %w", err)
	}

	// Copy instead of rename: the staging dir may be on another volume
	if err := copyFile(stagedPath, target); err != nil {
		u.restoreDLLs(record)
		if record.hadPrevious {
			os.Remove(target)
			if restoreErr := os.Rename(backup, target); restoreErr != nil {
				return fmt.Errorf("install failed (%v) and restore failed: %w", err, restoreErr)
			}
		}
		return fmt.Errorf("failed to install the new binary: %w", err)
	}

	u.last = record
	return nil
}

// Rollback puts back what the last Install replaced: the previous
// sing-box.exe and libraries from their .old copies (over the new ones), and
// removes the libraries that release added — the new version does not
// start. sing-box must be stopped. An error when that Install had no
// previous binary: there is nothing to go back to.
func (u *Updater) Rollback() error {
	record := u.last
	if record == nil {
		return errors.New("no installed update to roll back")
	}
	if !record.hadPrevious {
		return errors.New("there was no previous sing-box.exe")
	}
	u.last = nil

	target := filepath.Join(u.exeDir, config.SingBoxExe)
	var errs []error
	// A rename replaces the new binary (the .old is on the same volume)
	if err := os.Rename(target+".old", target); err != nil {
		errs = append(errs, fmt.Errorf("failed to restore the previous binary: %w", err))
	}
	if err := u.restoreDLLs(record); err != nil {
		errs = append(errs, fmt.Errorf("failed to restore the libraries: %w", err))
	}
	return errors.Join(errs...)
}

// installDLLs copies the staged *.dll into Bin, keeping replaced ones as
// .old, and records which ones replaced a library and which are new; on
// failure it has undone itself
func (u *Updater) installDLLs(stagedDir string, record *installRecord) error {
	dlls, _ := filepath.Glob(filepath.Join(stagedDir, "*.dll"))
	for _, src := range dlls {
		name := filepath.Base(src)
		target := filepath.Join(u.exeDir, name)
		if _, err := os.Stat(target); err == nil {
			os.Remove(target + ".old")
			if err := os.Rename(target, target+".old"); err != nil {
				u.restoreDLLs(record)
				return err
			}
			record.replacedDLLs = append(record.replacedDLLs, name)
		} else {
			record.addedDLLs = append(record.addedDLLs, name)
		}
		if err := copyFile(src, target); err != nil {
			u.restoreDLLs(record)
			return err
		}
	}
	return nil
}

// restoreDLLs undoes installDLLs: the replaced libraries back from .old, the
// added ones removed (a stale .old of a library that was not there is left
// alone — it is no backup of this install)
func (u *Updater) restoreDLLs(record *installRecord) error {
	var errs []error
	for _, name := range record.replacedDLLs {
		target := filepath.Join(u.exeDir, name)
		if err := os.Rename(target+".old", target); err != nil {
			errs = append(errs, err)
		}
	}
	for _, name := range record.addedDLLs {
		if err := os.Remove(filepath.Join(u.exeDir, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
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
