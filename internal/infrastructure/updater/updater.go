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
	"tray-sing-box/internal/infrastructure/process"
)

const defaultAPIURL = "https://api.github.com/repos/SagerNet/sing-box/releases/latest"

// versionLine matches the first line of `sing-box version` output
var versionLine = regexp.MustCompile(`sing-box version (\S+)`)

// Updater implements domain.BinaryRepository against GitHub releases
type Updater struct {
	exeDir string
	apiURL string
	client *http.Client
}

// New creates an updater for the sing-box binary located in exeDir
func New(exeDir string) *Updater {
	return &Updater{
		exeDir: exeDir,
		apiURL: defaultAPIURL,
		client: &http.Client{Timeout: 10 * time.Minute},
	}
}

// CurrentVersion reports the version of the installed sing-box binary.
// Returns "" without error when the binary is not installed yet.
func (u *Updater) CurrentVersion() (string, error) {
	path := filepath.Join(u.exeDir, config.SingBoxExe)
	if _, err := os.Stat(path); err != nil {
		return "", nil
	}
	return binaryVersion(path)
}

// binaryVersion runs `<binary> version` and parses the version out
func binaryVersion(path string) (string, error) {
	output, err := process.NewHiddenCommand(path, "version").CombinedOutput()
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
func (u *Updater) Download(release domain.ReleaseInfo) (string, error) {
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

	zipFile, err := os.CreateTemp("", "singbox-update-*.zip")
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

	stagedDir, err := os.MkdirTemp("", "singbox-staged-*")
	if err != nil {
		return "", err
	}
	stagedPath := filepath.Join(stagedDir, config.SingBoxExe)
	if err := extractFromZip(zipPath, config.SingBoxExe, stagedPath); err != nil {
		return "", err
	}

	// The staged binary must run and report the version we asked for
	stagedVersion, err := binaryVersion(stagedPath)
	if err != nil {
		return "", fmt.Errorf("downloaded binary failed verification: %w", err)
	}
	if stagedVersion != release.Version {
		return "", fmt.Errorf("downloaded binary reports version %s, expected %s", stagedVersion, release.Version)
	}

	return stagedPath, nil
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

	// Copy instead of rename: the staging dir may be on another volume
	if err := copyFile(stagedPath, target); err != nil {
		if hadPrevious {
			os.Remove(target)
			if restoreErr := os.Rename(backup, target); restoreErr != nil {
				return fmt.Errorf("install failed (%v) and restore failed: %w", err, restoreErr)
			}
		}
		return fmt.Errorf("failed to install the new binary: %w", err)
	}

	os.RemoveAll(filepath.Dir(stagedPath))
	return nil
}

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
