package selfupdate

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"tray-sing-box/internal/config"
	"tray-sing-box/internal/infrastructure/nettrust"
	"tray-sing-box/internal/domain"
	"tray-sing-box/internal/infrastructure/process"
)

// Updater implements domain.AppRepository over the project's GitHub releases.
//
// A release must carry three assets: the exe named AssetName(version),
// checksums.txt (sha256sum format) and checksums.txt.sig (base64 ed25519
// signature of checksums.txt, made by tools/relsign with the key whose
// public half is compiled in). Download verifies the signature first, then
// the exe's checksum, then runs the staged exe with --version.
//
// The swap works while the app is running because Windows lets a running
// exe be renamed (not overwritten): current -> .old, staged -> current. The
// new process is started with --wait-pid=<ours> and takes over once this
// process has exited (single-instance mutex).
type Updater struct {
	exePath string
	repo    string // GitHub "owner/name"
	pubKey  ed25519.PublicKey
	client  *http.Client
	apiURL  string // latest-release endpoint (overridable for tests)

	// Optional: how to run the staged exe for verification. Tests use it to
	// run the test binary in "fake" mode; nil means `staged --version`.
	versionCommand func(ctx context.Context, stagedPath string) *exec.Cmd
}

// stagedVersionTimeout bounds the `--version` run of a downloaded exe. The
// caller holds the operation locks meanwhile, so a build that never answers
// (a MessageBox on a hidden desktop, --version misplaced after a wait) must
// not hang every other operation forever. Generous: the first launch of a
// fresh exe may sit in an antivirus scan.
var stagedVersionTimeout = 60 * time.Second

// New creates an updater for the running exe. It fails when the repository
// or the public key is not configured — self-update is then unavailable.
func New(exePath, repo, publicKey string) (*Updater, error) {
	if strings.TrimSpace(repo) == "" || strings.TrimSpace(publicKey) == "" {
		return nil, fmt.Errorf("self-update is not configured (repository or public key missing)")
	}
	pub, err := ParsePublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	return &Updater{
		exePath: exePath,
		repo:    repo,
		pubKey:  pub,
		client:  nettrust.Client(5 * time.Minute),
		apiURL:  "https://api.github.com/repos/" + repo + "/releases/latest",
	}, nil
}

// AssetName is the exe asset name for a version, as produced by the release
// workflow: tray-sing-box-<version>-windows-<arch>.exe
func AssetName(version string) string {
	base := strings.TrimSuffix(config.AppExeName, ".exe")
	return fmt.Sprintf("%s-%s-windows-%s.exe", base, strings.TrimPrefix(version, "v"), runtime.GOARCH)
}

// githubRelease is the subset of the GitHub release API response we use
type githubRelease struct {
	TagName    string `json:"tag_name"`
	Body       string `json:"body"`
	Prerelease bool   `json:"prerelease"`
	Draft      bool   `json:"draft"`
	Assets     []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
		Size               int64  `json:"size"`
	} `json:"assets"`
}

// release is what LatestRelease found; the asset URLs are kept for Download
type release struct {
	domain.AppRelease
	exeURL, sumsURL, sigURL string
	exeName                 string
}

// LatestRelease queries GitHub for the latest release, refuses drafts,
// pre-releases and non-release tags, and checks it carries all three assets
func (u *Updater) LatestRelease() (domain.AppRelease, error) {
	rel, err := u.fetchLatest()
	if err != nil {
		return domain.AppRelease{}, err
	}
	return rel.AppRelease, nil
}

func (u *Updater) fetchLatest() (*release, error) {
	req, err := http.NewRequest(http.MethodGet, u.apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", config.AppName)

	resp, err := u.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GitHub API request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned status %s", resp.Status)
	}

	var gh githubRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&gh); err != nil {
		return nil, fmt.Errorf("failed to parse GitHub response: %w", err)
	}
	version := strings.TrimPrefix(gh.TagName, "v")
	if version == "" {
		return nil, fmt.Errorf("GitHub response has no release tag")
	}
	if gh.Draft || gh.Prerelease {
		return nil, fmt.Errorf("release %s is a draft or pre-release", gh.TagName)
	}
	// A hand-published "v1.2.3-rc1" without the prerelease flag must not be
	// rolled out as the latest version either
	if !domain.IsReleaseVersion(gh.TagName) {
		return nil, fmt.Errorf("release %s is not a release version (want v<major>.<minor>.<patch>)", gh.TagName)
	}

	rel := &release{AppRelease: domain.AppRelease{Version: version, Notes: strings.TrimSpace(gh.Body)}, exeName: AssetName(version)}
	for _, asset := range gh.Assets {
		switch asset.Name {
		case rel.exeName:
			rel.exeURL = asset.BrowserDownloadURL
		case ChecksumsFile:
			rel.sumsURL = asset.BrowserDownloadURL
		case SignatureFile:
			rel.sigURL = asset.BrowserDownloadURL
		}
	}
	switch {
	case rel.exeURL == "":
		return nil, fmt.Errorf("release %s has no asset %q", gh.TagName, rel.exeName)
	case rel.sumsURL == "":
		return nil, fmt.Errorf("release %s has no %s", gh.TagName, ChecksumsFile)
	case rel.sigURL == "":
		return nil, fmt.Errorf("release %s is not signed (no %s)", gh.TagName, SignatureFile)
	}
	return rel, nil
}

// Download fetches the release exe next to the running one (same volume,
// so Install can rename) and verifies it: signed manifest, checksum,
// `--version` of the staged file. Returns the staged path.
func (u *Updater) Download(want domain.AppRelease) (string, error) {
	// The URLs are re-fetched rather than trusted from an earlier call: the
	// release may have been re-published in between
	rel, err := u.fetchLatest()
	if err != nil {
		return "", err
	}
	if rel.Version != want.Version {
		return "", fmt.Errorf("latest release is now %s, not %s", rel.Version, want.Version)
	}

	manifest, err := u.fetch(rel.sumsURL, 1<<20)
	if err != nil {
		return "", fmt.Errorf("%s: %w", ChecksumsFile, err)
	}
	signature, err := u.fetch(rel.sigURL, 4096)
	if err != nil {
		return "", fmt.Errorf("%s: %w", SignatureFile, err)
	}
	if err := Verify(u.pubKey, manifest, string(signature)); err != nil {
		return "", fmt.Errorf("release %s rejected: %w", rel.Version, err)
	}
	sums, err := ParseChecksums(manifest)
	if err != nil {
		return "", fmt.Errorf("release %s rejected: bad %s: %w", rel.Version, ChecksumsFile, err)
	}
	wantSum, ok := sums[rel.exeName]
	if !ok {
		return "", fmt.Errorf("release %s rejected: %s does not list %s", rel.Version, ChecksumsFile, rel.exeName)
	}

	staged := u.exePath + ".new"
	os.Remove(staged)
	if err := u.fetchToFile(rel.exeURL, staged); err != nil {
		os.Remove(staged)
		return "", err
	}
	gotSum, err := FileSHA256(staged)
	if err != nil {
		os.Remove(staged)
		return "", err
	}
	if gotSum != wantSum {
		os.Remove(staged)
		return "", fmt.Errorf("release %s rejected: checksum mismatch for %s", rel.Version, rel.exeName)
	}

	// The file is what the manifest promises; now make sure it is a working
	// build of the expected version before it replaces the running one
	reported, err := u.stagedVersion(staged)
	if err != nil {
		os.Remove(staged)
		return "", fmt.Errorf("downloaded exe does not run: %w", err)
	}
	if strings.TrimPrefix(reported, "v") != rel.Version {
		os.Remove(staged)
		return "", fmt.Errorf("downloaded exe reports version %q, expected %s", reported, rel.Version)
	}
	log.Printf("App update: version %s downloaded and verified (%s)", rel.Version, staged)
	return staged, nil
}

func (u *Updater) stagedVersion(staged string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), stagedVersionTimeout)
	defer cancel()

	var cmd *exec.Cmd
	if u.versionCommand != nil {
		cmd = u.versionCommand(ctx, staged)
	} else {
		cmd = process.NewHiddenCommandContext(ctx, staged, "--version")
	}
	output, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return "", fmt.Errorf("no answer to --version within %s", stagedVersionTimeout)
		}
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

// Install swaps the running exe with the staged one. The running file can
// be renamed but not overwritten; the previous version is kept as .old
// (one generation) and restored when the swap fails halfway.
func (u *Updater) Install(staged string) error {
	backup := u.exePath + ".old"
	os.Remove(backup)
	if err := os.Rename(u.exePath, backup); err != nil {
		return fmt.Errorf("failed to move the running exe aside: %w", err)
	}
	if err := os.Rename(staged, u.exePath); err != nil {
		if restoreErr := os.Rename(backup, u.exePath); restoreErr != nil {
			return fmt.Errorf("install failed (%v) and restore failed: %w", err, restoreErr)
		}
		return fmt.Errorf("failed to put the new exe in place: %w", err)
	}
	return nil
}

// Relaunch starts the exe now on disk. It waits for this process to exit
// (--wait-pid) before it takes over, so the single-instance mutex and the
// sing-box adoption work as on a normal start.
func (u *Updater) Relaunch() error {
	cmd := exec.Command(u.exePath, "--wait-pid="+strconv.Itoa(os.Getpid()))
	cmd.Dir = filepath.Dir(u.exePath)
	if err := cmd.Start(); err != nil {
		return err
	}
	// Not waited for: the child outlives this process
	_ = cmd.Process.Release()
	return nil
}

func (u *Updater) fetch(url string, limit int64) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", config.AppName)
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download returned status %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

func (u *Updater) fetchToFile(url, path string) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", config.AppName)
	resp, err := u.client.Do(req)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned status %s", resp.Status)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0755)
	if err != nil {
		return err
	}
	// The signature bounds what is installed, not how much is written
	const maxDownload = 256 << 20
	n, err := io.Copy(f, io.LimitReader(resp.Body, maxDownload+1))
	if err != nil {
		f.Close()
		return fmt.Errorf("download failed: %w", err)
	}
	if n > maxDownload {
		f.Close()
		return fmt.Errorf("download larger than %d MB, refused", maxDownload>>20)
	}
	return f.Close()
}
