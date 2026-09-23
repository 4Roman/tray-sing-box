package domain

import (
	"fmt"
	"log"
	"regexp"
	"strings"
	"sync"
)

// AppRelease describes a published release of this application
type AppRelease struct {
	Version string // e.g. "1.2.0" (tag without the "v")
	Notes   string // release notes, shown to the user
}

// AppRepository manages the application binary: release discovery, verified
// download, swap of the running exe and relaunch.
type AppRepository interface {
	// LatestRelease returns the newest published release
	LatestRelease() (AppRelease, error)
	// Download fetches the release exe next to the running one and verifies
	// it (manifest signature, checksum, `--version`), returning its path
	Download(release AppRelease) (string, error)
	// Install swaps the running exe with the staged one (keeping a backup)
	Install(stagedPath string) error
	// Relaunch starts the installed exe; the caller then exits
	Relaunch() error
}

// AppUpdateResult describes the outcome of an update check or update
type AppUpdateResult struct {
	CurrentVersion string
	LatestVersion  string
	Notes          string
	Available      bool // a newer release exists
	Installed      bool // the exe was replaced; a relaunch is pending
}

// AppUpdateService updates the application itself
type AppUpdateService struct {
	repo    AppRepository
	current string

	mu               sync.Mutex
	installed        bool   // an update was installed and not relaunched yet
	installedVersion string // what is on disk then (GitHub may have moved on)
	installedNotes   string
}

// NewAppUpdateService creates the service for the running version
func NewAppUpdateService(repo AppRepository, currentVersion string) *AppUpdateService {
	return &AppUpdateService{repo: repo, current: currentVersion}
}

var releaseVersion = regexp.MustCompile(`^v?\d+\.\d+\.\d+$`)

// IsReleaseVersion reports whether v is a plain release tag ("v1.2.3"), as
// opposed to a development build ("b056ce3-dirty", "v1.2.3-4-gabcdef")
func IsReleaseVersion(v string) bool {
	return releaseVersion.MatchString(strings.TrimSpace(v))
}

// Check looks up the latest release without downloading anything
func (s *AppUpdateService) Check() (*AppUpdateResult, error) {
	latest, err := s.repo.LatestRelease()
	if err != nil {
		return nil, fmt.Errorf("failed to check the latest release: %w", err)
	}
	result := &AppUpdateResult{CurrentVersion: s.current, LatestVersion: latest.Version, Notes: latest.Notes}
	result.Available = s.isNewer(latest.Version)
	return result, nil
}

// isNewer reports whether the release should replace the running build. A
// development build has no comparable version: it is updated to any release
// on request (the user chose to), never silently (see Check callers).
func (s *AppUpdateService) isNewer(latest string) bool {
	if !IsReleaseVersion(s.current) {
		return IsReleaseVersion(latest)
	}
	return CompareVersions(s.current, latest) < 0
}

// Update installs the latest release when it is newer. The exe on disk is
// replaced and Relaunch must follow (the caller decides when, e.g. after
// telling the user); until then the service reports Installed.
func (s *AppUpdateService) Update() (*AppUpdateResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// A pending relaunch is reported as such without a network round-trip:
	// the version on disk is what matters, not whatever GitHub's latest is
	// by now, and it must be reachable offline too
	if s.installed {
		return &AppUpdateResult{
			CurrentVersion: s.current, LatestVersion: s.installedVersion, Notes: s.installedNotes,
			Available: true, Installed: true,
		}, nil
	}

	result, err := s.Check()
	if err != nil {
		return nil, err
	}
	if !result.Available {
		return result, nil
	}

	log.Printf("App update: %q -> %q", s.current, result.LatestVersion)
	staged, err := s.repo.Download(AppRelease{Version: result.LatestVersion, Notes: result.Notes})
	if err != nil {
		return result, fmt.Errorf("failed to download version %s: %w", result.LatestVersion, err)
	}
	if err := s.repo.Install(staged); err != nil {
		return result, fmt.Errorf("failed to install version %s: %w", result.LatestVersion, err)
	}
	s.installed = true
	s.installedVersion = result.LatestVersion
	s.installedNotes = result.Notes
	result.Installed = true
	log.Printf("App update: version %s installed, relaunch pending", result.LatestVersion)
	return result, nil
}

// Relaunch starts the installed version. The caller must exit right after:
// the new process waits for this one to end before it takes over.
func (s *AppUpdateService) Relaunch() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.installed {
		return fmt.Errorf("no update installed")
	}
	if err := s.repo.Relaunch(); err != nil {
		return fmt.Errorf("failed to start the new version: %w", err)
	}
	return nil
}

// Installed reports whether an update is waiting for a relaunch
func (s *AppUpdateService) Installed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.installed
}

// InstalledVersion is the version on disk while a relaunch is pending ("" otherwise)
func (s *AppUpdateService) InstalledVersion() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.installed {
		return ""
	}
	return s.installedVersion
}
