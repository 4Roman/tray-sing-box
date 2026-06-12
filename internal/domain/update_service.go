package domain

import (
	"fmt"
	"log"
	"strconv"
	"strings"
)

// ReleaseInfo describes a published sing-box release
type ReleaseInfo struct {
	Version  string // e.g. "1.12.4"
	AssetURL string // download URL of the windows zip for this machine
}

// BinaryRepository manages the sing-box binary: local version inspection,
// release discovery and installation.
type BinaryRepository interface {
	CurrentVersion() (string, error)
	LatestRelease() (ReleaseInfo, error)
	// Download fetches and verifies the release, returning a staged binary path
	Download(release ReleaseInfo) (string, error)
	// Install replaces the working binary with the staged one (with backup)
	Install(stagedPath string) error
}

// UpdateResult describes the outcome of an update check
type UpdateResult struct {
	CurrentVersion string // installed version before the update ("" if none)
	LatestVersion  string // latest published version
	Updated        bool   // whether the binary was replaced
	Restarted      bool   // whether the VPN was restarted afterwards
}

// UpdateService updates the sing-box binary from official releases
type UpdateService struct {
	repo BinaryRepository
	vpn  *VPNService
}

// NewUpdateService creates a new update service
func NewUpdateService(repo BinaryRepository, vpn *VPNService) *UpdateService {
	return &UpdateService{repo: repo, vpn: vpn}
}

// Update checks the latest release against the installed version and
// installs it when newer. The download happens while the VPN keeps running;
// the VPN is only stopped for the binary swap and started again afterwards.
func (s *UpdateService) Update() (*UpdateResult, error) {
	current, err := s.repo.CurrentVersion()
	if err != nil {
		log.Printf("Update: cannot determine current version: %v", err)
		current = ""
	}

	latest, err := s.repo.LatestRelease()
	if err != nil {
		return nil, fmt.Errorf("failed to check the latest release: %w", err)
	}

	result := &UpdateResult{CurrentVersion: current, LatestVersion: latest.Version}
	log.Printf("Update: current=%q latest=%q", current, latest.Version)

	if current != "" && CompareVersions(current, latest.Version) >= 0 {
		return result, nil
	}

	staged, err := s.repo.Download(latest)
	if err != nil {
		return result, fmt.Errorf("failed to download sing-box %s: %w", latest.Version, err)
	}

	wasRunning := s.vpn.GetStatus().IsRunning()
	if wasRunning {
		if err := s.vpn.Stop(); err != nil {
			return result, fmt.Errorf("failed to stop VPN for the update: %w", err)
		}
	}

	installErr := s.repo.Install(staged)

	if wasRunning {
		// Start regardless of install outcome: on failure Install restores
		// the previous binary, so the VPN comes back on the old version
		if err := s.vpn.Start(); err != nil {
			log.Printf("Update: failed to start VPN after update: %v", err)
		} else {
			result.Restarted = true
		}
	}

	if installErr != nil {
		return result, fmt.Errorf("failed to install sing-box %s: %w", latest.Version, installErr)
	}

	result.Updated = true
	log.Printf("Update: sing-box updated %q -> %q (restarted: %v)", current, latest.Version, result.Restarted)
	return result, nil
}

// CompareVersions compares two version strings like "1.12.4" or
// "1.13.0-alpha.1". Returns -1 / 0 / 1 when a is older / equal / newer.
// A prerelease is older than the release with the same base version.
func CompareVersions(a, b string) int {
	aBase, aPre, _ := strings.Cut(strings.TrimPrefix(a, "v"), "-")
	bBase, bPre, _ := strings.Cut(strings.TrimPrefix(b, "v"), "-")

	aParts := strings.Split(aBase, ".")
	bParts := strings.Split(bBase, ".")
	for i := 0; i < len(aParts) || i < len(bParts); i++ {
		an, bn := 0, 0
		if i < len(aParts) {
			an, _ = strconv.Atoi(aParts[i])
		}
		if i < len(bParts) {
			bn, _ = strconv.Atoi(bParts[i])
		}
		if an != bn {
			if an < bn {
				return -1
			}
			return 1
		}
	}

	switch {
	case aPre == bPre:
		return 0
	case aPre != "" && bPre == "":
		return -1
	case aPre == "" && bPre != "":
		return 1
	case aPre < bPre:
		return -1
	default:
		return 1
	}
}
