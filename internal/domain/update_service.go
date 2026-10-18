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
	// CheckConfig runs `sing-box check` on the current config.json with a
	// staged binary, or with the installed one when binary is "". nil when
	// there is no config.json yet; an error wrapping ErrSingBoxMissing when
	// there is no such binary; otherwise the error is what sing-box printed.
	CheckConfig(binary string) error
	// Discard removes a staged download that will not be installed
	Discard(stagedPath string) error
	// Install replaces the working binary with the staged one (with backup)
	Install(stagedPath string) error
	// Rollback puts back what the last Install replaced (the previous binary
	// and libraries from their backups; libraries that release added are
	// removed). An error when that Install had no previous binary.
	Rollback() error
}

// UpdateResult describes the outcome of an update check
type UpdateResult struct {
	CurrentVersion string // installed version before the update ("" if none)
	LatestVersion  string // latest published version
	Updated        bool   // whether the binary was replaced (and stays replaced)
	Restarted      bool   // whether the VPN was restarted afterwards
	// The new version refuses the current config.json, which the installed
	// one accepts: nothing was stopped or replaced
	ConfigRejected bool
	// The new version did not start: the previous one was put back (and runs
	// again when Restarted)
	RolledBack bool
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
// A new version that refuses the current config is not installed, one that
// does not start is rolled back: an update never leaves the VPN down where
// the old version runs.
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

	// Before anything is stopped: a version that would not run the config is
	// not installed at all
	if err := s.checkConfig(staged, current, latest.Version); err != nil {
		result.ConfigRejected = true
		if discardErr := s.repo.Discard(staged); discardErr != nil {
			log.Printf("Update: failed to remove the download: %v", discardErr)
		}
		return result, err
	}

	// The swap is a maintenance stop, not a user decision: WithStoppedOrUndo
	// leaves the stored intent alone (a failed start must not disable
	// auto-enable on next boot) and keeps the crash monitor away from the
	// half-swapped binary. The VPN is started again regardless of the install
	// outcome: on failure Install restores the previous binary, so it comes
	// back on the old version. A new version that installs but does not start
	// is rolled back and the old one started — otherwise the monitor would
	// retry the new one until it gives up, and the VPN would stay down.
	installed := false
	outcome, err := s.vpn.WithStoppedOrUndo(func() error {
		if err := s.repo.Install(staged); err != nil {
			return fmt.Errorf("failed to install sing-box %s: %w", latest.Version, err)
		}
		installed = true
		return nil
	}, s.repo.Rollback)
	result.Restarted = outcome.Restarted
	result.RolledBack = outcome.Undone
	result.Updated = installed && !outcome.Undone
	if installed && outcome.StartErr != nil {
		err := notStartedError(latest.Version, current, outcome)
		log.Printf("Update: %v", err)
		return result, err
	}
	if err != nil {
		if installed {
			return result, fmt.Errorf("sing-box updated to %s, but: %w", latest.Version, err)
		}
		return result, err
	}

	log.Printf("Update: sing-box updated %q -> %q (restarted: %v)", current, latest.Version, result.Restarted)
	return result, nil
}

// checkConfig checks the current config with the downloaded binary. The
// latest release may be several minor versions ahead, and sing-box
// regularly drops deprecated options: a binary that refuses the config would
// leave the VPN down. The update is refused when the installed binary
// accepts the config. When it refuses it too (or there is none) the config
// is broken for both, and the update goes on only while the VPN is down:
// nothing is lost then, and the new binary is in place for a fixed config.
// A running VPN still works with the config it read earlier — stopping it
// for the swap would leave it down on either version.
func (s *UpdateService) checkConfig(staged, current, latest string) error {
	stagedErr := s.repo.CheckConfig(staged)
	if stagedErr == nil {
		return nil
	}
	if installedErr := s.repo.CheckConfig(""); installedErr != nil {
		if s.vpn.GetStatus() == VPNStatusRunning {
			log.Printf("Update: sing-box %s and the installed binary both refuse the config (%v; %v), the VPN runs: update cancelled", latest, stagedErr, installedErr)
			return fmt.Errorf("текущий config.json не принимают ни sing-box %s, ни установленная версия%s:\n%w\n\n"+
				"VPN работает с конфигом, прочитанным раньше, поэтому обновление отменено: после остановки он не запустился бы ни на одной версии. "+
				"Исправьте config.json, затем обновите снова.",
				latest, versionSuffix(current), stagedErr)
		}
		log.Printf("Update: sing-box %s refuses the config (%v), and so does the installed binary (%v), the VPN is down: updating anyway", latest, stagedErr, installedErr)
		return nil
	}
	log.Printf("Update: sing-box %s refuses the config the installed binary accepts, update cancelled: %v", latest, stagedErr)
	return fmt.Errorf("sing-box %s не принимает текущий конфиг:\n%w\n\n"+
		"Обновление отменено, продолжает работать установленная версия%s. "+
		"Сначала измените config.json под новую версию (что в ней убрано или переименовано — в списке изменений sing-box), затем обновите снова.",
		latest, stagedErr, versionSuffix(current))
}

// notStartedError tells the user that the new version did not start and what
// became of the rollback
func notStartedError(latest, current string, outcome SwapOutcome) error {
	old := versionSuffix(current)
	switch {
	case outcome.UndoErr != nil:
		return fmt.Errorf("sing-box %s не запустился:\n%w\n\nВернуть прежнюю версию%s не удалось: %w",
			latest, outcome.StartErr, old, outcome.UndoErr)
	case outcome.RestartErr != nil:
		return fmt.Errorf("sing-box %s не запустился:\n%w\n\nВозвращена прежняя версия%s, но и она не запустилась:\n%w",
			latest, outcome.StartErr, old, outcome.RestartErr)
	}
	return fmt.Errorf("sing-box %s не запустился:\n%w\n\nВозвращена прежняя версия%s, VPN снова работает. Обновление можно повторить, устранив причину.",
		latest, outcome.StartErr, old)
}

// versionSuffix is " <version>" for a message, or nothing when the installed
// version could not be determined
func versionSuffix(version string) string {
	if version == "" {
		return ""
	}
	return " " + version
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
