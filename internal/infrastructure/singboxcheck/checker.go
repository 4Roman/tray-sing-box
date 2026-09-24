//go:build windows

// Package singboxcheck validates candidate configurations with the real
// sing-box binary (`sing-box check`) before they are written to disk.
package singboxcheck

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"tray-sing-box/internal/config"
	"tray-sing-box/internal/domain"
	"tray-sing-box/internal/infrastructure/process"
)

// ansiEscapes matches terminal color codes in sing-box output
var ansiEscapes = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// scratchDir is where the config under test is written: the data dir (not
// the user's %TEMP%, where a non-elevated program could swap it before the
// elevated check reads it). The SINGBOX_REAL_DIR tests point it elsewhere so
// that they never write into a real installation.
var scratchDir = func(dataDir string) string { return dataDir }

// NewValidator returns a config validator backed by `sing-box check`, with
// sing-box.exe in binDir and dataDir as the working directory (relative
// paths in the config resolve there, as they do for the running VPN).
// When sing-box.exe is not present it answers domain.ErrSingBoxMissing: an
// ordinary save goes ahead unchecked (basic JSON validity is still enforced
// by the config editor), the first config of an installation does not.
func NewValidator(binDir, dataDir string) func(configJSON []byte) error {
	singBoxPath := filepath.Join(binDir, config.SingBoxExe)

	return func(configJSON []byte) error {
		if _, err := os.Stat(singBoxPath); err != nil {
			return fmt.Errorf("%w at: %s", domain.ErrSingBoxMissing, singBoxPath)
		}

		// In the data dir, not the user's %TEMP%: the elevated `sing-box
		// check` must validate exactly what is about to be saved
		tmp, err := os.CreateTemp(scratchDir(dataDir), ".singbox-check-*.json")
		if err != nil {
			return nil // cannot stage the check; do not block the save
		}
		tmpPath := tmp.Name()
		defer os.Remove(tmpPath)

		if _, err := tmp.Write(configJSON); err != nil {
			tmp.Close()
			return nil
		}
		if err := tmp.Close(); err != nil {
			return nil
		}

		cmd := process.NewHiddenCommand(singBoxPath, "check", "-c", tmpPath)
		cmd.Env = process.SingBoxEnv(binDir, dataDir)
		// Relative paths inside the config (cache.db, rule sets) resolve
		// against the sing-box working directory
		cmd.Dir = dataDir
		// HelperOutput: this is sing-box.exe too, the process manager must
		// not take it for the VPN (or kill it on a Stop)
		output, err := process.HelperOutput(cmd)
		if err != nil {
			message := strings.TrimSpace(ansiEscapes.ReplaceAllString(string(output), ""))
			if message == "" {
				message = err.Error()
			}
			return fmt.Errorf("sing-box check: %s", message)
		}
		return nil
	}
}
