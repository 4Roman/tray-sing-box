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
	"tray-sing-box/internal/infrastructure/process"
)

// ansiEscapes matches terminal color codes in sing-box output
var ansiEscapes = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// NewValidator returns a config validator backed by `sing-box check`.
// When sing-box.exe is not present in exeDir the validator accepts
// everything: basic JSON validity is still enforced by the config editor.
func NewValidator(exeDir string) func(configJSON []byte) error {
	singBoxPath := filepath.Join(exeDir, config.SingBoxExe)

	return func(configJSON []byte) error {
		if _, err := os.Stat(singBoxPath); err != nil {
			return nil // no binary to check with
		}

		tmp, err := os.CreateTemp("", "singbox-check-*.json")
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
		// Relative paths inside the config (cache.db, rule sets) resolve
		// against the sing-box working directory
		cmd.Dir = exeDir
		output, err := cmd.CombinedOutput()
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
