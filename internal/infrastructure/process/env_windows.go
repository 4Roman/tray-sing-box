//go:build windows

package process

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"tray-sing-box/internal/infrastructure/paths"
)

// testEnv: the process tests pass their fake's mode through here (the fake
// sing-box is the test binary, steered by an environment variable)
var testEnv []string

// SingBoxEnv is the whole environment of a sing-box child — the VPN,
// `check`, `version`: built here, never inherited. The app runs elevated
// with the user's environment, and sing-box would take from it what a
// non-elevated program of the user can set. PATH above all: builds with the
// naive outbound load libcronet.dll from the exe's folder and then from every
// PATH directory, and the user's own PATH entries (some writable without
// elevation, such as %LOCALAPPDATA%\Microsoft\WindowsApps) would hand the
// elevated sing-box a DLL to run. Also GODEBUG and the like. dataDir holds
// the temp directory and stands in for the profile.
func SingBoxEnv(binDir, dataDir string) []string {
	f := paths.SystemFolders()
	temp := filepath.Join(dataDir, "tmp")
	os.MkdirAll(temp, 0755) // inherits the data dir's DACL
	env := []string{
		"SystemRoot=" + f.Windows,
		"windir=" + f.Windows,
		"SystemDrive=" + filepath.VolumeName(f.Windows),
		"ProgramData=" + f.ProgramData,
		"ProgramFiles=" + f.ProgramFiles,
		"PATH=" + strings.Join([]string{binDir, f.System32, f.Windows, filepath.Join(f.System32, "Wbem")}, ";"),
		"TEMP=" + temp,
		"TMP=" + temp,
		"USERPROFILE=" + dataDir,
	}
	// The one thing taken from outside: sing-box's ENABLE_DEPRECATED_<X>
	// switches (1.12+ refuses to start on a config that still uses a
	// deprecated feature unless its switch is set), as normalized booleans
	for _, kv := range os.Environ() {
		name, value, ok := strings.Cut(kv, "=")
		if !ok || !deprecatedSwitch.MatchString(strings.ToUpper(name)) {
			continue
		}
		if b, err := strconv.ParseBool(value); err == nil {
			env = append(env, strings.ToUpper(name)+"="+strconv.FormatBool(b))
		}
	}
	return append(env, testEnv...)
}

var deprecatedSwitch = regexp.MustCompile(`^ENABLE_DEPRECATED_[A-Z0-9_]+$`)
