// Package paths decides where the application keeps its binaries and its
// data.
//
// Two layouts exist:
//
//   - Portable: everything next to the exe — the historical layout, a copy
//     in any folder, a dev build run from the repo. Data == Bin.
//   - Installed: the exe lives under Program Files, where only an
//     administrator can write, and the data (config.json, logs, subscriptions,
//     history) lives in %ProgramData%\SingBoxTray. This is what the installer
//     sets up. The point is security: the autostart task launches the exe
//     elevated without a UAC prompt, so an exe in a user-writable folder
//     lets any non-elevated program swap it and gain administrator rights at
//     the next logon. sing-box.exe lives in Bin for the same reason.
//
// The layout is decided by the exe location and by what lies next to it;
// there is no setting, so a moved or copied installation keeps working.
//
// Security: the app runs elevated, launched at logon by a task that inherits
// the user's environment — and a user variable (HKCU\Environment) overrides
// a system one of the same name. So nothing here trusts %ProgramFiles%,
// %ProgramData% or %SystemRoot%: the folders come from the known-folder API
// (registry-backed), see SystemFolders. The data directory of an installed
// layout gets a DACL that only lets administrators write (Ensure).
package paths

import (
	"os"
	"path/filepath"
	"strings"

	"tray-sing-box/internal/config"
)

// Layout is where the app's files live
type Layout struct {
	Bin      string // tray-sing-box.exe, sing-box.exe (+ .old/.new backups)
	Data     string // config.json, logs, subscriptions.json, config-history/, cache
	Portable bool   // Data == Bin
}

// Resolve decides the layout for the running exe. Installed mode needs the
// exe under Program Files AND no config.json next to it; anything else is
// portable, so an existing installation is never surprised by a new layout.
func Resolve(exePath string) Layout {
	f := SystemFolders()
	return resolve(exePath, f.ProgramFiles, f.ProgramFilesX86, f.ProgramData, fileExists)
}

// Folders are the machine-wide folders the layout depends on
type Folders struct {
	ProgramFiles, ProgramFilesX86, ProgramData, Windows, System32 string
}

// Under reports whether dir is root or lies inside it (case-insensitive,
// like Windows paths); an empty root contains nothing
func Under(dir, root string) bool { return under(dir, root) }

func resolve(exePath, programFiles, programFilesX86, programData string, exists func(string) bool) Layout {
	bin := filepath.Dir(exePath)
	portable := Layout{Bin: bin, Data: bin, Portable: true}

	if exists(filepath.Join(bin, config.SingBoxConfig)) {
		return portable
	}
	if !(under(bin, programFiles) || under(bin, programFilesX86)) {
		return portable
	}
	if programData == "" {
		// Installed, but where the data belongs is unknown: not portable
		// (the exe's folder is no data directory), Ensure fails instead
		return Layout{Bin: bin, Data: "", Portable: false}
	}
	return Layout{Bin: bin, Data: filepath.Join(programData, config.AppName), Portable: false}
}

// under reports whether dir is root or lies inside it (case-insensitive,
// like Windows paths)
func under(dir, root string) bool {
	if root == "" {
		return false
	}
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(dir))
	if err != nil {
		return false
	}
	rel = strings.ToLower(rel)
	return rel == "." || (!strings.HasPrefix(rel, "..") && !filepath.IsAbs(rel))
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Ensure creates the data directory of an installed layout (a portable one
// exists by definition) and locks it down: only administrators may write
// there. Under %ProgramData% every user may create files and folders by
// default, and config.json decides what the elevated sing-box does (an
// external UI download, a log file anywhere — arbitrary writes as
// administrator), and it holds credentials, so no one but administrators may
// read it either. A directory that is not provably an administrator's own is
// not trusted at all: it is moved aside and started afresh.
//
// The returned warning (a directory moved aside) is for the log, which
// itself lives in the data directory and is opened only afterwards.
func (l Layout) Ensure() (warning string, err error) {
	if l.Portable {
		return "", nil
	}
	return secureDir(l.Data)
}

// File paths of the layout
func (l Layout) SingBoxExe() string      { return filepath.Join(l.Bin, config.SingBoxExe) }
func (l Layout) ConfigFile() string      { return filepath.Join(l.Data, config.SingBoxConfig) }
func (l Layout) Subscriptions() string   { return filepath.Join(l.Data, config.SubscriptionsFileName) }
func (l Layout) DPIParams() string       { return filepath.Join(l.Data, config.DPIParamsFileName) }
func (l Layout) IconFallbackDir() string { return filepath.Join(l.Bin, "assets", "icons") }
