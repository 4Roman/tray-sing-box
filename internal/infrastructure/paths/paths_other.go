//go:build !windows

package paths

import "os"

// SystemFolders: the app is Windows-only; this keeps the package buildable
// (and its platform-independent tests runnable) elsewhere
func SystemFolders() Folders {
	return Folders{
		ProgramFiles:    os.Getenv("ProgramFiles"),
		ProgramFilesX86: os.Getenv("ProgramFiles(x86)"),
		ProgramData:     os.Getenv("ProgramData"),
	}
}

func System32(name string) string { return name }

func secureDir(dir string) (string, error) {
	if dir == "" {
		return "", os.ErrNotExist
	}
	return "", os.MkdirAll(dir, 0755)
}
