package logger

import (
	"os"
	"path/filepath"
	"testing"

	"tray-sing-box/internal/config"
)

func TestRotateMovesOversizedLogAside(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), config.LogFileName)

	// A small log stays where it is
	if err := os.WriteFile(logPath, []byte("small"), 0644); err != nil {
		t.Fatal(err)
	}
	if got := rotate(logPath); got != "" {
		t.Fatalf("small log rotated to %q", got)
	}

	// An oversized one is moved to .old, replacing the previous generation
	if err := os.WriteFile(logPath+".old", []byte("previous generation"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(logPath, config.LogMaxSizeMB<<20+1); err != nil {
		t.Fatal(err)
	}
	if got := rotate(logPath); got != logPath+".old" {
		t.Fatalf("rotate = %q, want %q", got, logPath+".old")
	}
	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Fatal("oversized log still in place after rotation")
	}
	info, err := os.Stat(logPath + ".old")
	if err != nil || info.Size() != config.LogMaxSizeMB<<20+1 {
		t.Fatalf("rotated log missing or wrong: %v", err)
	}
}

func TestRotateWithoutLog(t *testing.T) {
	if got := rotate(filepath.Join(t.TempDir(), config.LogFileName)); got != "" {
		t.Fatalf("rotate without a log = %q", got)
	}
}
