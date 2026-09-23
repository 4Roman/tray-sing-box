package logger

import (
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/getlantern/golog"

	"tray-sing-box/internal/config"
)

// Logger provides logging functionality
type Logger struct {
	file *os.File
}

// New creates a new logger instance writing to dataDir/tray-sing-box.log
func New(dataDir string) (*Logger, error) {
	logPath := filepath.Join(dataDir, config.LogFileName)
	rotated := rotate(logPath)
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	log.SetOutput(logFile)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// The tray library reports its failures (icon not added, icon file not
	// loadable) only through golog, which writes to stderr — nowhere for a
	// GUI app. Debug output stays off.
	golog.SetOutputs(logFile, io.Discard)

	log.Println("=== Application started ===")
	if rotated != "" {
		log.Printf("Previous log exceeded %d MB and was moved to %s", config.LogMaxSizeMB, rotated)
	}

	return &Logger{file: logFile}, nil
}

// rotate moves an oversized log aside (one generation, the previous ".old"
// is replaced) and returns the new name, or "" when nothing was rotated.
// The log is append-only and sing-box output is piped into it, so without
// this it grows forever. Best effort: when the rename fails (e.g. another
// instance holds the file) logging simply continues in the same file.
func rotate(logPath string) string {
	info, err := os.Stat(logPath)
	if err != nil || info.Size() <= config.LogMaxSizeMB<<20 {
		return ""
	}
	oldPath := logPath + ".old"
	if err := os.Rename(logPath, oldPath); err != nil {
		return ""
	}
	return oldPath
}

// Close closes the log file
func (l *Logger) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// Info logs an informational message
func (l *Logger) Info(msg string) {
	log.Println("[INFO]", msg)
}

// Error logs an error message
func (l *Logger) Error(msg string) {
	log.Println("[ERROR]", msg)
}

// Debug logs a debug message
func (l *Logger) Debug(msg string) {
	log.Println("[DEBUG]", msg)
}
