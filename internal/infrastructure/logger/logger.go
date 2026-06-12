package logger

import (
	"log"
	"os"
	"path/filepath"

	"tray-sing-box/internal/config"
)

// Logger provides logging functionality
type Logger struct {
	file *os.File
}

// New creates a new logger instance
func New() (*Logger, error) {
	exePath, err := os.Executable()
	if err != nil {
		return nil, err
	}
	exeDir := filepath.Dir(exePath)

	logPath := filepath.Join(exeDir, config.LogFileName)
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	log.SetOutput(logFile)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	log.Println("=== Application started ===")

	return &Logger{file: logFile}, nil
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
