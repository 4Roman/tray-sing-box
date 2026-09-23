// Package logtail locates the application's log files and reads their tails
// for the settings web UI.
package logtail

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"

	"tray-sing-box/internal/config"
)

// File identifies one known log file
type File struct {
	ID   string // "app" (tray-sing-box.log), "singbox" (config.json log.output) or "console" (sing-box stdout/stderr)
	Path string
}

// Reader locates the known log files in the data directory
type Reader struct {
	exeDir string // the data dir: config.json and the log files (name kept)
}

// New creates a Reader rooted at the data directory holding config.json and
// the log files (next to the exe in the portable layout)
func New(dataDir string) *Reader {
	return &Reader{exeDir: dataDir}
}

// Files returns the tray app log and, when config.json sets log.output, the
// sing-box log. Paths are returned even when the files do not exist yet —
// the caller reports a missing file to the user. The capture of sing-box's
// stdout/stderr ("console") is listed only once it exists: with log.output
// set it stays nearly empty, without it this is where the sing-box log goes.
func (r *Reader) Files() []File {
	files := []File{{ID: "app", Path: filepath.Join(r.exeDir, config.LogFileName)}}
	singbox := r.singboxLogPath()
	if singbox != "" {
		files = append(files, File{ID: "singbox", Path: singbox})
	}
	console := filepath.Join(r.exeDir, config.SingBoxConsoleLog)
	if _, err := os.Stat(console); err == nil && !strings.EqualFold(console, singbox) {
		files = append(files, File{ID: "console", Path: console})
	}
	return files
}

// singboxLogPath extracts log.output from config.json; sing-box resolves
// relative paths against its working directory, which is the data dir
func (r *Reader) singboxLogPath() string {
	raw, err := os.ReadFile(filepath.Join(r.exeDir, config.SingBoxConfig))
	if err != nil {
		return ""
	}
	var cfg struct {
		Log struct {
			Output string `json:"output"`
		} `json:"log"`
	}
	if json.Unmarshal(raw, &cfg) != nil {
		return ""
	}
	out := strings.TrimSpace(cfg.Log.Output)
	if out == "" {
		return ""
	}
	if !filepath.IsAbs(out) {
		out = filepath.Join(r.exeDir, out)
	}
	// Only inside the data dir: the elevated app reads this file for the web
	// page, whose token a non-elevated program can obtain — a log.output
	// elsewhere (e.g. into the user-writable folder of a taken-over portable
	// copy, where a link could lead anywhere) is not shown
	rel, err := filepath.Rel(r.exeDir, filepath.Clean(out))
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return ""
	}
	return filepath.Clean(out)
}

// Tail returns up to maxBytes from the end of the file. When the file is
// longer, the result is trimmed to whole lines (the first partial line is
// dropped).
func Tail(path string, maxBytes int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	var offset int64
	if info.Size() > maxBytes {
		offset = info.Size() - maxBytes
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return "", err
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return "", err
	}
	if offset > 0 {
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			data = data[i+1:]
		}
	}
	return string(data), nil
}
