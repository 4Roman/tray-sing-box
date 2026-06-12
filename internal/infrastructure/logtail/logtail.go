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
	ID   string // "app" (tray-sing-box.log) or "singbox" (config.json log.output)
	Path string
}

// Reader locates the known log files next to the executable
type Reader struct {
	exeDir string
}

// New creates a Reader rooted at the directory holding the exe, config.json
// and the log files
func New(exeDir string) *Reader {
	return &Reader{exeDir: exeDir}
}

// Files returns the tray app log and, when config.json sets log.output, the
// sing-box log. Paths are returned even when the files do not exist yet —
// the caller reports a missing file to the user.
func (r *Reader) Files() []File {
	files := []File{{ID: "app", Path: filepath.Join(r.exeDir, config.LogFileName)}}
	if p := r.singboxLogPath(); p != "" {
		files = append(files, File{ID: "singbox", Path: p})
	}
	return files
}

// singboxLogPath extracts log.output from config.json; sing-box resolves
// relative paths against its working directory, which is the exe dir here
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
	return out
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
