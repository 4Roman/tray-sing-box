package logtail

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tray-sing-box/internal/config"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestFilesAppOnly(t *testing.T) {
	dir := t.TempDir()
	files := New(dir).Files()
	if len(files) != 1 {
		t.Fatalf("want 1 file without config.json, got %d", len(files))
	}
	if files[0].ID != "app" || files[0].Path != filepath.Join(dir, config.LogFileName) {
		t.Fatalf("unexpected app log entry: %+v", files[0])
	}
}

func TestFilesWithSingboxLog(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, config.SingBoxConfig), `{"log":{"level":"info","output":"sing-box.log"}}`)

	files := New(dir).Files()
	if len(files) != 2 {
		t.Fatalf("want 2 files, got %d: %+v", len(files), files)
	}
	if files[1].ID != "singbox" || files[1].Path != filepath.Join(dir, "sing-box.log") {
		t.Fatalf("unexpected singbox log entry: %+v", files[1])
	}
}

func TestFilesAbsoluteOutput(t *testing.T) {
	dir := t.TempDir()
	abs := filepath.Join(dir, "elsewhere", "sb.log")
	cfg := `{"log":{"output":` + jsonString(abs) + `}}`
	write(t, filepath.Join(dir, config.SingBoxConfig), cfg)

	files := New(dir).Files()
	if len(files) != 2 || files[1].Path != abs {
		t.Fatalf("absolute output not kept: %+v", files)
	}
}

func TestFilesIgnoresUnsetOrBrokenConfig(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, config.SingBoxConfig), `{"log":{"level":"info"}}`)
	if files := New(dir).Files(); len(files) != 1 {
		t.Fatalf("output unset: want 1 file, got %+v", files)
	}

	write(t, filepath.Join(dir, config.SingBoxConfig), `{broken`)
	if files := New(dir).Files(); len(files) != 1 {
		t.Fatalf("broken config: want 1 file, got %+v", files)
	}
}

// sing-box's stdout/stderr capture shows up once sing-box has been started
func TestFilesConsoleCapture(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, config.SingBoxConsoleLog), "FATAL start service\n")

	files := New(dir).Files()
	if len(files) != 2 || files[1].ID != "console" || files[1].Path != filepath.Join(dir, config.SingBoxConsoleLog) {
		t.Fatalf("console capture not listed: %+v", files)
	}

	// With a separate log.output all three are listed, the console last
	write(t, filepath.Join(dir, config.SingBoxConfig), `{"log":{"output":"sing-box.log"}}`)
	files = New(dir).Files()
	if len(files) != 3 || files[1].ID != "singbox" || files[2].ID != "console" {
		t.Fatalf("want app, singbox, console — got %+v", files)
	}

	// log.output pointing at the very same file: listed once
	write(t, filepath.Join(dir, config.SingBoxConfig), `{"log":{"output":"`+config.SingBoxConsoleLog+`"}}`)
	files = New(dir).Files()
	if len(files) != 2 || files[1].ID != "singbox" {
		t.Fatalf("same file listed twice or lost: %+v", files)
	}
}

func TestTailShortFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.log")
	write(t, path, "line1\nline2\n")

	got, err := Tail(path, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if got != "line1\nline2\n" {
		t.Fatalf("short file must be returned whole, got %q", got)
	}
}

func TestTailTrimsToWholeLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.log")
	write(t, path, "aaaaaaaaaa\nbbbbbbbbbb\ncccccccccc\n")

	// 15 bytes from the end lands mid-"bbb" line; it must be dropped
	got, err := Tail(path, 15)
	if err != nil {
		t.Fatal(err)
	}
	if got != "cccccccccc\n" {
		t.Fatalf("want only whole last line, got %q", got)
	}
	if strings.Contains(got, "b") {
		t.Fatalf("partial line leaked: %q", got)
	}
}

func TestTailMissingFile(t *testing.T) {
	if _, err := Tail(filepath.Join(t.TempDir(), "nope.log"), 10); err == nil {
		t.Fatal("want error for missing file")
	}
}

// jsonString marshals s as a JSON string literal (handles Windows backslashes)
func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// A log.output outside the data dir is not shown by the elevated viewer
func TestFilesIgnoresOutputOutsideTheDataDir(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "sb.log")
	for _, out := range []string{outside, `..\\sb.log`} {
		write(t, filepath.Join(dir, config.SingBoxConfig), `{"log":{"output":`+jsonString(out)+`}}`)
		for _, f := range New(dir).Files() {
			if f.ID == "singbox" {
				t.Fatalf("log.output %q outside the data dir listed: %+v", out, f)
			}
		}
	}
}
