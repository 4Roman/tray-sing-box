package migrate

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"tray-sing-box/internal/config"
	"tray-sing-box/internal/infrastructure/paths"
)

// tempDir is t.TempDir with a patient cleanup: the tests create files named
// sing-box.exe / *.dll, and a real-time antivirus scanner may hold a freshly
// written one for a moment, which fails t.TempDir's single RemoveAll
func tempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "migrate-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		var err error
		for i := 0; i < 20; i++ {
			if err = os.RemoveAll(dir); err == nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Logf("leaving %s behind: %v", dir, err)
	})
	return dir
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return string(data)
}

func TestNeededOnlyForAnInstalledLayoutWithoutConfig(t *testing.T) {
	data := tempDir(t)
	installed := paths.Layout{Bin: tempDir(t), Data: data}
	if !Needed(installed) {
		t.Fatal("installed layout without config.json must migrate")
	}
	write(t, filepath.Join(data, config.SingBoxConfig), "{}")
	if Needed(installed) {
		t.Fatal("a configured installation must not migrate again")
	}
	if Needed(paths.Layout{Bin: data, Data: data, Portable: true}) {
		t.Fatal("a portable layout never migrates")
	}
}

func TestSource(t *testing.T) {
	old := tempDir(t)
	layout := paths.Layout{Bin: tempDir(t), Data: tempDir(t)}

	if _, ok := Source("", layout); ok {
		t.Fatal("no registered exe must give no source")
	}
	if _, ok := Source(filepath.Join(old, config.AppExeName), layout); ok {
		t.Fatal("a directory without config.json is not a source")
	}
	write(t, filepath.Join(old, config.SingBoxConfig), "{}")
	if dir, ok := Source(filepath.Join(old, config.AppExeName), layout); !ok || dir != old {
		t.Fatalf("Source = %q, %v", dir, ok)
	}
	// The task pointing at the new installation itself is not a source
	write(t, filepath.Join(layout.Bin, config.SingBoxConfig), "{}")
	if _, ok := Source(filepath.Join(layout.Bin, config.AppExeName), layout); ok {
		t.Fatal("the installation's own directory must not be a source")
	}
}

func TestRunCopiesEverythingAndStopsTheOldCopy(t *testing.T) {
	old := tempDir(t)
	write(t, filepath.Join(old, config.SingBoxConfig), `{"log":{}}`)
	write(t, filepath.Join(old, config.SubscriptionsFileName), `[]`)
	write(t, filepath.Join(old, config.DPIParamsFileName), `--dpi-desync=fake`)
	write(t, filepath.Join(old, "cache.db"), "cache")
	write(t, filepath.Join(old, config.ConfigHistoryDir, "config-1.json"), "{}")
	write(t, filepath.Join(old, config.SingBoxExe), "MZ sing-box")
	write(t, filepath.Join(old, "libcronet.dll"), "MZ dll")
	write(t, filepath.Join(old, config.AppExeName), "MZ old tray") // not copied
	write(t, filepath.Join(old, "tray-sing-box.log"), "old log")   // not copied

	layout := paths.Layout{Bin: tempDir(t), Data: tempDir(t)}
	stopped := ""
	report, err := Run(old, layout, func(dir string) (int, error) { stopped = dir; return 2, nil })
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if stopped != old {
		t.Fatalf("old installation not stopped (got %q)", stopped)
	}

	if read(t, layout.ConfigFile()) != `{"log":{}}` || read(t, layout.Subscriptions()) != `[]` || read(t, layout.DPIParams()) != `--dpi-desync=fake` {
		t.Fatal("data files not copied")
	}
	if read(t, filepath.Join(layout.Data, "cache.db")) != "cache" {
		t.Fatal("cache.db not copied")
	}
	if read(t, filepath.Join(layout.Data, config.ConfigHistoryDir, "config-1.json")) != "{}" {
		t.Fatal("config-history not copied")
	}
	if read(t, layout.SingBoxExe()) != "MZ sing-box" || read(t, filepath.Join(layout.Bin, "libcronet.dll")) != "MZ dll" {
		t.Fatal("binary / dll not copied to Bin")
	}
	for _, name := range []string{config.AppExeName, "tray-sing-box.log"} {
		if _, err := os.Stat(filepath.Join(layout.Bin, name)); err == nil {
			t.Fatalf("%s must not be copied", name)
		}
		if _, err := os.Stat(filepath.Join(layout.Data, name)); err == nil {
			t.Fatalf("%s must not be copied", name)
		}
	}
	if len(report.Copied) != 7 || len(report.Skipped) != 0 {
		t.Fatalf("report = %+v", report)
	}

	// The source is untouched
	if read(t, filepath.Join(old, config.SingBoxConfig)) != `{"log":{}}` {
		t.Fatal("source modified")
	}
}

// Files already present in the destination are kept, not overwritten
func TestRunNeverOverwrites(t *testing.T) {
	old := tempDir(t)
	write(t, filepath.Join(old, config.SingBoxConfig), "old")
	write(t, filepath.Join(old, config.SingBoxExe), "old exe")
	layout := paths.Layout{Bin: tempDir(t), Data: tempDir(t)}
	write(t, layout.SingBoxExe(), "newer exe already here")

	report, err := Run(old, layout, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if read(t, layout.SingBoxExe()) != "newer exe already here" {
		t.Fatal("existing sing-box.exe overwritten")
	}
	if read(t, layout.ConfigFile()) != "old" {
		t.Fatal("config not copied")
	}
	if len(report.Skipped) != 1 || report.Skipped[0] != config.SingBoxExe {
		t.Fatalf("report = %+v", report)
	}
}

// A failing stop is logged, the copy still happens
func TestRunSurvivesStopFailure(t *testing.T) {
	old := tempDir(t)
	write(t, filepath.Join(old, config.SingBoxConfig), "{}")
	layout := paths.Layout{Bin: tempDir(t), Data: tempDir(t)}
	if _, err := Run(old, layout, func(string) (int, error) { return 0, os.ErrPermission }); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if read(t, layout.ConfigFile()) != "{}" {
		t.Fatal("config not copied after a stop failure")
	}
}

type fakeTask struct {
	exe               string
	off               bool // the task was disabled by the user
	enabled, disabled int
}

func (f *fakeTask) TakeoverSource() (string, bool) { return f.exe, !f.off }
func (f *fakeTask) Enable() error                  { f.enabled++; return nil }
func (f *fakeTask) Disable() error                 { f.disabled++; return nil }

func TestTakeOverCopiesThenRepointsTheTask(t *testing.T) {
	old := tempDir(t)
	write(t, filepath.Join(old, config.SingBoxConfig), `{"old":true}`)
	layout := paths.Layout{Bin: tempDir(t), Data: tempDir(t)}
	task := &fakeTask{exe: filepath.Join(old, config.AppExeName)}
	stopped := ""
	stop := func(dir string) (int, error) { stopped = dir; return 1, nil }

	report, err := TakeOver(layout, task, stop, true)
	if err != nil || report == nil {
		t.Fatalf("TakeOver = %v, %v", report, err)
	}
	if stopped != old {
		t.Fatalf("stopped %q, want the old installation %q", stopped, old)
	}
	if got := read(t, layout.ConfigFile()); got != `{"old":true}` {
		t.Fatalf("config not taken over: %q", got)
	}
	if task.enabled != 1 || task.disabled != 0 {
		t.Fatalf("carry=true must re-register the task for this exe: enabled %d, disabled %d", task.enabled, task.disabled)
	}

	// The installer variant deletes the task instead (it enables it itself
	// when the user asked for autostart)
	layout2 := paths.Layout{Bin: tempDir(t), Data: tempDir(t)}
	task2 := &fakeTask{exe: filepath.Join(old, config.AppExeName)}
	if _, err := TakeOver(layout2, task2, stop, false); err != nil {
		t.Fatal(err)
	}
	if task2.enabled != 0 || task2.disabled != 1 {
		t.Fatalf("carry=false must delete the task: enabled %d, disabled %d", task2.enabled, task2.disabled)
	}
}

func TestTakeOverLeavesTheTaskAloneWhenThereIsNothingToTake(t *testing.T) {
	stop := func(dir string) (int, error) { t.Fatalf("stop called for %s", dir); return 0, nil }

	// Configured installation: nothing to do, whatever the task says
	data := tempDir(t)
	write(t, filepath.Join(data, config.SingBoxConfig), "{}")
	configured := paths.Layout{Bin: tempDir(t), Data: data}
	task := &fakeTask{exe: filepath.Join(tempDir(t), config.AppExeName)}
	if report, err := TakeOver(configured, task, stop, true); err != nil || report != nil {
		t.Fatalf("configured: TakeOver = %v, %v", report, err)
	}

	// No task, or a task pointing at a directory without config.json
	empty := paths.Layout{Bin: tempDir(t), Data: tempDir(t)}
	for _, exe := range []string{"", filepath.Join(tempDir(t), config.AppExeName), filepath.Join(empty.Bin, config.AppExeName)} {
		task := &fakeTask{exe: exe}
		if report, err := TakeOver(empty, task, stop, true); err != nil || report != nil {
			t.Fatalf("exe %q: TakeOver = %v, %v", exe, report, err)
		}
		if task.enabled != 0 || task.disabled != 0 {
			t.Fatalf("exe %q: task touched (enabled %d, disabled %d)", exe, task.enabled, task.disabled)
		}
	}
}

func TestTakeOverKeepsTheTaskAfterAFailedCopy(t *testing.T) {
	old := tempDir(t)
	write(t, filepath.Join(old, config.SingBoxConfig), "{}")
	// A file where the data directory should be: the copy fails
	blocked := filepath.Join(tempDir(t), "data")
	write(t, blocked, "not a directory")
	layout := paths.Layout{Bin: tempDir(t), Data: blocked}
	task := &fakeTask{exe: filepath.Join(old, config.AppExeName)}
	if _, err := TakeOver(layout, task, nil, true); err == nil {
		t.Fatal("expected the copy to fail")
	}
	if task.enabled != 0 || task.disabled != 0 {
		t.Fatal("the task must stay as it is when the takeover failed: the old copy is still the working one")
	}
}

// An optional file that cannot be copied does not stop the takeover; the
// binaries and config.json still arrive and the failure is reported
func TestRunContinuesPastAnOptionalFailure(t *testing.T) {
	old2 := tempDir(t)
	write(t, filepath.Join(old2, config.SingBoxConfig), "{}")
	write(t, filepath.Join(old2, config.SingBoxExe), "exe")
	write(t, filepath.Join(old2, config.SubscriptionsFileName), "[]")
	layout2 := paths.Layout{Bin: tempDir(t), Data: tempDir(t)}
	// Source file unreadable: a directory under the subscriptions name
	os.Remove(filepath.Join(old2, config.SubscriptionsFileName))
	write(t, filepath.Join(old2, config.SubscriptionsFileName, "x"), "")

	report2, err := Run(old2, layout2, nil)
	if err != nil {
		t.Fatalf("Run with an unreadable optional file: %v", err)
	}
	if len(report2.Failed) != 1 {
		t.Fatalf("Failed = %v, want the subscriptions file", report2.Failed)
	}
	if got := read(t, layout2.ConfigFile()); got != "{}" {
		t.Fatalf("config.json not copied after an optional failure: %q", got)
	}
	if got := read(t, filepath.Join(layout2.Bin, config.SingBoxExe)); got != "exe" {
		t.Fatalf("sing-box.exe not copied: %q", got)
	}
}

// Without the binaries the takeover is not done: config.json stays behind,
// so Needed() stays true and the next start retries
func TestRunLeavesConfigForLastWhenTheBinaryFails(t *testing.T) {
	old := tempDir(t)
	write(t, filepath.Join(old, config.SingBoxConfig), "{}")
	write(t, filepath.Join(old, config.SingBoxExe), "exe")
	// A file where the binaries directory should be
	blockedBin := filepath.Join(tempDir(t), "bin")
	write(t, blockedBin, "not a directory")
	layout := paths.Layout{Bin: blockedBin, Data: tempDir(t)}

	if _, err := Run(old, layout, nil); err == nil {
		t.Fatal("expected the binary copy to fail")
	}
	if _, err := os.Stat(layout.ConfigFile()); !os.IsNotExist(err) {
		t.Fatalf("config.json must not be copied before the binaries: %v", err)
	}
	if !Needed(layout) {
		t.Fatal("a failed takeover must be retried on the next start")
	}
}

// No temporary ".part" files are left behind
func TestRunLeavesNoPartialFiles(t *testing.T) {
	old := tempDir(t)
	write(t, filepath.Join(old, config.SingBoxConfig), "{}")
	write(t, filepath.Join(old, config.SingBoxExe), "exe")
	write(t, filepath.Join(old, config.ConfigHistoryDir, "config-1.json"), "{}")
	layout := paths.Layout{Bin: tempDir(t), Data: tempDir(t)}
	if _, err := Run(old, layout, nil); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{layout.Bin, layout.Data, filepath.Join(layout.Data, config.ConfigHistoryDir)} {
		if parts, _ := filepath.Glob(filepath.Join(dir, ".*.part-*")); len(parts) != 0 {
			t.Fatalf("partial files left in %s: %v", dir, parts)
		}
	}
}

// A task the user disabled is not re-enabled for the new copy
func TestTakeOverKeepsADisabledTaskOff(t *testing.T) {
	old := tempDir(t)
	write(t, filepath.Join(old, config.SingBoxConfig), "{}")
	layout := paths.Layout{Bin: tempDir(t), Data: tempDir(t)}
	task := &fakeTask{exe: filepath.Join(old, config.AppExeName), off: true}
	if _, err := TakeOver(layout, task, nil, true); err != nil {
		t.Fatal(err)
	}
	if task.enabled != 0 || task.disabled != 1 {
		t.Fatalf("a disabled task must be deleted, not re-enabled: enabled %d, disabled %d", task.enabled, task.disabled)
	}
}

// Files the config names by a relative path come along; absolute ones and
// URL paths do not
func TestRunBringsRelativeFileReferences(t *testing.T) {
	old := tempDir(t)
	write(t, filepath.Join(old, config.SingBoxExe), "exe")
	write(t, filepath.Join(old, "ads.srs"), "rules")
	write(t, filepath.Join(old, "certs", "ca.pem"), "pem")
	write(t, filepath.Join(old, config.SingBoxConfig), `{
		"route": {"rule_set": [{"type": "local", "tag": "ads", "path": "ads.srs"}]},
		"outbounds": [
			{"type": "vless", "tag": "v", "tls": {"certificate_path": "certs\\\\ca.pem"}, "transport": {"type": "ws", "path": "/ws"}},
			{"type": "trojan", "tag": "t", "tls": {"certificate_path": "C:\\\\elsewhere\\\\x.pem"}},
			{"type": "vless", "tag": "u", "tls": {"key_path": "..\\\\outside.key"}}
		]
	}`)
	layout := paths.Layout{Bin: tempDir(t), Data: tempDir(t)}
	if _, err := Run(old, layout, nil); err != nil {
		t.Fatal(err)
	}
	if got := read(t, filepath.Join(layout.Data, "ads.srs")); got != "rules" {
		t.Fatalf("rule set not taken over: %q", got)
	}
	if got := read(t, filepath.Join(layout.Data, "certs", "ca.pem")); got != "pem" {
		t.Fatalf("certificate not taken over: %q", got)
	}
	if _, err := os.Stat(filepath.Join(layout.Data, "ws")); err == nil {
		t.Fatal("a URL path was taken for a file")
	}
}
