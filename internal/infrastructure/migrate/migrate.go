// Package migrate takes over a previous portable installation when the app
// runs installed for the first time (see paths): the user's config,
// subscriptions and history move to the data directory, sing-box.exe to
// the binaries directory, and the old copy's processes are stopped so the
// new installation can start its own sing-box without a port/TUN conflict.
// The source directory is never modified.
package migrate

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"tray-sing-box/internal/config"
	"tray-sing-box/internal/infrastructure/paths"
)

// dataFiles are copied to the data directory (missing ones are skipped)
var dataFiles = []string{
	config.SingBoxConfig,
	config.SubscriptionsFileName,
	config.DPIParamsFileName,
	"cache.db", // sing-box's cache: rule sets, selector choice
}

// dataDirs are copied recursively to the data directory
var dataDirs = []string{config.ConfigHistoryDir}

// Report says what was taken over
type Report struct {
	From    string
	Copied  []string // relative names
	Skipped []string // present in the destination already
	Failed  []string // optional files that could not be copied ("name: error")
}

// Task is what the takeover needs from the autostart task: where the
// previous installation is (only a task that can be trusted with that — see
// autostart.Scheduler.TakeoverSource), and the task's fate afterwards
type Task interface {
	TakeoverSource() (exe string, enabled bool)
	Enable() error
	Disable() error
}

// TakeOver is the whole first-run takeover: when the installed layout has no
// configuration yet and the autostart task launches another installation
// with one, that installation is ended (stop), its files are copied (Run)
// and the task — which would otherwise revive the old copy at the next
// logon — is re-registered for this exe (carry: the app took over by
// itself) or deleted (the installer decides about autostart right after).
// Returns nil, nil when there was nothing to take over.
func TakeOver(layout paths.Layout, task Task, stop func(dir string) (int, error), carry bool) (*Report, error) {
	if !Needed(layout) {
		return nil, nil
	}
	exe, enabled := task.TakeoverSource()
	from, ok := Source(exe, layout)
	if !ok {
		return nil, nil
	}
	report, err := Run(from, layout, stop)
	if err != nil {
		return report, err
	}
	// A task the user had disabled is not revived for the new copy: it is
	// deleted (the copy's own checkbox re-creates it on request)
	if carry && enabled {
		err = task.Enable()
	} else {
		err = task.Disable()
	}
	if err != nil {
		return report, fmt.Errorf("autostart task after the takeover: %w", err)
	}
	return report, nil
}

// Needed reports whether an installed layout still has no configuration —
// the only time a takeover is considered
func Needed(layout paths.Layout) bool {
	if layout.Portable {
		return false
	}
	_, err := os.Stat(layout.ConfigFile())
	return os.IsNotExist(err)
}

// Source returns the directory of a previous installation worth taking over:
// the one the autostart task launches, when it is another directory with a
// config.json in it
func Source(registeredExe string, layout paths.Layout) (string, bool) {
	if registeredExe == "" {
		return "", false
	}
	dir := filepath.Dir(registeredExe)
	if strings.EqualFold(filepath.Clean(dir), filepath.Clean(layout.Bin)) {
		return "", false
	}
	if _, err := os.Stat(filepath.Join(dir, config.SingBoxConfig)); err != nil {
		return "", false
	}
	return dir, true
}

// Run copies the files of the installation in from into layout. stop ends
// the old copy's processes first (nil to skip); its failure is logged, not
// fatal — the copy is still worth having.
func Run(from string, layout paths.Layout, stop func(dir string) (int, error)) (*Report, error) {
	report := &Report{From: from}
	log.Printf("Taking over the previous installation in %s", from)

	if stop != nil {
		if n, err := stop(from); err != nil {
			log.Printf("Warning: could not stop the previous installation completely: %v", err)
		} else if n > 0 {
			log.Printf("Stopped %d process(es) of the previous installation", n)
		}
	}

	// Order matters: Needed() keys on config.json, so it is copied LAST and
	// only when the binaries made it. A failure before that point leaves the
	// installation "not configured" and the takeover is retried on the next
	// start (copyIfMissing skips what is already there); a failure after it
	// would be final. So: binaries first (fatal — without sing-box.exe the
	// copy is useless and nothing else recreates a cronet DLL), then the
	// optional data (logged, not fatal), then config.json (fatal).

	// The binary and any DLLs next to it (a cronet-enabled build ships one)
	entries, err := os.ReadDir(from)
	if err != nil {
		return report, err
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !(strings.EqualFold(name, config.SingBoxExe) || strings.EqualFold(filepath.Ext(name), ".dll")) {
			continue
		}
		if err := copyIfMissing(filepath.Join(from, name), filepath.Join(layout.Bin, name), report, name); err != nil {
			return report, err
		}
	}

	for _, name := range dataFiles {
		if name == config.SingBoxConfig {
			continue
		}
		if err := copyIfMissing(filepath.Join(from, name), filepath.Join(layout.Data, name), report, name); err != nil {
			report.Failed = append(report.Failed, err.Error())
		}
	}
	for _, name := range dataDirs {
		if err := copyDirIfMissing(filepath.Join(from, name), filepath.Join(layout.Data, name), report, name); err != nil {
			report.Failed = append(report.Failed, err.Error())
		}
	}

	// Files the config names by a relative path (local rule sets, certificate
	// and key files, the cache) resolve against sing-box's working directory
	// — the data dir now, the old folder before: they come along. Absolute
	// ones keep pointing at the old folder, which is usually writable without
	// elevation: logged, for the user to move into the data dir.
	refs, absolute := configFileRefs(filepath.Join(from, config.SingBoxConfig))
	for _, ref := range refs {
		if err := copyIfMissing(filepath.Join(from, ref), filepath.Join(layout.Data, ref), report, ref); err != nil {
			report.Failed = append(report.Failed, err.Error())
		}
	}
	for _, ref := range absolute {
		log.Printf("Warning: the taken-over config uses %s outside the protected data directory %s — move it there and use a relative path", ref, layout.Data)
	}

	if err := copyIfMissing(filepath.Join(from, config.SingBoxConfig), layout.ConfigFile(), report, config.SingBoxConfig); err != nil {
		return report, err
	}

	log.Printf("Takeover finished: copied %v, skipped %v, failed %v", report.Copied, report.Skipped, report.Failed)
	return report, nil
}

// fileRefKeys name files a sing-box config reads (the takeover copies them)
var fileRefKeys = map[string]bool{
	"path": true, "certificate_path": true, "key_path": true, "private_key_path": true,
	"client_certificate_path": true, "client_key_path": true, "config_path": true,
}

// configFileRefs returns the file references of the config at path:
// relative ones inside its folder (filepath.IsLocal) and absolute ones.
// transport.path is a URL path, not a file.
func configFileRefs(path string) (relative, absolute []string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil
	}
	var cfg any
	if json.Unmarshal(raw, &cfg) != nil {
		return nil, nil
	}
	seen := map[string]bool{}
	var walk func(v any, parent string)
	walk = func(v any, parent string) {
		switch x := v.(type) {
		case map[string]any:
			for k, child := range x {
				key := strings.ToLower(k)
				if s, ok := child.(string); ok && fileRefKeys[key] && parent != "transport" && parent != "outbounds" && s != "" && !seen[s] {
					seen[s] = true
					if filepath.IsAbs(s) || filepath.VolumeName(s) != "" {
						absolute = append(absolute, s)
					} else if filepath.IsLocal(s) {
						relative = append(relative, filepath.Clean(s))
					}
					continue
				}
				walk(child, key)
			}
		case []any:
			for _, child := range x {
				walk(child, parent)
			}
		}
	}
	walk(cfg, "")
	return relative, absolute
}

func copyIfMissing(src, dst string, report *Report, name string) error {
	if _, err := os.Stat(src); err != nil {
		return nil // nothing to take
	}
	if _, err := os.Stat(dst); err == nil {
		report.Skipped = append(report.Skipped, name)
		return nil
	}
	if err := copyFile(src, dst); err != nil {
		return fmt.Errorf("copy %s: %w", name, err)
	}
	report.Copied = append(report.Copied, name)
	return nil
}

func copyDirIfMissing(src, dst string, report *Report, name string) error {
	info, err := os.Stat(src)
	if err != nil || !info.IsDir() {
		return nil
	}
	if _, err := os.Stat(dst); err == nil {
		report.Skipped = append(report.Skipped, name)
		return nil
	}
	if err := copyDir(src, dst); err != nil {
		return fmt.Errorf("copy %s: %w", name, err)
	}
	report.Copied = append(report.Copied, name)
	return nil
}

func copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0755)
		}
		return copyFile(path, target)
	})
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	// Written under a temporary name and linked into place without
	// replacing anything: a destination that exists is always complete.
	// Two starts may take over at the same time (the takeover runs before
	// the single-instance mutex); the loser's link fails and counts as done.
	tmp, err := os.CreateTemp(filepath.Dir(dst), "."+filepath.Base(dst)+".part-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Link(tmpPath, dst); err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil
		}
		// A volume without hard links: rename, still never over a file
		if _, statErr := os.Stat(dst); statErr == nil {
			return nil
		}
		return os.Rename(tmpPath, dst)
	}
	return nil
}
