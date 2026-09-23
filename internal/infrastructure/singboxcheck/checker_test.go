//go:build windows

package singboxcheck

import (
	"os"
	"path/filepath"
	"testing"

	"tray-sing-box/internal/infrastructure/configfile"
)

// Integration against a real sing-box installation. Enabled by pointing
// SINGBOX_REAL_DIR at a directory with sing-box.exe and config.json; the
// real config is only read, all edits happen on a temp copy.
func realDir(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("SINGBOX_REAL_DIR")
	if dir == "" {
		t.Skip("SINGBOX_REAL_DIR not set")
	}
	// Read-only on the real installation: the scratch config goes elsewhere
	scratch := t.TempDir()
	old := scratchDir
	scratchDir = func(string) string { return scratch }
	t.Cleanup(func() { scratchDir = old })
	if _, err := os.Stat(filepath.Join(dir, "sing-box.exe")); err != nil {
		t.Skipf("sing-box.exe not found in %s", dir)
	}
	return dir
}

func TestValidatorAcceptsRealConfig(t *testing.T) {
	dir := realDir(t)
	raw, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Skipf("config.json not readable: %v", err)
	}

	if err := NewValidator(dir, dir)(raw); err != nil {
		t.Fatalf("real config rejected: %v", err)
	}
}

func TestValidatorRejectsBrokenConfig(t *testing.T) {
	dir := realDir(t)

	err := NewValidator(dir, dir)([]byte(`{"outbounds": [{"type": "no-such-type", "tag": "x"}]}`))
	if err == nil {
		t.Fatal("broken config accepted by validator")
	}
	t.Logf("validator error (expected): %v", err)
}

// Switching the active outbound on a copy of the real config must produce
// a config the real sing-box accepts.
func TestSwitchOutboundOnRealConfigCopy(t *testing.T) {
	dir := realDir(t)
	raw, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Skipf("config.json not readable: %v", err)
	}

	copyPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(copyPath, raw, 0644); err != nil {
		t.Fatal(err)
	}

	editor := configfile.New(copyPath)
	editor.SetValidator(NewValidator(dir, dir))

	list, err := editor.ListOutbounds()
	if err != nil {
		t.Fatalf("ListOutbounds: %v", err)
	}
	if len(list) == 0 {
		t.Skip("no outbounds in real config")
	}

	// Pick a proxy outbound that is not currently active
	active, _ := editor.ActiveOutbound()
	var target string
	for _, o := range list {
		if o.Type != "direct" && o.Type != "block" && o.Type != "dns" &&
			o.Type != "selector" && o.Type != "urltest" && o.Tag != active {
			target = o.Tag
			break
		}
	}
	if target == "" {
		t.Skip("no alternative proxy outbound to switch to")
	}

	// save() runs the real `sing-box check` via the validator
	if err := editor.SwitchOutbound(target); err != nil {
		t.Fatalf("SwitchOutbound(%q): %v", target, err)
	}

	newActive, err := editor.ActiveOutbound()
	if err != nil {
		t.Fatalf("ActiveOutbound: %v", err)
	}
	if newActive != target {
		t.Fatalf("active = %q, want %q", newActive, target)
	}
	t.Logf("switched %q -> %q, real sing-box check passed", active, target)
}
