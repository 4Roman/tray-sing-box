package configfile

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tray-sing-box/internal/config"
)

func historyFiles(t *testing.T, configPath string) []string {
	t.Helper()
	dir := filepath.Join(filepath.Dir(configPath), config.ConfigHistoryDir)
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestSaveArchivesPreviousVersion(t *testing.T) {
	editor, path := newSyncEditor(t)

	if err := editor.AddOutbound(map[string]any{"type": "vless", "tag": "new-node", "server": "n.example.com"}); err != nil {
		t.Fatalf("AddOutbounds: %v", err)
	}

	names := historyFiles(t, path)
	if len(names) != 1 {
		t.Fatalf("want 1 archived version, got %v", names)
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(path), config.ConfigHistoryDir, names[0]))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "new-node") {
		t.Fatal("archive must hold the PRE-save config")
	}
	if !strings.Contains(string(raw), "sub-a") {
		t.Fatal("archive does not look like the previous config")
	}
}

func TestListHistoryAndRestore(t *testing.T) {
	editor, path := newSyncEditor(t)

	// Two saves -> two archived versions
	if err := editor.AddOutbound(map[string]any{"type": "vless", "tag": "v1", "server": "1.example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := editor.AddOutbound(map[string]any{"type": "vless", "tag": "v2", "server": "2.example.com"}); err != nil {
		t.Fatal(err)
	}

	versions, err := editor.ListHistory()
	if err != nil {
		t.Fatalf("ListHistory: %v", err)
	}
	if len(versions) != 2 {
		t.Fatalf("want 2 versions, got %+v", versions)
	}

	// The oldest archive (index 1, list is newest first) has neither v1 nor v2
	if err := editor.RestoreVersion(versions[1].Name); err != nil {
		t.Fatalf("RestoreVersion: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "\"v1\"") || strings.Contains(string(raw), "\"v2\"") {
		t.Fatalf("rollback did not restore the old config:\n%s", raw)
	}

	// The rollback itself was archived: one more version than before
	versions, err = editor.ListHistory()
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 3 {
		t.Fatalf("rollback must be archived too, got %d versions", len(versions))
	}
}

func TestRestoreVersionRejectsBadNames(t *testing.T) {
	editor, _ := newSyncEditor(t)
	for _, name := range []string{
		"../config.json",
		"config-20260612-193045.json.exe",
		"..\\..\\windows\\system32\\evil",
		"nope.json",
	} {
		if err := editor.RestoreVersion(name); err == nil {
			t.Fatalf("name %q must be rejected", name)
		}
	}
}

func TestHistoryPruning(t *testing.T) {
	editor, path := newSyncEditor(t)

	for i := 0; i < config.ConfigHistoryKeep+5; i++ {
		out := map[string]any{"type": "vless", "tag": "n", "server": fmt.Sprintf("s%d.example.com", i)}
		if err := editor.AddOutbound(out); err != nil {
			t.Fatal(err)
		}
	}

	names := historyFiles(t, path)
	if len(names) != config.ConfigHistoryKeep {
		t.Fatalf("history not pruned: %d files, want %d", len(names), config.ConfigHistoryKeep)
	}
}
