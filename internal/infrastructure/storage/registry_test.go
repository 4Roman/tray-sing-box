package storage

import (
	"fmt"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/windows/registry"

	"tray-sing-box/internal/config"
)

// testStorage works on a key of its own: the real one holds the intent of
// the VPN of whoever runs the tests
func testStorage(t *testing.T) *RegistryStorage {
	t.Helper()
	key := fmt.Sprintf(`Software\SingBoxTray-test-%d-%d`, os.Getpid(), time.Now().UnixNano())
	if key == config.RegStateKey {
		t.Fatal("the test would use the real state key")
	}
	t.Cleanup(func() { _ = registry.DeleteKey(registry.CURRENT_USER, key) })
	return &RegistryStorage{key: key}
}

func TestNewUsesTheStateKey(t *testing.T) {
	if New().key != config.RegStateKey {
		t.Fatalf("New() stores under %q, want %q", New().key, config.RegStateKey)
	}
}

func TestIntentRoundTrip(t *testing.T) {
	s := testStorage(t)

	// Nothing stored yet: "stopped", not an error (first run)
	if running, err := s.LoadVPNState(); err != nil || running {
		t.Fatalf("missing key: %v, %v", running, err)
	}
	for _, want := range []bool{true, false, true} {
		if err := s.SaveVPNState(want); err != nil {
			t.Fatalf("save %v: %v", want, err)
		}
		if got, err := s.LoadVPNState(); err != nil || got != want {
			t.Fatalf("after saving %v: loaded %v, %v", want, got, err)
		}
	}

	// The stored value is the DWORD the installer and older builds read
	k, err := registry.OpenKey(registry.CURRENT_USER, s.key, registry.QUERY_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	v, typ, err := k.GetIntegerValue("VPNRunning")
	k.Close()
	if err != nil || typ != registry.DWORD || v != 1 {
		t.Fatalf("VPNRunning = %d (type %d), %v", v, typ, err)
	}
}

func TestDeleteRemovesTheIntent(t *testing.T) {
	s := testStorage(t)
	if err := s.SaveVPNState(true); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := registry.OpenKey(registry.CURRENT_USER, s.key, registry.QUERY_VALUE); err != registry.ErrNotExist {
		t.Fatalf("key still there after Delete: %v", err)
	}
	if running, err := s.LoadVPNState(); err != nil || running {
		t.Fatalf("after delete: %v, %v", running, err)
	}
	// Deleting again (uninstall run twice) is fine
	if err := s.Delete(); err != nil {
		t.Fatalf("second delete: %v", err)
	}
}
