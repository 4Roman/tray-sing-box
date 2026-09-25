package storage

import (
	"fmt"
	"log"

	"golang.org/x/sys/windows/registry"

	"tray-sing-box/internal/config"
)

// RegistryStorage manages VPN state persistence in Windows Registry
type RegistryStorage struct {
	key string // under HKEY_CURRENT_USER; tests use a key of their own
}

// New creates a new registry storage instance
func New() *RegistryStorage {
	return &RegistryStorage{key: config.RegStateKey}
}

// SaveVPNState saves the current VPN state to registry
func (s *RegistryStorage) SaveVPNState(running bool) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, s.key, registry.SET_VALUE)
	if err != nil {
		// Try to create the key if it doesn't exist
		k, _, err = registry.CreateKey(registry.CURRENT_USER, s.key, registry.SET_VALUE)
		if err != nil {
			return fmt.Errorf("failed to create state key: %w", err)
		}
	}
	defer k.Close()

	var value uint32
	if running {
		value = 1
	} else {
		value = 0
	}

	if err := k.SetDWordValue("VPNRunning", value); err != nil {
		return fmt.Errorf("failed to save VPN state: %w", err)
	}

	log.Printf("VPN state saved: running=%v", running)
	return nil
}

// Delete removes the stored state (uninstall). A missing key is fine.
func (s *RegistryStorage) Delete() error {
	err := registry.DeleteKey(registry.CURRENT_USER, s.key)
	if err != nil && err != registry.ErrNotExist {
		return fmt.Errorf("failed to delete state key: %w", err)
	}
	return nil
}

// LoadVPNState loads the last VPN state from registry
func (s *RegistryStorage) LoadVPNState() (bool, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, s.key, registry.QUERY_VALUE)
	if err != nil {
		// Key doesn't exist, default to false
		return false, nil
	}
	defer k.Close()

	value, _, err := k.GetIntegerValue("VPNRunning")
	if err != nil {
		// Value doesn't exist, default to false
		return false, nil
	}

	// Not logged: the crash monitor reads the intent on every tick while the
	// VPN is down
	return value == 1, nil
}
