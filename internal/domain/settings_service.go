package domain

import (
	"fmt"
	"log"
	"time"
)

// OutboundInfo describes a configured outbound for UI listing
type OutboundInfo struct {
	Tag  string `json:"tag"`
	Type string `json:"type"`
}

// ConfigVersion describes one archived config.json version
type ConfigVersion struct {
	Name  string    `json:"name"`
	Saved time.Time `json:"saved"`
	Size  int64     `json:"size"`
}

// SettingsStore reads and edits sections of the sing-box configuration
type SettingsStore interface {
	ReadSection(name string) (string, error)
	WriteSection(name string, raw []byte) error
	ListOutbounds() ([]OutboundInfo, error)
	ActiveOutbound() (string, error)
	SwitchOutbound(tag string) error
	ListHistory() ([]ConfigVersion, error)
	RestoreVersion(name string) error
}

// SettingsService exposes configuration editing to the UI and applies
// changes by restarting the VPN when it is running.
type SettingsService struct {
	store SettingsStore
	vpn   *VPNService
}

// NewSettingsService creates a new settings service
func NewSettingsService(store SettingsStore, vpn *VPNService) *SettingsService {
	return &SettingsService{store: store, vpn: vpn}
}

// Section returns the JSON text of a config section (outbounds, route)
func (s *SettingsService) Section(name string) (string, error) {
	return s.store.ReadSection(name)
}

// SaveSection validates and stores new JSON for a config section, then
// restarts the VPN if it is running.
func (s *SettingsService) SaveSection(name string, raw []byte) (restarted bool, err error) {
	if err := s.store.WriteSection(name, raw); err != nil {
		return false, err
	}
	log.Printf("Settings: section %q saved", name)

	restarted, err = s.vpn.RestartIfRunning()
	if err != nil {
		return false, fmt.Errorf("section saved, but VPN %w", err)
	}
	return restarted, nil
}

// Outbounds returns the configured outbounds and the currently active tag
func (s *SettingsService) Outbounds() ([]OutboundInfo, string, error) {
	list, err := s.store.ListOutbounds()
	if err != nil {
		return nil, "", err
	}
	active, err := s.store.ActiveOutbound()
	if err != nil {
		return nil, "", err
	}
	return list, active, nil
}

// UseOutbound routes traffic through the given outbound and restarts the
// VPN if it is running.
func (s *SettingsService) UseOutbound(tag string) (restarted bool, err error) {
	if err := s.store.SwitchOutbound(tag); err != nil {
		return false, err
	}
	log.Printf("Settings: switched active outbound to %q", tag)

	restarted, err = s.vpn.RestartIfRunning()
	if err != nil {
		return false, fmt.Errorf("outbound switched, but VPN %w", err)
	}
	return restarted, nil
}

// IsVPNRunning reports the current VPN status for UI display
func (s *SettingsService) IsVPNRunning() bool {
	return s.VPNStatus().IsRunning()
}

// VPNStatus reports the current VPN status, including "starting"
func (s *SettingsService) VPNStatus() VPNStatus {
	return s.vpn.GetStatus()
}

// SetVPN turns the VPN on or off on the user's request (same as the tray
// toggle: an explicit action that records the intent)
func (s *SettingsService) SetVPN(running bool) error {
	if running {
		return s.vpn.Start()
	}
	return s.vpn.Stop()
}

// History returns the archived config versions, newest first
func (s *SettingsService) History() ([]ConfigVersion, error) {
	return s.store.ListHistory()
}

// Rollback replaces the current config with an archived version and
// restarts the VPN if it is running.
func (s *SettingsService) Rollback(name string) (restarted bool, err error) {
	if err := s.store.RestoreVersion(name); err != nil {
		return false, err
	}
	log.Printf("Settings: config rolled back to %q", name)

	restarted, err = s.vpn.RestartIfRunning()
	if err != nil {
		return false, fmt.Errorf("конфиг восстановлен, но VPN %w", err)
	}
	return restarted, nil
}
