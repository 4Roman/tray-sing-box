package domain

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"
	"unicode"
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
	// ReadSection returns a section as text for display: credentials
	// (passwords, UUIDs, private keys) are replaced by a placeholder — the
	// text goes to the non-elevated browser
	ReadSection(name string) (string, error)
	// WriteSection saves a section; a placeholder kept from ReadSection gets
	// the stored credential back, but only in an outbound that is otherwise
	// unchanged — anything else must carry the real value
	WriteSection(name string, raw []byte) error
	ListOutbounds() ([]OutboundInfo, error)
	ActiveOutbound() (string, error)
	SwitchOutbound(tag string) error
	ListHistory() ([]ConfigVersion, error)
	RestoreVersion(name string) error
	// CreateConfig writes the first config of an installation that has none
	// (the store's reads then fail with ErrConfigMissing); it never replaces
	// an existing one and applies the same checks as every save
	CreateConfig(raw []byte) error
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

// Section returns the JSON text of a config section (outbounds, route) for
// display, credentials masked (see SettingsStore.ReadSection)
func (s *SettingsService) Section(name string) (string, error) {
	return s.store.ReadSection(name)
}

// SaveSection validates and stores new JSON for a config section, then
// restarts the VPN if it is running.
func (s *SettingsService) SaveSection(name string, raw []byte) (restarted bool, err error) {
	if err := s.store.WriteSection(name, raw); err != nil {
		logRefused(fmt.Sprintf("section %q", name), err)
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
		logRefused(fmt.Sprintf("switch to %q", tag), err)
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

// CreateConfig stores the first config.json of an installation that has
// none. Like every repair made through the app it goes through
// RestartIfRunning: with the VPN down that gives the monitor a fresh budget,
// so an intent "running" that gave up on the missing config is picked up
// again. Otherwise the VPN is the user's to start.
func (s *SettingsService) CreateConfig(raw []byte) error {
	if err := s.store.CreateConfig(raw); err != nil {
		logRefused("initial config.json", err)
		return err
	}
	log.Printf("Settings: initial config.json created")
	if _, err := s.vpn.RestartIfRunning(); err != nil {
		return fmt.Errorf("config.json сохранён, но VPN %w", err)
	}
	return nil
}

// History returns the archived config versions, newest first
func (s *SettingsService) History() ([]ConfigVersion, error) {
	return s.store.ListHistory()
}

// Rollback replaces the current config with an archived version and
// restarts the VPN if it is running.
func (s *SettingsService) Rollback(name string) (restarted bool, err error) {
	if err := s.store.RestoreVersion(name); err != nil {
		logRefused(fmt.Sprintf("rollback to %q", name), err)
		return false, err
	}
	log.Printf("Settings: config rolled back to %q", name)

	restarted, err = s.vpn.RestartIfRunning()
	if err != nil {
		return false, fmt.Errorf("конфиг восстановлен, но VPN %w", err)
	}
	return restarted, nil
}

// logRefused records a config change that was not made. The settings page
// shows the reason, but the page is reachable by any program of the user: the
// log (next to the config, administrators only when installed) keeps a trace
// of refused attempts, e.g. items the guard does not accept. The reasons name
// items, never their values (the page gets the same text). They are written
// on one line: a key name in a reason comes from the refused config, and a
// line break in it would forge log lines.
func logRefused(what string, err error) {
	log.Printf("Settings: %s not saved: %s", what, oneLine(err.Error()))
}

// oneLine replaces control characters (line breaks above all) with their
// quoted form
func oneLine(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsControl(r) {
			b.WriteString(strconv.QuoteRune(r))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
