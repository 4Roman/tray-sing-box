package domain

import (
	"errors"
	"fmt"
	"log"

	"tray-sing-box/internal/config"
)

// ContainerState mirrors the Docker container lifecycle for status display.
type ContainerState string

const (
	ContainerAbsent  ContainerState = "absent"
	ContainerStopped ContainerState = "stopped"
	ContainerRunning ContainerState = "running"
)

// DPIBypassManager manages the zapret DPI-bypass Docker container.
type DPIBypassManager interface {
	Available() error
	State() (ContainerState, error)
	Start() error
	Stop() error
	ProxyAddr() (host string, port int)
}

// BypassConfigStore is the config-editing surface needed for DPI bypass.
type BypassConfigStore interface {
	EnsureBypassOutbound(tag, server string, port int) error
	SetDetour(targetTag, detourTag string) error
	ClearDetour(detourTag string) error
	DetourTargets(detourTag string) ([]string, error)
	RouteReferences(tag string) (bool, error)
	ActiveOutbound() (string, error)
	OutboundType(tag string) (string, error)
}

// DPIBypassStatus reports the bypass state for tray/webui display.
type DPIBypassStatus struct {
	DockerOK    bool           `json:"docker"`
	Container   ContainerState `json:"container"`
	ChainActive bool           `json:"chain"`       // mode A: an outbound detours via dpi-bypass
	ChainTarget string         `json:"chainTarget"` // which outbound is chained
	DirectInUse bool           `json:"direct"`      // mode B: routing points at dpi-bypass
	Restarted   bool           `json:"restarted"`   // whether the VPN was restarted
}

// udpOutboundTypes can't be tunneled through an HTTP CONNECT proxy, so they
// cannot be chained (mode A) through the zapret HTTP proxy.
var udpOutboundTypes = map[string]bool{
	"hysteria2": true, "hysteria": true, "tuic": true, "wireguard": true,
}

// DPIBypassService wires the zapret container and the sing-box config together.
type DPIBypassService struct {
	manager DPIBypassManager
	store   BypassConfigStore
	vpn     *VPNService
}

// NewDPIBypassService creates a new DPI-bypass service.
func NewDPIBypassService(m DPIBypassManager, store BypassConfigStore, vpn *VPNService) *DPIBypassService {
	return &DPIBypassService{manager: m, store: store, vpn: vpn}
}

// Status reports the current bypass state. Docker calls take 100-300 ms, so
// callers should keep this off latency-sensitive paths (tray startup, /api/config).
func (s *DPIBypassService) Status() (*DPIBypassStatus, error) {
	st := &DPIBypassStatus{Container: ContainerAbsent}

	if err := s.manager.Available(); err == nil {
		st.DockerOK = true
		if state, err := s.manager.State(); err == nil {
			st.Container = state
		}
	}

	targets, err := s.store.DetourTargets(config.DPIBypassTag)
	if errors.Is(err, ErrConfigMissing) {
		// No config yet: nothing is wired, the Docker state is still news
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	if len(targets) > 0 {
		st.ChainActive = true
		st.ChainTarget = targets[0]
	}

	direct, err := s.store.RouteReferences(config.DPIBypassTag)
	if err != nil {
		return nil, err
	}
	st.DirectInUse = direct

	return st, nil
}

// EnableChain routes the active proxy outbound through the zapret container
// (mode A): start the container, ensure the dpi-bypass outbound, add a detour
// on the active proxy, then restart the VPN if it is running.
func (s *DPIBypassService) EnableChain() (*DPIBypassStatus, error) {
	if err := s.manager.Available(); err != nil {
		return nil, err
	}

	active, err := s.store.ActiveOutbound()
	if err != nil {
		return nil, withSetupHint(err)
	}
	if active == "" {
		return nil, fmt.Errorf("активный прокси-сервер не выбран — сначала выберите сервер")
	}
	if active == config.DPIBypassTag {
		return nil, fmt.Errorf("активен сам обход DPI — выберите VPN-сервер")
	}
	typ, err := s.store.OutboundType(active)
	if err != nil {
		return nil, err
	}
	if udpOutboundTypes[typ] {
		return nil, fmt.Errorf("активный сервер «%s» использует %s (UDP) — обход DPI через HTTP-прокси работает только с TCP-серверами (vless/trojan/vmess)", active, typ)
	}

	// Start the container before editing the config so a restarted sing-box
	// never points at a dead proxy.
	if err := s.manager.Start(); err != nil {
		return nil, fmt.Errorf("не удалось запустить контейнер обхода DPI: %w", err)
	}

	host, port := s.manager.ProxyAddr()
	if err := s.store.EnsureBypassOutbound(config.DPIBypassTag, host, port); err != nil {
		return nil, err
	}
	if err := s.store.SetDetour(active, config.DPIBypassTag); err != nil {
		return nil, err
	}

	restarted, err := s.vpn.RestartIfRunning()
	if err != nil {
		return nil, fmt.Errorf("обход DPI включён, но VPN %w", err)
	}

	log.Printf("DPI bypass chain enabled: %q -> %s", active, config.DPIBypassTag)
	return s.statusWithRestart(restarted)
}

// DisableChain removes the detour (mode A) and stops the container unless mode
// B still routes through it, then restarts the VPN if it is running.
func (s *DPIBypassService) DisableChain() (*DPIBypassStatus, error) {
	if err := s.store.ClearDetour(config.DPIBypassTag); err != nil {
		return nil, err
	}

	directInUse, err := s.store.RouteReferences(config.DPIBypassTag)
	if err != nil {
		return nil, err
	}
	if !directInUse {
		if err := s.manager.Stop(); err != nil {
			log.Printf("DPI bypass: failed to stop container (ignored): %v", err)
		}
	}

	restarted, err := s.vpn.RestartIfRunning()
	if err != nil {
		return nil, fmt.Errorf("обход DPI выключен, но VPN %w", err)
	}

	log.Printf("DPI bypass chain disabled")
	return s.statusWithRestart(restarted)
}

// EnableDirect prepares mode B: start the container and ensure the dpi-bypass
// outbound exists. The caller then routes traffic to it via the existing
// "switch active outbound" mechanism.
func (s *DPIBypassService) EnableDirect() (*DPIBypassStatus, error) {
	if err := s.manager.Available(); err != nil {
		return nil, err
	}
	// The config must be there before a privileged container is started for it
	if _, err := s.store.ActiveOutbound(); err != nil {
		return nil, withSetupHint(err)
	}
	if err := s.manager.Start(); err != nil {
		return nil, fmt.Errorf("не удалось запустить контейнер обхода DPI: %w", err)
	}
	host, port := s.manager.ProxyAddr()
	if err := s.store.EnsureBypassOutbound(config.DPIBypassTag, host, port); err != nil {
		return nil, err
	}
	log.Printf("DPI bypass outbound ready for direct use")
	return s.Status()
}

// ToggleChain flips mode A on or off (drives the tray checkbox).
func (s *DPIBypassService) ToggleChain() (*DPIBypassStatus, error) {
	st, err := s.Status()
	if err != nil {
		return nil, err
	}
	if st.ChainActive {
		return s.DisableChain()
	}
	return s.EnableChain()
}

// statusWithRestart returns the current status stamped with the restart flag.
func (s *DPIBypassService) statusWithRestart(restarted bool) (*DPIBypassStatus, error) {
	st, err := s.Status()
	if err != nil {
		return nil, err
	}
	st.Restarted = restarted
	return st, nil
}
