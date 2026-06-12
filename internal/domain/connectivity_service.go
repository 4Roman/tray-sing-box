package domain

import (
	"log"
	"sync"
	"time"
)

// ConnectivityProber sends a tiny request (optionally through the local
// sing-box inbound proxy) and returns nil when the internet is reachable
// (implemented by infrastructure/connectivity)
type ConnectivityProber func(proxyURL string) error

// ProxyURLSource finds a local inbound proxy in the config to probe through
// (implemented by configfile.Editor; "" means probe directly, e.g. TUN mode)
type ProxyURLSource interface {
	LocalProxyURL() (string, error)
}

// ConnectivityStatus is the latest connectivity verdict
type ConnectivityStatus struct {
	Checked bool      `json:"checked"` // a verdict exists (VPN running long enough)
	OK      bool      `json:"ok"`
	At      time.Time `json:"at"`
}

// connectivityFailThreshold is how many consecutive probe failures it takes
// to flip the verdict to "no connectivity" — a single lost probe (one bad
// request, a server hiccup) must not flap the status.
const connectivityFailThreshold = 2

// ConnectivityService periodically verifies that traffic actually flows
// while the VPN is running. "Process alive" does not imply "tunnel works":
// a dead upstream server keeps the icon green forever otherwise.
type ConnectivityService struct {
	probe  ConnectivityProber
	config ProxyURLSource
	vpn    *VPNService

	mu       sync.Mutex
	status   ConnectivityStatus
	failures int
}

// NewConnectivityService creates a new connectivity service
func NewConnectivityService(probe ConnectivityProber, config ProxyURLSource, vpn *VPNService) *ConnectivityService {
	return &ConnectivityService{probe: probe, config: config, vpn: vpn}
}

// Check runs one probe and returns the (possibly debounced) verdict.
// When the VPN is stopped the verdict resets to "unchecked".
func (s *ConnectivityService) Check() ConnectivityStatus {
	if !s.vpn.GetStatus().IsRunning() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.status = ConnectivityStatus{}
		s.failures = 0
		return s.status
	}

	proxyURL, err := s.config.LocalProxyURL()
	if err != nil {
		log.Printf("Connectivity: failed to find a local proxy inbound: %v", err)
		proxyURL = "" // fall back to a direct probe
	}

	probeErr := s.probe(proxyURL)

	s.mu.Lock()
	defer s.mu.Unlock()

	if probeErr == nil {
		if s.status.Checked && !s.status.OK {
			log.Printf("Connectivity restored")
		}
		s.failures = 0
		s.status = ConnectivityStatus{Checked: true, OK: true, At: time.Now()}
		return s.status
	}

	s.failures++
	log.Printf("Connectivity probe failed (%d/%d): %v", s.failures, connectivityFailThreshold, probeErr)
	if s.failures >= connectivityFailThreshold {
		s.status = ConnectivityStatus{Checked: true, OK: false, At: time.Now()}
	}
	// Below the threshold the previous verdict stands (or stays unchecked)
	return s.status
}

// Status returns the latest verdict without probing
func (s *ConnectivityService) Status() ConnectivityStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}
