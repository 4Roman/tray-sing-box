package domain

// VPNStatus represents the current state of VPN
type VPNStatus int

const (
	VPNStatusStopped VPNStatus = iota
	VPNStatusRunning
	// VPNStatusStarting: the process is down, but the user wants the VPN on
	// and the app is still working on it (startup restore, auto-restart after
	// a crash). The UI shows it as "starting" and offers "stop", so the user
	// can call the attempts off.
	VPNStatusStarting
)

func (s VPNStatus) IsRunning() bool {
	return s == VPNStatusRunning
}

// IsStarting reports whether the app is still trying to bring the VPN up
func (s VPNStatus) IsStarting() bool {
	return s == VPNStatusStarting
}

func (s VPNStatus) String() string {
	switch s {
	case VPNStatusRunning:
		return "running"
	case VPNStatusStarting:
		return "starting"
	default:
		return "stopped"
	}
}
