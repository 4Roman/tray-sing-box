package domain

// VPNStatus represents the current state of VPN
type VPNStatus int

const (
	VPNStatusStopped VPNStatus = iota
	VPNStatusRunning
)

func (s VPNStatus) IsRunning() bool {
	return s == VPNStatusRunning
}
