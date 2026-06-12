package domain

import (
	"fmt"
	"log"
	"sync"
	"time"

	"tray-sing-box/internal/config"
)

// ProcessManager interface for managing VPN process
type ProcessManager interface {
	Start() error
	Stop() error
	IsRunning() bool
}

// Storage interface for persisting VPN state
type Storage interface {
	SaveVPNState(running bool) error
	LoadVPNState() (bool, error)
}

// VPNService manages VPN business logic
type VPNService struct {
	processManager ProcessManager
	storage        Storage
	statusChangeCh chan VPNStatus

	// OnAutoRestartFailed, when set before StartMonitoring, is called once
	// per crash loop after the monitor gives up auto-restarting sing-box
	OnAutoRestartFailed func(err error)

	restartMu    sync.Mutex
	autoRestarts int       // consecutive crash auto-restart attempts
	gaveUp       bool      // already reported the exhausted crash loop
	runningSince time.Time // observed running continuously since
}

// NewVPNService creates a new VPN service instance
func NewVPNService(pm ProcessManager, storage Storage) *VPNService {
	return &VPNService{
		processManager: pm,
		storage:        storage,
		statusChangeCh: make(chan VPNStatus, 1),
	}
}

// Start starts the VPN
func (s *VPNService) Start() error {
	log.Printf("=== VPNService.Start called ===")

	if err := s.processManager.Start(); err != nil {
		return fmt.Errorf("failed to start VPN: %w", err)
	}

	if err := s.storage.SaveVPNState(true); err != nil {
		log.Printf("Warning: failed to save VPN state: %v", err)
	}

	s.notifyStatusChange(VPNStatusRunning)
	return nil
}

// Stop stops the VPN
func (s *VPNService) Stop() error {
	log.Printf("=== VPNService.Stop called ===")

	if err := s.processManager.Stop(); err != nil {
		return fmt.Errorf("failed to stop VPN: %w", err)
	}

	if err := s.storage.SaveVPNState(false); err != nil {
		log.Printf("Warning: failed to save VPN state: %v", err)
	}

	s.notifyStatusChange(VPNStatusStopped)
	return nil
}

// RestartIfRunning restarts the VPN when it is running (e.g. to apply a
// config change) and reports whether a restart happened.
func (s *VPNService) RestartIfRunning() (bool, error) {
	if !s.GetStatus().IsRunning() {
		return false, nil
	}
	log.Printf("Restarting VPN to apply configuration changes")
	if err := s.Stop(); err != nil {
		return false, fmt.Errorf("restart failed on stop: %w", err)
	}
	if err := s.Start(); err != nil {
		return false, fmt.Errorf("restart failed on start: %w", err)
	}
	return true, nil
}

// Toggle toggles VPN state
func (s *VPNService) Toggle() error {
	if s.GetStatus().IsRunning() {
		return s.Stop()
	}
	return s.Start()
}

// GetStatus returns current VPN status
func (s *VPNService) GetStatus() VPNStatus {
	if s.processManager.IsRunning() {
		return VPNStatusRunning
	}
	return VPNStatusStopped
}

// RestoreLastState restores the last saved VPN state.
// At boot sing-box may fail to start on the first attempt (TUN driver or
// network stack not ready yet), so the start is retried a few times.
func (s *VPNService) RestoreLastState() error {
	savedState, err := s.storage.LoadVPNState()
	if err != nil {
		return fmt.Errorf("failed to load VPN state: %w", err)
	}

	log.Printf("Restoring VPN state: %v", savedState)

	if !savedState {
		return nil
	}

	var lastErr error
	for attempt := 1; attempt <= config.RestoreStartAttempts; attempt++ {
		if err := s.Start(); err != nil {
			lastErr = err
			log.Printf("Restore attempt %d/%d failed: %v", attempt, config.RestoreStartAttempts, err)
		} else {
			// Give the process a moment to initialize, then verify it survived
			time.Sleep(time.Duration(config.RestoreCheckDelay) * time.Second)
			if s.processManager.IsRunning() {
				log.Printf("VPN state restored on attempt %d", attempt)
				return nil
			}
			lastErr = fmt.Errorf("sing-box exited shortly after start")
			log.Printf("Restore attempt %d/%d: %v", attempt, config.RestoreStartAttempts, lastErr)
		}
		time.Sleep(time.Duration(config.RestoreRetryDelay) * time.Second)
	}

	return fmt.Errorf("failed to restore VPN state: %w", lastErr)
}

// StartMonitoring starts monitoring VPN status
func (s *VPNService) StartMonitoring() {
	ticker := time.NewTicker(time.Duration(config.StatusCheckInterval) * time.Second)
	go func() {
		defer ticker.Stop()
		lastStatus := s.GetStatus()
		s.markRunning(lastStatus.IsRunning())

		for range ticker.C {
			currentStatus := s.GetStatus()
			if currentStatus != lastStatus {
				log.Printf("VPN status changed: %v -> %v", lastStatus, currentStatus)
				s.notifyStatusChange(currentStatus)
				lastStatus = currentStatus

				// Deliberately not persisted: the stored state is the user's
				// intent (last explicit Start/Stop). During Windows shutdown
				// the system kills sing-box before this app exits — saving the
				// observed "stopped" here would erase the intent and break
				// auto-start restore on next boot.

				s.markRunning(currentStatus.IsRunning())
				if !currentStatus.IsRunning() {
					s.autoRestartIfCrashed()
				}
			} else if currentStatus.IsRunning() {
				s.maybeResetAutoRestarts()
			}
		}
	}()
}

// markRunning records when the process was last observed transitioning into
// the running state (zero time when stopped)
func (s *VPNService) markRunning(running bool) {
	s.restartMu.Lock()
	defer s.restartMu.Unlock()
	if running {
		s.runningSince = time.Now()
	} else {
		s.runningSince = time.Time{}
	}
}

// maybeResetAutoRestarts clears the crash counter after the process has
// stayed up long enough — only a *loop* of quick crashes should give up
func (s *VPNService) maybeResetAutoRestarts() {
	s.restartMu.Lock()
	defer s.restartMu.Unlock()
	if s.autoRestarts == 0 && !s.gaveUp {
		return
	}
	if !s.runningSince.IsZero() && time.Since(s.runningSince) >= config.AutoRestartResetAfter*time.Second {
		log.Printf("sing-box stable for %ds, crash auto-restart counter reset", config.AutoRestartResetAfter)
		s.autoRestarts = 0
		s.gaveUp = false
	}
}

// autoRestartIfCrashed restarts sing-box after an unexpected death: the
// process is gone but the stored intent (last explicit Start/Stop) says it
// should be running. A user stop saves intent=false first, so it never
// triggers this. After AutoRestartMaxAttempts consecutive failures the
// monitor gives up and reports once via OnAutoRestartFailed.
func (s *VPNService) autoRestartIfCrashed() {
	intent, err := s.storage.LoadVPNState()
	if err != nil {
		log.Printf("Crash auto-restart: failed to load intent: %v", err)
		return
	}
	if !intent {
		return
	}

	s.restartMu.Lock()
	if s.autoRestarts >= config.AutoRestartMaxAttempts {
		report := !s.gaveUp
		s.gaveUp = true
		s.restartMu.Unlock()
		if report {
			err := fmt.Errorf("sing-box неожиданно завершается; автоперезапуск не помог после %d попыток — проверьте логи", config.AutoRestartMaxAttempts)
			log.Printf("Crash auto-restart: giving up: %v", err)
			if s.OnAutoRestartFailed != nil {
				s.OnAutoRestartFailed(err)
			}
		}
		return
	}
	s.autoRestarts++
	attempt := s.autoRestarts
	s.restartMu.Unlock()

	log.Printf("sing-box died unexpectedly, auto-restarting (attempt %d/%d)", attempt, config.AutoRestartMaxAttempts)
	// Start the process directly, NOT via s.Start(): the stored state is the
	// user's intent and the monitor must never write it (see StartMonitoring)
	if err := s.processManager.Start(); err != nil {
		log.Printf("Crash auto-restart attempt %d failed: %v", attempt, err)
		return
	}
	s.notifyStatusChange(VPNStatusRunning)
}

// StatusChangeCh returns a channel that receives status change notifications
func (s *VPNService) StatusChangeCh() <-chan VPNStatus {
	return s.statusChangeCh
}

// notifyStatusChange sends a status change notification
func (s *VPNService) notifyStatusChange(status VPNStatus) {
	select {
	case s.statusChangeCh <- status:
	default:
		// Channel is full, skip notification
	}
}
