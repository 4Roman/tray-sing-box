package domain

import (
	"errors"
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

// Setup errors a ProcessManager wraps: the user can fix them, and the
// message says how (withSetupHint). An installed copy starts without either
// unless it took over a portable one.
var (
	ErrSingBoxMissing = errors.New("sing-box.exe not found")
	ErrConfigMissing  = errors.New("config.json not found")
)

// withSetupHint appends what to do about a setup error to the text the user
// sees (tray popup, web UI, the give-up report)
func withSetupHint(err error) error {
	switch {
	case errors.Is(err, ErrSingBoxMissing):
		return fmt.Errorf("%w\n\nСкачайте sing-box: пункт «Обновить sing-box» в меню трея или кнопка на странице настроек.", err)
	case errors.Is(err, ErrConfigMissing):
		return fmt.Errorf("%w\n\nПоложите свой config.json по этому пути. У установленной копии папка данных доступна только администраторам: копируйте из Проводника или PowerShell, запущенных от имени администратора.", err)
	}
	return err
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

	// SessionEnding, when set before StartMonitoring, reports that Windows is
	// shutting down or logging off. The system kills sing-box before this app
	// exits; the monitor must not try to bring it back into a closing session.
	SessionEnding func() bool

	// lifeMu serializes everything that starts or stops the process: explicit
	// Start/Stop, restarts, the startup restore and the monitor's auto-restart.
	// The monitor only TryLocks it, so a process that is down on purpose
	// (restart for a config change, binary swap) is never taken for a crash,
	// and a user Stop has always persisted intent=false before the monitor
	// reads the intent.
	lifeMu sync.Mutex

	restartMu       sync.Mutex
	autoRestarts    int       // consecutive auto-restart attempts
	gaveUp          bool      // already reported the exhausted crash loop
	runningSince    time.Time // observed running continuously since
	nextAutoRestart time.Time // the monitor makes no attempt before this moment
	lastRestartErr  error     // why the last auto-restart attempt failed
	published       VPNStatus // last status actually delivered to statusChangeCh
	notifyDropped   bool      // a notification was dropped since that delivery
}

// NewVPNService creates a new VPN service instance
func NewVPNService(pm ProcessManager, storage Storage) *VPNService {
	return &VPNService{
		processManager: pm,
		storage:        storage,
		statusChangeCh: make(chan VPNStatus, 1),
	}
}

// Start starts the VPN on the user's request and records the intent
func (s *VPNService) Start() error {
	log.Printf("=== VPNService.Start called ===")

	s.lifeMu.Lock()
	defer s.lifeMu.Unlock()

	if err := s.processManager.Start(); err != nil {
		return withSetupHint(fmt.Errorf("failed to start VPN: %w", err))
	}

	if err := s.storage.SaveVPNState(true); err != nil {
		log.Printf("Warning: failed to save VPN state: %v", err)
	}

	// An explicit action gives the crash monitor a fresh budget
	s.resetAutoRestarts()
	s.notifyStatusChange(VPNStatusRunning)
	return nil
}

// Stop stops the VPN on the user's request and records the intent
func (s *VPNService) Stop() error {
	log.Printf("=== VPNService.Stop called ===")

	s.lifeMu.Lock()
	defer s.lifeMu.Unlock()

	// The user's decision is recorded first and stays recorded even when the
	// kill fails or the process takes too long to die: with intent still
	// "running" the monitor would bring back a VPN the user has just stopped.
	// (Restarts never come through here, so a failed stop cannot wipe the
	// intent of a VPN the user wants running.)
	if err := s.storage.SaveVPNState(false); err != nil {
		log.Printf("Warning: failed to save VPN state: %v", err)
	}
	s.resetAutoRestarts()

	if err := s.processManager.Stop(); err != nil {
		return fmt.Errorf("failed to stop VPN: %w", err)
	}

	s.notifyStatusChange(VPNStatusStopped)
	return nil
}

// RestartIfRunning restarts the VPN when it is running (e.g. to apply a
// config change) and reports whether a restart happened. A restart is not a
// user decision, so the stored intent is left untouched: if the start fails
// the intent still says "running" and the monitor keeps trying, instead of
// the VPN silently staying off across reboots.
func (s *VPNService) RestartIfRunning() (bool, error) {
	s.lifeMu.Lock()
	defer s.lifeMu.Unlock()

	if !s.processManager.IsRunning() {
		// The config has just changed: if the monitor had given up on a crash
		// loop, let it try again with the new one (it checks the intent itself)
		s.resetAutoRestarts()
		return false, nil
	}
	log.Printf("Restarting VPN to apply configuration changes")
	if err := s.processManager.Stop(); err != nil {
		return false, fmt.Errorf("restart failed on stop: %w", err)
	}
	if err := s.processManager.Start(); err != nil {
		s.notifyStatusChange(VPNStatusStopped)
		return false, fmt.Errorf("restart failed on start: %w", err)
	}
	s.notifyStatusChange(VPNStatusRunning)
	return true, nil
}

// WithStopped runs fn while sing-box is guaranteed to be down (binary swap)
// and starts it again afterwards if it was running — regardless of fn's
// outcome. Like RestartIfRunning it never touches the stored intent, and the
// monitor is held off for the whole duration. The returned error is the stop
// failure (fn was not called), fn's own error, or the failure to start again.
func (s *VPNService) WithStopped(fn func() error) (restarted bool, err error) {
	s.lifeMu.Lock()
	defer s.lifeMu.Unlock()

	wasRunning := s.processManager.IsRunning()
	if wasRunning {
		if err := s.processManager.Stop(); err != nil {
			return false, fmt.Errorf("failed to stop VPN: %w", err)
		}
		s.notifyStatusChange(VPNStatusStopped)
	}

	fnErr := fn()

	if !wasRunning && fnErr == nil {
		// The binary was replaced while the VPN was down: a monitor that had
		// given up (e.g. sing-box.exe was missing) may try again
		s.resetAutoRestarts()
	}

	if wasRunning {
		if err := s.processManager.Start(); err != nil {
			log.Printf("Failed to start VPN again: %v", err)
			if fnErr == nil {
				fnErr = fmt.Errorf("failed to start VPN again: %w", err)
			}
		} else {
			restarted = true
			s.notifyStatusChange(VPNStatusRunning)
		}
	}
	return restarted, fnErr
}

// GetStatus returns current VPN status
func (s *VPNService) GetStatus() VPNStatus {
	if s.processManager.IsRunning() {
		return VPNStatusRunning
	}
	// Down, but wanted up and not given up on: the restore or the monitor is
	// (or will shortly be) working on it. An unreadable intent is NOT
	// "starting": tryAutoRestart does nothing in that case, so the status
	// would claim an effort nobody is making (and this is called far too
	// often to log from).
	if intent, err := s.storage.LoadVPNState(); err == nil && intent && !s.hasGivenUp() {
		return VPNStatusStarting
	}
	return VPNStatusStopped
}

// hasGivenUp reports whether the monitor has exhausted its auto-restarts
func (s *VPNService) hasGivenUp() bool {
	s.restartMu.Lock()
	defer s.restartMu.Unlock()
	return s.gaveUp
}

// RestoreLastState restores the last saved VPN state.
// At boot sing-box may fail to start on the first attempt (TUN driver or
// network stack not ready yet), so the start is retried a few times. When
// these attempts are exhausted the intent still says "running", so the
// monitor (StartMonitoring, started right after) keeps trying with a backoff
// and finally reports through OnAutoRestartFailed.
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
		if attempt > 1 {
			time.Sleep(time.Duration(config.RestoreRetryDelay) * time.Second)
		}
		// The intent is already "running": start the process only, nothing
		// to persist. The restore runs in the background — the user may have
		// pressed "stop" in the meantime, and that decision wins.
		if err := s.startProcess(); err != nil {
			if errors.Is(err, errStoppedByUser) {
				log.Printf("Restore aborted: the VPN was stopped by the user")
				return nil
			}
			lastErr = err
			log.Printf("Restore attempt %d/%d failed: %v", attempt, config.RestoreStartAttempts, err)
			continue
		}

		// Give the process a moment to initialize, then verify it survived
		time.Sleep(time.Duration(config.RestoreCheckDelay) * time.Second)
		if s.processManager.IsRunning() {
			log.Printf("VPN state restored on attempt %d", attempt)
			return nil
		}
		lastErr = fmt.Errorf("sing-box exited shortly after start")
		if exit := s.lastProcessExit(); exit != nil {
			lastErr = exit
		}
		log.Printf("Restore attempt %d/%d: %v", attempt, config.RestoreStartAttempts, lastErr)
	}

	if !s.intentRunning() {
		return nil
	}
	return fmt.Errorf("failed to restore VPN state: %w", lastErr)
}

// errStoppedByUser is returned by startProcess when the stored intent no
// longer says "running"
var errStoppedByUser = errors.New("VPN was stopped by the user")

// startProcess starts sing-box for the restore, without recording an intent.
// The intent is re-checked under lifeMu: Stop persists intent=false before it
// releases the lock, so a concurrent user Stop can never be followed by a
// restore start (checking before taking the lock could read the old value
// while Stop is still killing the process).
func (s *VPNService) startProcess() error {
	s.lifeMu.Lock()
	defer s.lifeMu.Unlock()

	if !s.intentRunning() {
		return errStoppedByUser
	}
	if err := s.processManager.Start(); err != nil {
		return fmt.Errorf("failed to start VPN: %w", err)
	}
	s.notifyStatusChange(VPNStatusRunning)
	return nil
}

// intentRunning reports whether the stored intent still says "running"
func (s *VPNService) intentRunning() bool {
	intent, err := s.storage.LoadVPNState()
	if err != nil {
		log.Printf("Warning: failed to load VPN state: %v", err)
		return true
	}
	return intent
}

// StartMonitoring starts monitoring VPN status
func (s *VPNService) StartMonitoring() {
	ticker := time.NewTicker(time.Duration(config.StatusCheckInterval) * time.Second)
	go func() {
		defer ticker.Stop()
		lastStatus := s.GetStatus()
		s.markRunning(lastStatus.IsRunning())

		for range ticker.C {
			lastStatus = s.monitorTick(lastStatus)
		}
	}()
}

// monitorTick is one monitoring step. It is level-triggered: as long as the
// process is down while the intent says "running" it keeps scheduling restart
// attempts — a transition-only check would stop after the first attempt when
// that attempt fails or the restarted process dies before the next tick, and
// would never act on a restore that failed at boot.
func (s *VPNService) monitorTick(lastStatus VPNStatus) VPNStatus {
	currentStatus := s.GetStatus()

	if currentStatus != lastStatus {
		log.Printf("VPN status changed: %v -> %v", lastStatus, currentStatus)
		s.markRunning(currentStatus.IsRunning())

		// Deliberately not persisted: the stored state is the user's
		// intent (last explicit Start/Stop). During Windows shutdown
		// the system kills sing-box before this app exits — saving the
		// observed "stopped" here would erase the intent and break
		// auto-start restore on next boot.
	}

	// Compared with what the listener has actually received, not with the
	// previous observation: an optimistic "running" followed by a quick death
	// is corrected here. After a dropped notification the listener's view is
	// unknown (it re-reads the status whenever it gets to the pending
	// wake-up, possibly before the change that was dropped), so keep
	// notifying until one is delivered.
	if published, dropped := s.lastPublished(); dropped || currentStatus != published {
		s.notifyStatusChange(currentStatus)
	}

	if currentStatus.IsRunning() {
		s.maybeResetAutoRestarts()
	} else if s.autoRestartDue() {
		s.autoRestartIfCrashed()
	}
	return currentStatus
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
		s.resetAutoRestartsLocked()
	}
}

// resetAutoRestarts gives the monitor a fresh auto-restart budget
func (s *VPNService) resetAutoRestarts() {
	s.restartMu.Lock()
	defer s.restartMu.Unlock()
	s.resetAutoRestartsLocked()
}

func (s *VPNService) resetAutoRestartsLocked() {
	s.autoRestarts = 0
	s.gaveUp = false
	s.nextAutoRestart = time.Time{}
	s.lastRestartErr = nil
}

// autoRestartDue reports whether the monitor may make an auto-restart attempt
// now: not after giving up, and not before the backoff of the previous
// attempt has passed (which also gives that attempt time to prove itself)
func (s *VPNService) autoRestartDue() bool {
	s.restartMu.Lock()
	defer s.restartMu.Unlock()
	return !s.gaveUp && !time.Now().Before(s.nextAutoRestart)
}

// autoRestartIfCrashed restarts sing-box when it is down although the stored
// intent (last explicit Start/Stop) says it should be running. After
// AutoRestartMaxAttempts consecutive attempts the monitor gives up and
// reports once via OnAutoRestartFailed.
func (s *VPNService) autoRestartIfCrashed() {
	// The hook is called outside lifeMu: it belongs to the application
	if err := s.tryAutoRestart(); err != nil && s.OnAutoRestartFailed != nil {
		s.OnAutoRestartFailed(err)
	}
}

// tryAutoRestart makes one auto-restart attempt; the returned error is the
// "giving up" report, produced once per crash loop
func (s *VPNService) tryAutoRestart() error {
	if s.SessionEnding != nil && s.SessionEnding() {
		log.Printf("Windows session is ending, sing-box is not auto-restarted")
		return nil
	}

	// A lifecycle operation is in progress — the process is down on purpose
	if !s.lifeMu.TryLock() {
		return nil
	}
	defer s.lifeMu.Unlock()

	intent, err := s.storage.LoadVPNState()
	if err != nil {
		log.Printf("Crash auto-restart: failed to load intent: %v", err)
		return nil
	}
	if !intent {
		return nil
	}
	// It may be back already (a restart finished right before the lock)
	if s.processManager.IsRunning() {
		return nil
	}

	// A process that outlived the start check and died later: the start
	// "succeeded", so this is the only place its reason can be picked up —
	// both for the next attempt's log and for the give-up report below
	if exit := s.lastProcessExit(); exit != nil {
		s.restartMu.Lock()
		s.lastRestartErr = exit
		s.restartMu.Unlock()
	}

	s.restartMu.Lock()
	if s.autoRestarts >= config.AutoRestartMaxAttempts {
		report := !s.gaveUp
		s.gaveUp = true
		lastErr := s.lastRestartErr
		s.restartMu.Unlock()
		if !report {
			return nil
		}
		err := fmt.Errorf("sing-box не работает, хотя VPN включён: автоперезапуск не помог после %d попыток — проверьте логи", config.AutoRestartMaxAttempts)
		if lastErr != nil {
			err = fmt.Errorf("%w\n\nПоследняя ошибка: %v", err, withSetupHint(lastErr))
		}
		log.Printf("Crash auto-restart: giving up: %v", err)
		return err
	}
	s.autoRestarts++
	attempt := s.autoRestarts
	s.nextAutoRestart = time.Now().Add(time.Duration(attempt*config.AutoRestartBackoff) * time.Second)
	s.restartMu.Unlock()

	log.Printf("sing-box is down while the VPN should be running, auto-restarting (attempt %d/%d)", attempt, config.AutoRestartMaxAttempts)
	// Start the process directly, NOT via s.Start(): the stored state is the
	// user's intent and the monitor must never write it (see monitorTick)
	if err := s.processManager.Start(); err != nil {
		log.Printf("Crash auto-restart attempt %d failed: %v", attempt, err)
		s.restartMu.Lock()
		s.lastRestartErr = err
		s.restartMu.Unlock()
		return nil
	}
	// This attempt started fine: an older attempt's error must not be
	// reported as "the last error" if it dies later for another reason
	s.restartMu.Lock()
	s.lastRestartErr = nil
	s.restartMu.Unlock()
	s.notifyStatusChange(VPNStatusRunning)
	return nil
}

// exitReporter is implemented by a process manager that knows why the process
// it started died on its own (optional: the fakes in tests do not)
type exitReporter interface {
	LastExit() error
}

func (s *VPNService) lastProcessExit() error {
	if reporter, ok := s.processManager.(exitReporter); ok {
		return reporter.LastExit()
	}
	return nil
}

// StatusChangeCh returns a channel that receives status change notifications.
// A notification is a wake-up: the channel holds one value and drops the rest,
// so listeners should re-read GetStatus instead of trusting the payload.
func (s *VPNService) StatusChangeCh() <-chan VPNStatus {
	return s.statusChangeCh
}

// notifyStatusChange sends a status change notification
func (s *VPNService) notifyStatusChange(status VPNStatus) {
	select {
	case s.statusChangeCh <- status:
		s.restartMu.Lock()
		s.published = status
		s.notifyDropped = false
		s.restartMu.Unlock()
	default:
		// Channel is full, skip notification (the monitor re-sends it on the
		// next tick)
		s.restartMu.Lock()
		s.notifyDropped = true
		s.restartMu.Unlock()
	}
}

// lastPublished returns the last status delivered to statusChangeCh and
// whether a later notification was dropped
func (s *VPNService) lastPublished() (VPNStatus, bool) {
	s.restartMu.Lock()
	defer s.restartMu.Unlock()
	return s.published, s.notifyDropped
}
