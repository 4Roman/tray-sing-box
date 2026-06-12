package domain

import (
	"testing"
	"time"

	"tray-sing-box/internal/config"
)

// The crash auto-restart decision logic is tested directly (without the
// monitoring ticker): autoRestartIfCrashed is what the monitor calls on an
// observed running -> stopped transition.

func TestAutoRestartWhenIntentRunning(t *testing.T) {
	pm := &fakeProcessManager{} // process died
	svc := NewVPNService(pm, &fakeStorage{state: true})

	svc.autoRestartIfCrashed()

	if !pm.IsRunning() {
		t.Fatal("process must be restarted when intent is running")
	}
	if svc.autoRestarts != 1 {
		t.Fatalf("autoRestarts = %d", svc.autoRestarts)
	}
}

func TestNoAutoRestartWhenUserStopped(t *testing.T) {
	pm := &fakeProcessManager{}
	svc := NewVPNService(pm, &fakeStorage{state: false}) // explicit stop saved

	svc.autoRestartIfCrashed()

	if pm.IsRunning() {
		t.Fatal("process must not be restarted after an explicit stop")
	}
}

func TestAutoRestartGivesUpAndReportsOnce(t *testing.T) {
	pm := &fakeProcessManager{}
	svc := NewVPNService(pm, &fakeStorage{state: true})

	var reports int
	svc.OnAutoRestartFailed = func(err error) { reports++ }

	for i := 0; i < config.AutoRestartMaxAttempts+3; i++ {
		svc.autoRestartIfCrashed()
		pm.setRunning(false) // the process keeps dying immediately
	}

	if svc.autoRestarts != config.AutoRestartMaxAttempts {
		t.Fatalf("autoRestarts = %d, want %d", svc.autoRestarts, config.AutoRestartMaxAttempts)
	}
	if reports != 1 {
		t.Fatalf("exhausted crash loop must be reported exactly once, got %d", reports)
	}
	if pm.IsRunning() {
		t.Fatal("no restart attempts after giving up")
	}
}

func TestStableUptimeResetsCounter(t *testing.T) {
	pm := &fakeProcessManager{running: true}
	svc := NewVPNService(pm, &fakeStorage{state: true})
	svc.autoRestarts = config.AutoRestartMaxAttempts
	svc.gaveUp = true

	// Not yet stable long enough — counter stays
	svc.runningSince = time.Now()
	svc.maybeResetAutoRestarts()
	if svc.autoRestarts == 0 {
		t.Fatal("counter must not reset before the uptime threshold")
	}

	// Stable past the threshold — counter and the gave-up flag reset
	svc.runningSince = time.Now().Add(-time.Duration(config.AutoRestartResetAfter+1) * time.Second)
	svc.maybeResetAutoRestarts()
	if svc.autoRestarts != 0 || svc.gaveUp {
		t.Fatalf("counter not reset: autoRestarts=%d gaveUp=%v", svc.autoRestarts, svc.gaveUp)
	}

	// And the next crash is handled again
	pm.setRunning(false)
	svc.autoRestartIfCrashed()
	if !pm.IsRunning() {
		t.Fatal("auto-restart must work again after the reset")
	}
}
