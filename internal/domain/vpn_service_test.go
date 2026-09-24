package domain

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeProcessManager struct {
	mu       sync.Mutex
	running  bool
	startErr error
	stopErr  error
	starts   int // Start calls, successful or not
}

func (f *fakeProcessManager) Start() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.starts++
	if f.startErr != nil {
		return f.startErr
	}
	f.running = true
	return nil
}

func (f *fakeProcessManager) Stop() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stopErr != nil {
		return f.stopErr
	}
	f.running = false
	return nil
}

func (f *fakeProcessManager) IsRunning() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.running
}

func (f *fakeProcessManager) setRunning(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.running = v
}

func (f *fakeProcessManager) startCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.starts
}

type fakeStorage struct {
	mu    sync.Mutex
	state bool
	saves int
}

func (f *fakeStorage) SaveVPNState(running bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.state = running
	f.saves++
	return nil
}

func (f *fakeStorage) LoadVPNState() (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.state, nil
}

func (f *fakeStorage) snapshot() (bool, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.state, f.saves
}

func TestStartStopPersistIntent(t *testing.T) {
	pm := &fakeProcessManager{}
	st := &fakeStorage{}
	svc := NewVPNService(pm, st)

	if err := svc.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if state, _ := st.snapshot(); !state {
		t.Fatal("Start did not persist running=true")
	}

	if err := svc.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if state, _ := st.snapshot(); state {
		t.Fatal("Stop did not persist running=false")
	}
}

// A start that fails for a reason the user can fix says how to fix it: an
// installed copy has neither sing-box.exe nor config.json until it took over
// a portable one
func TestStartErrorCarriesTheSetupHint(t *testing.T) {
	for _, tc := range []struct {
		err  error
		hint string
	}{
		{fmt.Errorf("%w at: C:\\bin\\sing-box.exe", ErrSingBoxMissing), "«Обновить sing-box»"},
		{fmt.Errorf("%w at: C:\\data\\config.json", ErrConfigMissing), "Положите свой config.json"},
	} {
		svc := NewVPNService(&fakeProcessManager{startErr: tc.err}, &fakeStorage{})
		err := svc.Start()
		if err == nil || !errors.Is(err, tc.err) || !strings.Contains(err.Error(), tc.hint) {
			t.Errorf("Start error %q: want the cause and the hint %q", err, tc.hint)
		}
	}

	// Anything else is passed through as it is
	svc := NewVPNService(&fakeProcessManager{startErr: errors.New("wintun not ready")}, &fakeStorage{})
	if err := svc.Start(); err == nil || err.Error() != "failed to start VPN: wintun not ready" {
		t.Errorf("Start error = %v, want the plain cause", err)
	}
}

// External process death (e.g. Windows shutdown killing sing-box before the
// tray exits) must NOT overwrite the user's stored intent.
func TestMonitoringDoesNotOverwriteIntent(t *testing.T) {
	pm := &fakeProcessManager{}
	st := &fakeStorage{}
	svc := NewVPNService(pm, st)

	if err := svc.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	_, savesAfterStart := st.snapshot()

	// Drain the notification produced by Start: the channel is buffered with
	// capacity 1 and the monitor drops notifications when it is full.
	<-svc.StatusChangeCh()

	svc.StartMonitoring()
	// Let the monitor goroutine capture its initial status before the kill
	time.Sleep(200 * time.Millisecond)

	// Simulate the process being killed externally
	pm.setRunning(false)

	// Wait for the monitor to notice (interval is 2s)
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case status := <-svc.StatusChangeCh():
			if status.IsRunning() {
				continue
			}
			// Monitor noticed the death; intent must be unchanged
			state, saves := st.snapshot()
			if !state {
				t.Fatal("monitor overwrote stored intent with observed state")
			}
			if saves != savesAfterStart {
				t.Fatalf("monitor performed %d extra saves", saves-savesAfterStart)
			}
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
	t.Fatal("monitor never reported the status change")
}

func TestRestoreLastStateStartsWhenIntentRunning(t *testing.T) {
	pm := &fakeProcessManager{}
	st := &fakeStorage{state: true}
	svc := NewVPNService(pm, st)

	if err := svc.RestoreLastState(); err != nil {
		t.Fatalf("RestoreLastState: %v", err)
	}
	if !pm.IsRunning() {
		t.Fatal("VPN was not started during restore")
	}
}

func TestRestoreLastStateNoopWhenIntentStopped(t *testing.T) {
	pm := &fakeProcessManager{}
	st := &fakeStorage{state: false}
	svc := NewVPNService(pm, st)

	if err := svc.RestoreLastState(); err != nil {
		t.Fatalf("RestoreLastState: %v", err)
	}
	if pm.IsRunning() {
		t.Fatal("VPN was started although stored intent is stopped")
	}
}
