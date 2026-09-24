package domain

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"tray-sing-box/internal/config"
)

// monitorTick is driven directly: the ticker only calls it every
// StatusCheckInterval seconds. skipBackoff stands in for the time that passes
// between attempts in production.
func skipBackoff(svc *VPNService) {
	svc.restartMu.Lock()
	defer svc.restartMu.Unlock()
	svc.nextAutoRestart = time.Time{}
}

// drain empties the notification channel and returns the last status seen
func drain(svc *VPNService) (last VPNStatus, got bool) {
	for {
		select {
		case last = <-svc.StatusChangeCh():
			got = true
		default:
			return last, got
		}
	}
}

// A restarted process that dies again before the next tick never produces a
// running -> stopped transition. The monitor must still use its whole budget
// and report once — a transition-triggered monitor stopped after attempt 1.
func TestMonitorKeepsRestartingFastCrashLoop(t *testing.T) {
	pm := &fakeProcessManager{}
	svc := NewVPNService(pm, &fakeStorage{state: true})

	var reports int
	svc.OnAutoRestartFailed = func(err error) { reports++ }

	status := VPNStatusStopped
	for i := 0; i < config.AutoRestartMaxAttempts+3; i++ {
		status = svc.monitorTick(status)
		pm.setRunning(false) // dies right after every start
		skipBackoff(svc)
	}

	if got := pm.startCount(); got != config.AutoRestartMaxAttempts {
		t.Fatalf("start attempts = %d, want %d", got, config.AutoRestartMaxAttempts)
	}
	if reports != 1 {
		t.Fatalf("exhausted crash loop must be reported exactly once, got %d", reports)
	}

	// The listener consumed the optimistic "running" published by an attempt;
	// the next tick must correct it although nothing changed since the last
	// observation (stopped -> stopped)
	drain(svc)
	svc.monitorTick(status)
	if last, got := drain(svc); !got || last.IsRunning() {
		t.Fatalf("tray would keep showing a dead VPN as running (notified=%v status=%v)", got, last)
	}
}

// A restore that failed at boot leaves the process down with intent=running
// and no transition at all: the monitor must pick it up.
func TestMonitorRetriesAfterFailedRestore(t *testing.T) {
	pm := &fakeProcessManager{}
	svc := NewVPNService(pm, &fakeStorage{state: true})

	svc.monitorTick(VPNStatusStopped)

	if !pm.IsRunning() {
		t.Fatal("monitor must start a VPN that is down while the intent is running")
	}
}

func TestMonitorRetriesWhenStartFailsAndReportsLastError(t *testing.T) {
	pm := &fakeProcessManager{startErr: errors.New("wintun not ready")}
	svc := NewVPNService(pm, &fakeStorage{state: true})

	var reported error
	svc.OnAutoRestartFailed = func(err error) { reported = err }

	status := VPNStatusStopped
	for i := 0; i < config.AutoRestartMaxAttempts+1; i++ {
		status = svc.monitorTick(status)
		skipBackoff(svc)
	}

	if got := pm.startCount(); got != config.AutoRestartMaxAttempts {
		t.Fatalf("start attempts = %d, want %d", got, config.AutoRestartMaxAttempts)
	}
	if reported == nil || !strings.Contains(reported.Error(), "wintun not ready") {
		t.Fatalf("give-up report must carry the last start error, got: %v", reported)
	}
}

// Between attempts the monitor waits: the previous attempt needs time to
// prove itself, and a boot-time failure must not burn the budget in seconds
func TestMonitorBacksOffBetweenAttempts(t *testing.T) {
	pm := &fakeProcessManager{}
	svc := NewVPNService(pm, &fakeStorage{state: true})

	status := svc.monitorTick(VPNStatusStopped)
	pm.setRunning(false)
	for i := 0; i < 5; i++ {
		status = svc.monitorTick(status)
		pm.setRunning(false)
	}

	if got := pm.startCount(); got != 1 {
		t.Fatalf("start attempts within the backoff window = %d, want 1", got)
	}
}

func TestMonitorLeavesUserStoppedVPNAlone(t *testing.T) {
	pm := &fakeProcessManager{}
	svc := NewVPNService(pm, &fakeStorage{state: false})

	svc.monitorTick(VPNStatusStopped)

	if pm.startCount() != 0 {
		t.Fatal("monitor must not start a VPN the user stopped")
	}
}

// While a restart / binary swap holds the lifecycle lock the process is down
// on purpose
func TestNoAutoRestartDuringLifecycleOperation(t *testing.T) {
	pm := &fakeProcessManager{}
	svc := NewVPNService(pm, &fakeStorage{state: true})

	svc.lifeMu.Lock()
	svc.autoRestartIfCrashed()
	svc.lifeMu.Unlock()

	if pm.startCount() != 0 || svc.autoRestarts != 0 {
		t.Fatalf("auto-restart ran during a lifecycle operation: starts=%d attempts=%d", pm.startCount(), svc.autoRestarts)
	}

	svc.autoRestartIfCrashed()
	if !pm.IsRunning() {
		t.Fatal("auto-restart must work again once the operation is over")
	}
}

func TestNoAutoRestartWhileSessionIsEnding(t *testing.T) {
	pm := &fakeProcessManager{}
	svc := NewVPNService(pm, &fakeStorage{state: true})
	svc.SessionEnding = func() bool { return true }

	svc.autoRestartIfCrashed()

	if pm.startCount() != 0 {
		t.Fatal("sing-box must not be restarted into a closing Windows session")
	}
}

func TestExplicitStartGivesFreshAutoRestartBudget(t *testing.T) {
	pm := &fakeProcessManager{}
	svc := NewVPNService(pm, &fakeStorage{state: true})
	svc.autoRestarts = config.AutoRestartMaxAttempts
	svc.gaveUp = true

	if err := svc.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if svc.autoRestarts != 0 || svc.gaveUp {
		t.Fatalf("budget not reset: autoRestarts=%d gaveUp=%v", svc.autoRestarts, svc.gaveUp)
	}
}

// A restart applies a config change — it is not a user decision. If the start
// fails the intent must still say "running", otherwise the VPN silently stays
// off on every next boot.
func TestRestartIfRunningNeverWritesIntent(t *testing.T) {
	pm := &fakeProcessManager{running: true}
	st := &fakeStorage{state: true}
	svc := NewVPNService(pm, st)

	restarted, err := svc.RestartIfRunning()
	if err != nil || !restarted {
		t.Fatalf("RestartIfRunning = %v, %v", restarted, err)
	}
	if state, saves := st.snapshot(); !state || saves != 0 {
		t.Fatalf("restart touched the intent: state=%v saves=%d", state, saves)
	}

	pm.startErr = errors.New("config rejected")
	if _, err := svc.RestartIfRunning(); err == nil {
		t.Fatal("expected the start error")
	}
	if state, saves := st.snapshot(); !state || saves != 0 {
		t.Fatalf("failed restart changed the intent: state=%v saves=%d", state, saves)
	}
}

func TestRestartIfRunningNoopWhenStopped(t *testing.T) {
	pm := &fakeProcessManager{}
	svc := NewVPNService(pm, &fakeStorage{})

	restarted, err := svc.RestartIfRunning()
	if err != nil || restarted || pm.startCount() != 0 {
		t.Fatalf("RestartIfRunning on a stopped VPN = %v, %v (starts=%d)", restarted, err, pm.startCount())
	}
}

func TestWithStoppedRunsWhileDownAndKeepsIntent(t *testing.T) {
	pm := &fakeProcessManager{running: true}
	st := &fakeStorage{state: true}
	svc := NewVPNService(pm, st)

	var ranWhileDown bool
	restarted, err := svc.WithStopped(func() error {
		ranWhileDown = !pm.IsRunning()
		return nil
	})
	if err != nil || !restarted {
		t.Fatalf("WithStopped = %v, %v", restarted, err)
	}
	if !ranWhileDown {
		t.Fatal("fn must run while the process is stopped")
	}
	if !pm.IsRunning() {
		t.Fatal("VPN must be started again")
	}
	if state, saves := st.snapshot(); !state || saves != 0 {
		t.Fatalf("WithStopped touched the intent: state=%v saves=%d", state, saves)
	}
}

func TestWithStoppedStartsAgainEvenWhenFnFails(t *testing.T) {
	pm := &fakeProcessManager{running: true}
	svc := NewVPNService(pm, &fakeStorage{state: true})

	fnErr := errors.New("swap failed")
	restarted, err := svc.WithStopped(func() error { return fnErr })
	if !errors.Is(err, fnErr) {
		t.Fatalf("err = %v, want the fn error", err)
	}
	if !restarted || !pm.IsRunning() {
		t.Fatal("VPN must come back after a failed fn")
	}
}

// The restore starts the process only: the intent is already "running"
func TestRestoreDoesNotRewriteIntent(t *testing.T) {
	pm := &fakeProcessManager{}
	st := &fakeStorage{state: true}
	svc := NewVPNService(pm, st)

	if err := svc.RestoreLastState(); err != nil {
		t.Fatalf("RestoreLastState: %v", err)
	}
	if _, saves := st.snapshot(); saves != 0 {
		t.Fatalf("restore performed %d intent saves", saves)
	}
}

// The user's "stop" is recorded even when the kill fails or the process takes
// too long to die: with intent=running the level-triggered monitor would
// revive a VPN the user has just stopped.
func TestStopFailureStillRecordsUserIntent(t *testing.T) {
	pm := &fakeProcessManager{running: true, stopErr: errors.New("still running 5 s after taskkill")}
	st := &fakeStorage{state: true}
	svc := NewVPNService(pm, st)

	if err := svc.Stop(); err == nil {
		t.Fatal("the stop error must reach the user")
	}
	if state, _ := st.snapshot(); state {
		t.Fatal("a failed Stop left intent=running")
	}

	// The process finally dies: the monitor must leave it alone
	pm.setRunning(false)
	svc.monitorTick(VPNStatusRunning)
	if pm.startCount() != 0 {
		t.Fatal("monitor revived a VPN the user stopped")
	}
}

// A restart must not start anything on top of an instance that failed to stop
// (Start would attach to the dying process), and must not touch the intent
func TestRestartIfRunningStopFailureDoesNotStart(t *testing.T) {
	pm := &fakeProcessManager{running: true, stopErr: errors.New("access denied")}
	st := &fakeStorage{state: true}
	svc := NewVPNService(pm, st)

	restarted, err := svc.RestartIfRunning()
	if err == nil || restarted {
		t.Fatalf("RestartIfRunning = %v, %v, want a stop error", restarted, err)
	}
	if pm.startCount() != 0 {
		t.Fatal("Start called after a failed Stop")
	}
	if state, saves := st.snapshot(); !state || saves != 0 {
		t.Fatalf("failed restart changed the intent: state=%v saves=%d", state, saves)
	}
}

// Safety-critical for the binary swap: fn must never run over a sing-box that
// could not be stopped
func TestWithStoppedDoesNotRunFnWhenStopFails(t *testing.T) {
	pm := &fakeProcessManager{running: true, stopErr: errors.New("access denied")}
	st := &fakeStorage{state: true}
	svc := NewVPNService(pm, st)

	ran := false
	restarted, err := svc.WithStopped(func() error { ran = true; return nil })
	if err == nil || restarted {
		t.Fatalf("WithStopped = %v, %v, want a stop error", restarted, err)
	}
	if ran {
		t.Fatal("fn ran although sing-box could not be stopped")
	}
	if pm.startCount() != 0 {
		t.Fatal("Start called after a failed Stop")
	}
	if _, saves := st.snapshot(); saves != 0 {
		t.Fatalf("WithStopped touched the intent (%d saves)", saves)
	}
}

// An update must not turn on a VPN the user keeps off
func TestWithStoppedDoesNotStartStoppedVPN(t *testing.T) {
	pm := &fakeProcessManager{}
	svc := NewVPNService(pm, &fakeStorage{})

	ran := false
	restarted, err := svc.WithStopped(func() error { ran = true; return nil })
	if err != nil || restarted || !ran {
		t.Fatalf("WithStopped = %v, %v (ran=%v)", restarted, err, ran)
	}
	if pm.startCount() != 0 {
		t.Fatal("a stopped VPN was started")
	}
}

// After the monitor gave up, a repair made through the app (config save ->
// RestartIfRunning, binary update -> WithStopped) must let it try again: both
// are no-ops for a stopped process, and the web UI has no start button.
func TestRepairThroughTheAppClearsGiveUp(t *testing.T) {
	repairs := map[string]func(*VPNService){
		"config change": func(svc *VPNService) { svc.RestartIfRunning() },
		"binary update": func(svc *VPNService) { svc.WithStopped(func() error { return nil }) },
	}
	for name, repair := range repairs {
		pm := &fakeProcessManager{}
		svc := NewVPNService(pm, &fakeStorage{state: true})
		svc.autoRestarts = config.AutoRestartMaxAttempts
		svc.gaveUp = true

		svc.monitorTick(VPNStatusStopped)
		if pm.startCount() != 0 {
			t.Fatalf("%s: monitor retried although it had given up", name)
		}

		repair(svc)
		svc.monitorTick(VPNStatusStopped)
		if !pm.IsRunning() {
			t.Fatalf("%s: monitor did not resume after the repair", name)
		}
	}
}

// A failed binary swap leaves the cause in place: no fresh budget
func TestFailedUpdateKeepsGiveUp(t *testing.T) {
	pm := &fakeProcessManager{}
	svc := NewVPNService(pm, &fakeStorage{state: true})
	svc.gaveUp = true

	svc.WithStopped(func() error { return errors.New("swap failed") })
	if !svc.gaveUp {
		t.Fatal("give-up state cleared by a failed update")
	}
}

// The wait after attempt N is N*AutoRestartBackoff
func TestAutoRestartBackoffGrows(t *testing.T) {
	pm := &fakeProcessManager{}
	svc := NewVPNService(pm, &fakeStorage{state: true})

	for attempt := 1; attempt <= 3; attempt++ {
		pm.setRunning(false)
		before := time.Now()
		svc.autoRestartIfCrashed()

		svc.restartMu.Lock()
		wait := svc.nextAutoRestart.Sub(before)
		svc.restartMu.Unlock()

		want := time.Duration(attempt*config.AutoRestartBackoff) * time.Second
		if wait < want || wait > want+time.Second {
			t.Fatalf("wait after attempt %d = %v, want ~%v", attempt, wait, want)
		}
	}
}

// The listener re-reads the status when it gets to a pending wake-up, which
// may be BEFORE the change whose notification was dropped. The monitor must
// keep notifying after a drop, even when the status equals the last delivered
// one.
func TestMonitorRenotifiesAfterDroppedNotification(t *testing.T) {
	pm := &fakeProcessManager{}
	svc := NewVPNService(pm, &fakeStorage{state: false})

	svc.notifyStatusChange(VPNStatusStopped) // delivered, not consumed yet
	svc.notifyStatusChange(VPNStatusRunning) // dropped: the channel is full
	pm.setRunning(true)
	drain(svc) // the listener wakes up and reads "running" itself

	pm.setRunning(false) // dies; equals the last DELIVERED status (stopped)
	svc.monitorTick(VPNStatusStopped)

	if _, got := drain(svc); !got {
		t.Fatal("listener was never told about the death: the tray keeps showing a dead VPN as running")
	}
}

// slowStopProcessManager parks Stop until released, like taskkill + the wait
// for the process to disappear
type slowStopProcessManager struct {
	fakeProcessManager
	stopEntered chan struct{}
	releaseStop chan struct{}
}

func (f *slowStopProcessManager) Stop() error {
	close(f.stopEntered)
	<-f.releaseStop
	return f.fakeProcessManager.Stop()
}

// "A user Stop during the restore wins": Stop persists intent=false before it
// releases lifeMu, and the restore reads the intent under that lock. Checking
// before taking the lock would read "running" while Stop is still killing the
// process and start sing-box right after the user stopped it.
func TestUserStopDuringRestoreWins(t *testing.T) {
	pm := &slowStopProcessManager{
		stopEntered: make(chan struct{}),
		releaseStop: make(chan struct{}),
	}
	st := &fakeStorage{state: true}
	svc := NewVPNService(pm, st)

	stopDone := make(chan error, 1)
	go func() { stopDone <- svc.Stop() }()
	<-pm.stopEntered // Stop holds lifeMu and is "killing the process"

	startErr := make(chan error, 1)
	go func() { startErr <- svc.startProcess() }() // a restore attempt wakes up now
	time.Sleep(100 * time.Millisecond)             // let it reach lifeMu
	close(pm.releaseStop)

	if err := <-stopDone; err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := <-startErr; !errors.Is(err, errStoppedByUser) {
		t.Fatalf("restore start = %v, want errStoppedByUser", err)
	}
	if pm.startCount() != 0 || pm.IsRunning() {
		t.Fatal("restore started sing-box right after the user stopped it")
	}
}

func TestRestoreAbortsWhenUserStopped(t *testing.T) {
	pm := &fakeProcessManager{startErr: errors.New("not ready")}
	st := &fakeStorage{state: true}
	svc := NewVPNService(pm, st)

	done := make(chan error, 1)
	go func() { done <- svc.RestoreLastState() }()

	// Attempt 1 fails at once; the user stops the VPN during the retry delay
	time.Sleep(300 * time.Millisecond)
	if err := svc.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	if err := <-done; err != nil {
		t.Fatalf("an aborted restore is not an error, got: %v", err)
	}
	if got := pm.startCount(); got != 1 {
		t.Fatalf("start attempts = %d, want 1 (no attempt after the user's stop)", got)
	}
}

// While the app is still bringing the VPN up the status says so — the tray
// then offers "stop", which is how the user calls the attempts off
func TestStatusStartingWhileTheAppKeepsTrying(t *testing.T) {
	pm := &fakeProcessManager{startErr: errors.New("not ready")}
	st := &fakeStorage{state: true}
	svc := NewVPNService(pm, st)

	if got := svc.GetStatus(); got != VPNStatusStarting {
		t.Fatalf("down + intent running = %v, want starting", got)
	}
	if svc.GetStatus().IsRunning() {
		t.Fatal("starting must not count as running")
	}

	// The user calls it off
	if err := svc.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if got := svc.GetStatus(); got != VPNStatusStopped {
		t.Fatalf("after the user's stop = %v, want stopped", got)
	}
}

func TestStatusStoppedOnceTheMonitorGaveUp(t *testing.T) {
	pm := &fakeProcessManager{startErr: errors.New("not ready")}
	svc := NewVPNService(pm, &fakeStorage{state: true})

	status := svc.GetStatus()
	for i := 0; i < config.AutoRestartMaxAttempts+1; i++ {
		status = svc.monitorTick(status)
		skipBackoff(svc)
	}

	if got := svc.GetStatus(); got != VPNStatusStopped {
		t.Fatalf("after giving up = %v, want stopped (the menu must offer \"start\" again)", got)
	}
}

func TestStatusStoppedWhenUserKeepsItOff(t *testing.T) {
	svc := NewVPNService(&fakeProcessManager{}, &fakeStorage{state: false})
	if got := svc.GetStatus(); got != VPNStatusStopped {
		t.Fatalf("down + intent stopped = %v, want stopped", got)
	}
}

// reportingProcessManager knows why its process died, like the real manager
type reportingProcessManager struct {
	fakeProcessManager
	lastExit error
}

func (f *reportingProcessManager) LastExit() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastExit
}

// Start supersedes the previous death, like the real manager
func (f *reportingProcessManager) Start() error {
	f.mu.Lock()
	f.lastExit = nil
	f.mu.Unlock()
	return f.fakeProcessManager.Start()
}

func (f *reportingProcessManager) die(reason error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.running = false
	f.lastExit = reason
}

// Every start "succeeds" and the process dies a few seconds in (TUN setup at
// boot): the give-up report must carry THAT reason — not nothing, and not the
// error of an earlier attempt that failed for a different reason
func TestGiveUpReportsWhyTheLastProcessDied(t *testing.T) {
	pm := &reportingProcessManager{}
	svc := NewVPNService(pm, &fakeStorage{state: true})

	var reported error
	svc.OnAutoRestartFailed = func(err error) { reported = err }

	// Attempt 1 fails outright
	pm.startErr = errors.New("sing-box.exe is locked by the antivirus")
	status := svc.monitorTick(VPNStatusStopped)
	skipBackoff(svc)

	// The rest start fine and die late
	pm.startErr = nil
	for i := 0; i < config.AutoRestartMaxAttempts; i++ {
		status = svc.monitorTick(status)
		pm.die(errors.New("configure tun interface: access denied"))
		skipBackoff(svc)
	}

	if reported == nil {
		t.Fatal("give-up was never reported")
	}
	if !strings.Contains(reported.Error(), "configure tun interface") {
		t.Fatalf("report does not carry the reason of the last death: %v", reported)
	}
	if strings.Contains(reported.Error(), "antivirus") {
		t.Fatalf("report blames an earlier attempt's error: %v", reported)
	}
}

// failingStorage cannot read the intent
type failingStorage struct{ fakeStorage }

func (f *failingStorage) LoadVPNState() (bool, error) {
	return false, errors.New("registry unavailable")
}

// With an unreadable intent the monitor does nothing — so the status must not
// claim "starting"
func TestStatusNotStartingWhenIntentIsUnreadable(t *testing.T) {
	svc := NewVPNService(&fakeProcessManager{}, &failingStorage{})
	if got := svc.GetStatus(); got != VPNStatusStopped {
		t.Fatalf("status with an unreadable intent = %v, want stopped", got)
	}
}

// The process died on its own, and then every restart attempt fails outright
// (config.json gone): the report must name the start error, not the older
// death
func TestGiveUpPrefersTheStartErrorOverAnOlderDeath(t *testing.T) {
	pm := &reportingProcessManager{}
	svc := NewVPNService(pm, &fakeStorage{state: true})

	var reported error
	svc.OnAutoRestartFailed = func(err error) { reported = err }

	pm.die(errors.New("killed from the task manager"))
	pm.startErr = fmt.Errorf("%w at: C:\\data\\config.json", ErrConfigMissing)

	status := VPNStatusRunning
	for i := 0; i < config.AutoRestartMaxAttempts+1; i++ {
		status = svc.monitorTick(status)
		skipBackoff(svc)
	}

	if reported == nil || !strings.Contains(reported.Error(), "config.json not found") {
		t.Fatalf("report must carry the start error, got: %v", reported)
	}
	if !strings.Contains(reported.Error(), "Положите свой config.json") {
		t.Fatalf("report must say how to fix a setup error, got: %v", reported)
	}
	if strings.Contains(reported.Error(), "task manager") {
		t.Fatalf("report fell back to the older death: %v", reported)
	}
}
