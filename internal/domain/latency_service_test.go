package domain

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tray-sing-box/internal/config"
)

// The report and the outcome reach the settings page as JSON: the names the
// page reads, and nothing for what is not there (no delay without an answer)
func TestLatencyJSON(t *testing.T) {
	report := LatencyReport{
		Tested:   time.Date(2026, 10, 18, 12, 30, 0, 0, time.UTC),
		Answered: 1,
		Total:    2,
		Active:   "de-1",
		Fastest:  "de-1",
		Results: []LatencyResult{
			{Tag: "de-1", Type: "vless", DelayMs: 84, Status: LatencyOK, Eligible: true},
			{Tag: "relay", Type: "trojan", Status: LatencyTimeout, Note: "промежуточный узел"},
		},
	}
	got, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"tested":"2026-10-18T12:30:00Z","answered":1,"total":2,"active":"de-1","fastest":"de-1","results":[` +
		`{"tag":"de-1","type":"vless","delay_ms":84,"status":"ok","eligible":true},` +
		`{"tag":"relay","type":"trojan","status":"timeout","eligible":false,"note":"промежуточный узел"}]}`
	if string(got) != want {
		t.Errorf("report JSON\n got %s\nwant %s", got, want)
	}

	outcome := FastestOutcome{Tag: "nl-2", Previous: "de-1", DelayMs: 40, PrevMs: 120, Switched: true, DPIWas: "de-1", Message: "Выбран"}
	got, err = json.Marshal(outcome)
	if err != nil {
		t.Fatal(err)
	}
	want = `{"tag":"nl-2","previous":"de-1","delay_ms":40,"prev_ms":120,"switched":true,"restarted":false,"needs_confirm":false,"dpi_was":"de-1","message":"Выбран"}`
	if string(got) != want {
		t.Errorf("outcome JSON\n got %s\nwant %s", got, want)
	}
	got, err = json.Marshal(FastestOutcome{NeedsConfirm: true, Message: "Продолжить?"})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"switched":false,"restarted":false,"needs_confirm":true,"message":"Продолжить?"}`; string(got) != want {
		t.Errorf("outcome JSON\n got %s\nwant %s", got, want)
	}
}

// --- the service ------------------------------------------------------------

// trackingLock is the operation lock as the service sees it: whether it is
// held, and how often it was asked for
type trackingLock struct {
	mu       sync.Mutex
	held     atomic.Bool
	attempts atomic.Int32
}

func (l *trackingLock) Lock() {
	l.attempts.Add(1)
	l.mu.Lock()
	l.held.Store(true)
}

func (l *trackingLock) Unlock() {
	l.held.Store(false)
	l.mu.Unlock()
}

// fakeLatencySource serves a plan and a routing; routings are handed out in
// turn (the last one stays), each call noting whether the lock was held
type fakeLatencySource struct {
	mu       sync.Mutex
	plan     *ProbePlan
	planErr  error
	routings []RoutingTarget
	detours  []string
	lock     *trackingLock
	rtHeld   []bool
}

func (f *fakeLatencySource) ProbePlan() (*ProbePlan, error) { return f.plan, f.planErr }

func (f *fakeLatencySource) RoutingTarget() (RoutingTarget, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.lock != nil {
		f.rtHeld = append(f.rtHeld, f.lock.held.Load())
	}
	rt := f.routings[0]
	if len(f.routings) > 1 {
		f.routings = f.routings[1:]
	}
	return rt, nil
}

func (f *fakeLatencySource) DetourTargets(tag string) ([]string, error) {
	if tag != config.DPIBypassTag {
		return nil, nil
	}
	return f.detours, nil
}

// fakeLatencyProber answers with fixed delays, or with measure when set
type fakeLatencyProber struct {
	mu       sync.Mutex
	calls    int
	tags     [][]string
	delays   map[string]Delay
	err      error
	measure  func(ctx context.Context) (map[string]Delay, error)
	lock     *trackingLock
	heldAt   []bool
	deadline time.Time
}

func (f *fakeLatencyProber) Measure(ctx context.Context, plan *ProbePlan, tags []string) (map[string]Delay, error) {
	f.mu.Lock()
	f.calls++
	f.tags = append(f.tags, tags)
	if f.lock != nil {
		f.heldAt = append(f.heldAt, f.lock.held.Load())
	}
	f.deadline, _ = ctx.Deadline()
	measure := f.measure
	f.mu.Unlock()
	if measure != nil {
		return measure(ctx)
	}
	return f.delays, f.err
}

func (f *fakeLatencyProber) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func candidate(tag string) LatencyCandidate {
	return LatencyCandidate{Tag: tag, Type: "vless", Testable: true, Eligible: true}
}

// fakeClock is the service's clock, moved by the test
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newTestLatencyService(src *fakeLatencySource, prober *fakeLatencyProber, use func(string) (bool, error), lock *trackingLock) (*LatencyService, *fakeClock) {
	clock := &fakeClock{t: time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)}
	var opLock sync.Locker
	if lock != nil {
		opLock = lock
	}
	s := NewLatencyService(src, prober, use, opLock)
	s.now = clock.now
	return s, clock
}

func twoServers() *fakeLatencyProber {
	return &fakeLatencyProber{delays: map[string]Delay{"a": {Ms: 300, Status: LatencyOK}, "b": {Ms: 100, Status: LatencyOK}}}
}

func twoCandidates(routings ...RoutingTarget) *fakeLatencySource {
	return &fakeLatencySource{plan: &ProbePlan{Candidates: []LatencyCandidate{candidate("a"), candidate("b")}}, routings: routings}
}

// The report: every candidate in the order of the config, the prober's
// answers (and its notes) over the plan's, the servers the routing uses
// measured first, the whole measurement bounded
func TestLatencyReport(t *testing.T) {
	relay := candidate("relay")
	relay.Eligible = false
	relay.Note = "промежуточный узел цепочки — не выбирается самым быстрым"
	src := &fakeLatencySource{
		plan: &ProbePlan{Candidates: []LatencyCandidate{
			{Tag: "proxy", Type: "selector", Note: "группа — проверяются её серверы"},
			candidate("a"), candidate("b"), relay, candidate("x"), candidate("y"),
			{Tag: "direct", Type: "direct"},
		}},
		routings: []RoutingTarget{{Kind: RoutingNode, Tag: "b", ProxyRefs: []string{"b"}, Final: "b"}},
	}
	prober := &fakeLatencyProber{delays: map[string]Delay{
		"proxy": {Status: LatencySkipped, Note: "группа — проверяются её серверы"},
		"a":     {Ms: 120, Status: LatencyOK},
		"b":     {Ms: 90, Status: LatencyOK},
		"relay": {Ms: 30, Status: LatencyOK},
		"x":     {Status: LatencySkipped, Note: "не проверяется: sing-box не смог его запустить отдельно: uTLS is required by reality client"},
		// y: the deadline came first
		"direct": {Status: LatencySkipped},
	}}
	svc, clock := newTestLatencyService(src, prober, nil, nil)

	report, err := svc.Test(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := &LatencyReport{
		Tested: clock.now(), Answered: 3, Total: 5, Active: "b", Fastest: "b",
		Results: []LatencyResult{
			{Tag: "proxy", Type: "selector", Status: LatencySkipped, Note: "группа — проверяются её серверы"},
			{Tag: "a", Type: "vless", DelayMs: 120, Status: LatencyOK, Eligible: true},
			{Tag: "b", Type: "vless", DelayMs: 90, Status: LatencyOK, Eligible: true},
			{Tag: "relay", Type: "vless", DelayMs: 30, Status: LatencyOK, Note: relay.Note},
			{Tag: "x", Type: "vless", Status: LatencySkipped, Eligible: true, Note: "не проверяется: sing-box не смог его запустить отдельно: uTLS is required by reality client"},
			{Tag: "y", Type: "vless", Status: LatencyUnfinished, Eligible: true},
			{Tag: "direct", Type: "direct", Status: LatencySkipped},
		},
	}
	if !reflect.DeepEqual(report, want) {
		t.Errorf("report\n got %+v\nwant %+v", report, want)
	}
	if svc.Last() != report {
		t.Error("Last is not the report of the check")
	}
	if got, want := prober.tags[0], []string{"b", "proxy", "a", "relay", "x", "y", "direct"}; !reflect.DeepEqual(got, want) {
		t.Errorf("measured in the order %v, want %v (the active server first)", got, want)
	}
	if left := time.Until(prober.deadline); prober.deadline.IsZero() || left > config.LatencyTestMaxSeconds*time.Second || left < (config.LatencyTestMaxSeconds-5)*time.Second {
		t.Errorf("the measurement ends in %v, want %d s", left, config.LatencyTestMaxSeconds)
	}
}

// A config without a server to test answers at once: no test instance, and
// nothing that counts for the interval
func TestLatencyNothingTestable(t *testing.T) {
	src := &fakeLatencySource{
		plan:     &ProbePlan{Candidates: []LatencyCandidate{{Tag: "direct", Type: "direct"}, {Tag: "tor", Type: "tor", Note: "тип «tor» не проверяется"}}},
		routings: []RoutingTarget{{Final: "direct"}},
	}
	prober := &fakeLatencyProber{}
	svc, _ := newTestLatencyService(src, prober, nil, nil)
	for i := 0; i < 2; i++ {
		report, err := svc.Test(context.Background())
		if err != nil {
			t.Fatalf("check %d: %v", i+1, err)
		}
		if report.Total != 0 || len(report.Results) != 2 || report.Results[1].Note != "тип «tor» не проверяется" {
			t.Fatalf("report = %+v", report)
		}
	}
	if prober.callCount() != 0 {
		t.Fatalf("a test instance was started %d times for nothing", prober.callCount())
	}
}

// One check at a time: a second one, plain or "select the fastest", is
// refused while the first runs
func TestLatencyBusy(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	prober := &fakeLatencyProber{measure: func(ctx context.Context) (map[string]Delay, error) {
		close(started)
		<-release
		return map[string]Delay{"a": {Ms: 50, Status: LatencyOK}}, nil
	}}
	svc, _ := newTestLatencyService(twoCandidates(nodeRouting("a")), prober, nil, nil)

	done := make(chan error, 1)
	go func() {
		_, err := svc.Test(context.Background())
		done <- err
	}()
	<-started
	if _, err := svc.Test(context.Background()); !errors.Is(err, ErrLatencyBusy) {
		t.Errorf("a second check: %v, want ErrLatencyBusy", err)
	}
	if _, _, err := svc.SelectFastest(context.Background(), false); !errors.Is(err, ErrLatencyBusy) {
		t.Errorf("select the fastest meanwhile: %v, want ErrLatencyBusy", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("the first check: %v", err)
	}
	if prober.callCount() != 1 {
		t.Fatalf("%d test instances", prober.callCount())
	}
}

// Test instances at least LatencyMinIntervalSeconds apart, counted from the
// end of the last one
func TestLatencyTooSoon(t *testing.T) {
	var clock *fakeClock
	prober := &fakeLatencyProber{}
	prober.measure = func(ctx context.Context) (map[string]Delay, error) {
		clock.advance(20 * time.Second) // a long check
		return map[string]Delay{"a": {Ms: 50, Status: LatencyOK}}, nil
	}
	svc, c := newTestLatencyService(twoCandidates(nodeRouting("a")), prober, nil, nil)
	clock = c

	if _, err := svc.Test(context.Background()); err != nil {
		t.Fatal(err)
	}
	clock.advance(config.LatencyMinIntervalSeconds*time.Second - time.Second)
	if _, err := svc.Test(context.Background()); !errors.Is(err, ErrLatencyTooSoon) {
		t.Fatalf("a check %d s after the end of the last: %v, want ErrLatencyTooSoon", config.LatencyMinIntervalSeconds-1, err)
	}
	if _, _, err := svc.SelectFastest(context.Background(), false); !errors.Is(err, ErrLatencyTooSoon) {
		t.Fatalf("select the fastest as soon: %v, want ErrLatencyTooSoon", err)
	}
	clock.advance(time.Second)
	if _, err := svc.Test(context.Background()); err != nil {
		t.Fatalf("a check %d s after: %v", config.LatencyMinIntervalSeconds, err)
	}
	if prober.callCount() != 2 {
		t.Fatalf("%d test instances, want 2", prober.callCount())
	}
}

// The end of the caller's ctx (the page went away) and Cancel (the app
// quits) end the check: "interrupted", the partial result is not kept
func TestLatencyCanceled(t *testing.T) {
	for _, how := range []string{"Cancel", "the caller's ctx"} {
		t.Run(how, func(t *testing.T) {
			started := make(chan struct{})
			prober := &fakeLatencyProber{measure: func(ctx context.Context) (map[string]Delay, error) {
				close(started)
				select {
				case <-ctx.Done():
				case <-time.After(5 * time.Second):
				}
				// What the real prober does: the rest unfinished, no error
				return map[string]Delay{"a": {Status: LatencyUnfinished}}, nil
			}}
			svc, _ := newTestLatencyService(twoCandidates(nodeRouting("a")), prober, nil, nil)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, err := svc.Test(ctx)
				done <- err
			}()
			<-started
			if how == "Cancel" {
				svc.Cancel()
			} else {
				cancel()
			}
			select {
			case err := <-done:
				if !errors.Is(err, ErrLatencyCanceled) {
					t.Fatalf("Test = %v, want ErrLatencyCanceled", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("the check did not end")
			}
			if svc.Last() != nil {
				t.Fatal("an interrupted check was kept")
			}
		})
	}
	// Between checks Cancel does nothing, and the next check runs
	svc, _ := newTestLatencyService(&fakeLatencySource{plan: &ProbePlan{}, routings: []RoutingTarget{{}}}, &fakeLatencyProber{}, nil, nil)
	svc.Cancel()
	if _, err := svc.Test(context.Background()); err != nil {
		t.Fatalf("a check after Cancel: %v", err)
	}
}

// The deadline: a test instance that never answered is an error; what was
// measured before it stands
func TestLatencyDeadline(t *testing.T) {
	prober := &fakeLatencyProber{measure: func(ctx context.Context) (map[string]Delay, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	svc, _ := newTestLatencyService(twoCandidates(nodeRouting("a")), prober, nil, nil)
	svc.limit = 50 * time.Millisecond
	_, err := svc.Test(context.Background())
	if err == nil || !strings.HasPrefix(err.Error(), "Тестовый sing-box не ответил за") {
		t.Fatalf("Test = %v, want the no-answer error", err)
	}

	prober.measure = func(ctx context.Context) (map[string]Delay, error) {
		<-ctx.Done()
		return map[string]Delay{"a": {Ms: 70, Status: LatencyOK}, "b": {Status: LatencyUnfinished}}, nil
	}
	svc, _ = newTestLatencyService(twoCandidates(nodeRouting("a")), prober, nil, nil)
	svc.limit = 50 * time.Millisecond
	report, err := svc.Test(context.Background())
	if err != nil {
		t.Fatalf("Test = %v", err)
	}
	if report.Answered != 1 || report.Results[1].Status != LatencyUnfinished {
		t.Fatalf("report = %+v", report)
	}
}

// A missing config.json or sing-box.exe says how to fix it
func TestLatencySetupHint(t *testing.T) {
	src := &fakeLatencySource{planErr: fmt.Errorf("%w at: C:\\data\\config.json", ErrConfigMissing), routings: []RoutingTarget{{}}}
	svc, _ := newTestLatencyService(src, &fakeLatencyProber{}, nil, nil)
	if _, err := svc.Test(context.Background()); err == nil || !strings.Contains(err.Error(), "«Первоначальная настройка»") {
		t.Fatalf("no config: %v", err)
	}

	svc, _ = newTestLatencyService(twoCandidates(nodeRouting("a")), &fakeLatencyProber{err: fmt.Errorf("%w at: C:\\bin\\sing-box.exe", ErrSingBoxMissing)}, nil, nil)
	if _, err := svc.Test(context.Background()); err == nil || !strings.Contains(err.Error(), "«Обновить sing-box»") {
		t.Fatalf("no sing-box: %v", err)
	}
}

// The measurement holds no lock the app waits for; the switch takes the
// operation lock, reads the routing again under it and calls use once
func TestSelectFastestLocksOnlyTheSwitch(t *testing.T) {
	lock := &trackingLock{}
	src := twoCandidates(nodeRouting("a"))
	src.lock = lock
	prober := twoServers()
	prober.lock = lock
	var used []string
	var usedHeld []bool
	use := func(tag string) (bool, error) {
		used = append(used, tag)
		usedHeld = append(usedHeld, lock.held.Load())
		return true, nil
	}
	svc, _ := newTestLatencyService(src, prober, use, lock)

	report, outcome, err := svc.SelectFastest(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(prober.heldAt, []bool{false}) {
		t.Errorf("the measurement ran with the lock held: %v", prober.heldAt)
	}
	if !reflect.DeepEqual(used, []string{"b"}) || !reflect.DeepEqual(usedHeld, []bool{true}) {
		t.Errorf("use called with %v, lock held %v; want once with b, under the lock", used, usedHeld)
	}
	if !reflect.DeepEqual(src.rtHeld, []bool{false, true}) {
		t.Errorf("routing read with the lock held: %v, want the check without it, the switch under it", src.rtHeld)
	}
	if lock.held.Load() {
		t.Error("the lock is still held")
	}
	if report == nil || report.Fastest != "b" {
		t.Errorf("report = %+v", report)
	}
	want := FastestOutcome{Tag: "b", Previous: "a", DelayMs: 100, PrevMs: 300, Switched: true, Restarted: true,
		Message: "Выбран самый быстрый — «b» (100 мс; был «a» — 300 мс), VPN перезапущен."}
	if *outcome != want {
		t.Errorf("outcome\n %+v\nwant\n %+v", *outcome, want)
	}
}

// The routing changed while the delays were measured (a section saved, a
// subscription refreshed): the decision follows the routing as it is now
func TestSelectFastestDecidesOnTheRoutingUnderTheLock(t *testing.T) {
	src := twoCandidates(nodeRouting("a"), RoutingTarget{Kind: RoutingURLTest, Tag: "auto", Groups: []string{"auto"}, Final: "auto"})
	calls := 0
	svc, _ := newTestLatencyService(src, twoServers(), func(string) (bool, error) { calls++; return false, nil }, &trackingLock{})
	_, outcome, err := svc.SelectFastest(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Switched || calls != 0 || !strings.Contains(outcome.Message, "urltest «auto»") {
		t.Fatalf("outcome %+v, use called %d times", outcome, calls)
	}
}

// Kept, refused or to be confirmed: nothing is saved
func TestSelectFastestWithoutASwitch(t *testing.T) {
	for name, rt := range map[string]RoutingTarget{
		"kept":       nodeRouting("b"),
		"refused":    {Kind: RoutingNode, Tag: "a", ProxyRefs: []string{"a", "b"}, Final: "b"},
		"to confirm": selectorRouting("proxy"),
	} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			svc, _ := newTestLatencyService(twoCandidates(rt), twoServers(), func(string) (bool, error) { calls++; return false, nil }, &trackingLock{})
			_, outcome, err := svc.SelectFastest(context.Background(), false)
			if err != nil || outcome.Switched || calls != 0 {
				t.Fatalf("outcome %+v, err %v, use called %d times", outcome, err, calls)
			}
		})
	}
}

// The fastest server was removed during the check (a subscription refresh):
// SwitchOutbound's error in the user's words; the report still comes back
func TestSelectFastestServerGone(t *testing.T) {
	svc, _ := newTestLatencyService(twoCandidates(nodeRouting("a")), twoServers(), func(tag string) (bool, error) {
		return false, fmt.Errorf("outbound %q %w", tag, ErrNoSuchOutbound)
	}, &trackingLock{})
	report, outcome, err := svc.SelectFastest(context.Background(), false)
	if err == nil || err.Error() != "Сервер «b» пропал из конфига во время проверки (обновилась подписка?) — повторите." {
		t.Fatalf("error = %v", err)
	}
	if report == nil || outcome != nil {
		t.Fatalf("report %v, outcome %v", report, outcome)
	}

	// Any other failure (the VPN restart after the switch) as it is
	restartErr := errors.New("outbound switched, but VPN failed to start")
	svc, _ = newTestLatencyService(twoCandidates(nodeRouting("a")), twoServers(), func(string) (bool, error) { return false, restartErr }, &trackingLock{})
	if _, _, err := svc.SelectFastest(context.Background(), false); !errors.Is(err, restartErr) {
		t.Fatalf("error = %v", err)
	}
}

// The DPI chain stays on the server it was enabled for: the outcome says so
// when that is the server switched away from
func TestSelectFastestDPIWas(t *testing.T) {
	for _, tc := range []struct {
		detours []string
		want    string
	}{
		{[]string{"a"}, "a"},
		{[]string{"c"}, ""},
		{nil, ""},
	} {
		src := twoCandidates(nodeRouting("a"))
		src.detours = tc.detours
		svc, _ := newTestLatencyService(src, twoServers(), func(string) (bool, error) { return false, nil }, &trackingLock{})
		_, outcome, err := svc.SelectFastest(context.Background(), false)
		if err != nil {
			t.Fatal(err)
		}
		if outcome.DPIWas != tc.want {
			t.Errorf("chain on %v: DPIWas = %q, want %q", tc.detours, outcome.DPIWas, tc.want)
		}
		if hint := strings.Contains(outcome.Message, "Обход DPI был включён для «a»"); hint != (tc.want != "") {
			t.Errorf("chain on %v: message %q", tc.detours, outcome.Message)
		}
	}
}

// The confirmation decides on the check it was asked about (a second
// measurement right after the first would be refused as too soon); a late
// one measures again
func TestSelectFastestConfirmation(t *testing.T) {
	src := &fakeLatencySource{
		plan:     &ProbePlan{Candidates: []LatencyCandidate{{Tag: "proxy", Type: "selector"}, candidate("a"), candidate("b")}},
		routings: []RoutingTarget{selectorRouting("proxy")},
	}
	prober := twoServers()
	var used []string
	svc, clock := newTestLatencyService(src, prober, func(tag string) (bool, error) { used = append(used, tag); return false, nil }, &trackingLock{})

	_, outcome, err := svc.SelectFastest(context.Background(), false)
	if err != nil || !outcome.NeedsConfirm || len(used) != 0 {
		t.Fatalf("outcome %+v, err %v, used %v", outcome, err, used)
	}
	clock.advance(5 * time.Second)
	_, outcome, err = svc.SelectFastest(context.Background(), true)
	if err != nil || !outcome.Switched || !reflect.DeepEqual(used, []string{"b"}) {
		t.Fatalf("confirmed: outcome %+v, err %v, used %v", outcome, err, used)
	}
	if prober.callCount() != 1 {
		t.Fatalf("the confirmation measured again (%d test instances)", prober.callCount())
	}

	clock.advance(config.FastestConfirmSeconds * time.Second)
	if _, _, err := svc.SelectFastest(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if prober.callCount() != 2 {
		t.Fatalf("a late confirmation did not measure again (%d test instances)", prober.callCount())
	}
}

// The page went away while a long operation held the lock: no switch
func TestSelectFastestCanceledWhileWaitingForTheLock(t *testing.T) {
	lock := &trackingLock{}
	calls := 0
	svc, _ := newTestLatencyService(twoCandidates(nodeRouting("a")), twoServers(), func(string) (bool, error) { calls++; return false, nil }, lock)

	lock.Lock() // a sing-box update, say
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, _, err := svc.SelectFastest(ctx, false)
		done <- err
	}()
	deadline := time.Now().Add(3 * time.Second)
	for lock.attempts.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	lock.Unlock()
	if err := <-done; !errors.Is(err, ErrLatencyCanceled) || calls != 0 {
		t.Fatalf("SelectFastest = %v, use called %d times", err, calls)
	}
}
