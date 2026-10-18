package domain

import (
	"context"
	"errors"
	"fmt"
	"log"
	"slices"
	"sync"
	"time"

	"tray-sing-box/internal/config"
)

// The latency test: every server's delay is measured by a separate,
// short-lived sing-box (the prober) started with a config built in memory
// from config.json (the source) — the running VPN, its start path and
// config.json are not touched, the test works with the VPN off as well
// (docs/design/latency-test.md). These are the models the source, the
// prober, the service and the UI share.

// LatencyStatus is the outcome of one server's measurement
type LatencyStatus string

const (
	LatencyOK         LatencyStatus = "ok"         // answered: Delay.Ms holds the time
	LatencyTimeout    LatencyStatus = "timeout"    // no answer within the probe timeout
	LatencyError      LatencyStatus = "error"      // the request through it failed
	LatencyUnfinished LatencyStatus = "unfinished" // the check ended before its answer came
	LatencySkipped    LatencyStatus = "skipped"    // not measured: not testable (LatencyCandidate.Note says why)
)

// Delay is the measurement of one server
type Delay struct {
	Ms     int
	Status LatencyStatus
	// Note is what the prober has to say about the server. LatencySkipped:
	// the note of the plan it finally ran — a server it left out because
	// sing-box could not start it on its own carries sing-box's reason, and
	// what depends on it says so (the plan the caller holds still calls
	// them testable). A test instance without that outbound (404) says so.
	Note string
}

// LatencyCandidate is an outbound of the config as the latency test sees it,
// in the order of the config
type LatencyCandidate struct {
	Tag, Type string
	// Testable: the test instance carries it, with everything it depends on
	Testable bool
	// Eligible: "select the fastest" may switch the routing to it
	Eligible bool
	// Note says, for the page, why it is not testable or not eligible, or
	// what to keep in mind about its delay
	Note string
}

// ProbePlan is the config of the test instance and what it may test
type ProbePlan struct {
	// Config is the whole config of the test instance but "experimental":
	// the prober adds its own clash_api (an address and a secret only it
	// knows)
	Config     map[string]any
	Candidates []LatencyCandidate
	// Redact replaces the credentials of the config, and the extra secrets
	// given (the prober's Clash API secret), where a text quotes them: every
	// output of the test instance passes through it before it reaches a
	// log, a popup or the page
	Redact func(text string, extra ...string) string
	// Exclude takes the output of a test instance that did not start
	// because sing-box could not create one outbound of Config on its own
	// ("initialize outbound[N]", "outbounds[N]"): the plan returned leaves
	// that outbound out, and every candidate that depends on it is no longer
	// testable, with sing-box's reason in its note. false when the output
	// names no outbound of Config: the failure is the config's as a whole.
	// The output must have passed Redact with the prober's own secrets (the
	// config's are removed here again).
	Exclude func(output string) (*ProbePlan, bool)
}

// The Kind of a RoutingTarget: what the routing sends the traffic to first
const (
	RoutingNode     = "node"     // a proxy server
	RoutingSelector = "selector" // a selector group: its choice is the user's
	RoutingURLTest  = "urltest"  // a urltest group: it picks the fastest member itself
	RoutingEndpoint = "endpoint" // an endpoint (WireGuard): the test does not measure it
)

// RoutingTarget is where the routing of config.json sends the traffic: the
// first route rule naming a proxy or a group, otherwise route.final, otherwise
// the first outbound (sing-box's default when route.final is not set); an
// endpoint when the routing names neither (next to a proxy or a group it
// takes what its rules send it, like direct: SwitchOutbound leaves it)
type RoutingTarget struct {
	Kind string // RoutingNode, RoutingSelector, RoutingURLTest, RoutingEndpoint, or "" (none of them)
	Tag  string
	// ProxyRefs are the distinct proxy servers the rules and route.final
	// (or the default outbound) send traffic to, in order: switching the
	// active server repoints every one of them (SwitchOutbound), so with
	// two or more the routing is split between servers
	ProxyRefs []string
	// Groups are the distinct selector and urltest groups the rules and
	// the final outbound name, in order. SwitchOutbound leaves them where
	// they are: next to a proxy or another group the routing is split too.
	Groups []string
	// Final is where the traffic no rule takes goes: route.final, or the
	// first outbound without it — any kind of outbound ("direct" as well)
	Final string
	// InRules: a route rule names Tag, it is not only the final outbound
	InRules bool
}

// LatencySource reads what the latency test needs from the config; it never
// writes
type LatencySource interface {
	ProbePlan() (*ProbePlan, error)
	RoutingTarget() (RoutingTarget, error)
	// DetourTargets are the outbounds whose detour is detourTag: the DPI
	// chain (mode A) is the detour "dpi-bypass" on the server it was
	// enabled for, and a switch away from that server leaves it there
	DetourTargets(detourTag string) ([]string, error)
}

// LatencyProber measures the delay of the given tags of a plan in a test
// instance of its own; a tag it did not get to is LatencyUnfinished
type LatencyProber interface {
	Measure(ctx context.Context, plan *ProbePlan, tags []string) (map[string]Delay, error)
}

// LatencyResult is one outbound of a LatencyReport
type LatencyResult struct {
	Tag      string        `json:"tag"`
	Type     string        `json:"type"`
	DelayMs  int           `json:"delay_ms,omitempty"`
	Status   LatencyStatus `json:"status"`
	Eligible bool          `json:"eligible"`
	Note     string        `json:"note,omitempty"`
}

// LatencyReport is the outcome of one latency check, kept in memory only
type LatencyReport struct {
	Tested   time.Time       `json:"tested"`
	Answered int             `json:"answered"`
	Total    int             `json:"total"`
	Active   string          `json:"active,omitempty"`
	Fastest  string          `json:"fastest,omitempty"`
	Results  []LatencyResult `json:"results"`
}

// FastestOutcome is what "select the fastest" decided and did
type FastestOutcome struct {
	Tag          string `json:"tag,omitempty"`
	Previous     string `json:"previous,omitempty"`
	DelayMs      int    `json:"delay_ms,omitempty"`
	PrevMs       int    `json:"prev_ms,omitempty"`
	Switched     bool   `json:"switched"`
	Restarted    bool   `json:"restarted"`
	NeedsConfirm bool   `json:"needs_confirm"`
	DPIWas       string `json:"dpi_was,omitempty"` // the DPI chain stayed on the previous node
	Message      string `json:"message"`           // ready Russian text
}

// The checks the service does not run, as the user reads them
var (
	ErrLatencyBusy     = errors.New("Проверка задержки уже идёт")
	ErrLatencyTooSoon  = errors.New("Повторите проверку через несколько секунд")
	ErrLatencyCanceled = errors.New("Проверка прервана")
)

// msgLatencyNoAnswer: the whole check ran out of time before the test
// instance answered (its own start timeout is shorter, but restarts — a
// taken port, a server left out — add up)
const msgLatencyNoAnswer = "Тестовый sing-box не ответил за %d с"

// LatencyService runs the latency test and "select the fastest". A check
// only reads the config (LatencySource) and runs a test instance of its own
// (LatencyProber): it holds no lock the rest of the app waits for — a
// subscription refresh, a sing-box update, the tray's "quit" go on meanwhile
// (the running sing-box.exe may be renamed by an update, and the process
// manager does not see the test instance). Only the switch to the fastest
// server takes the operation lock, the one every config change takes.
type LatencyService struct {
	src    LatencySource
	prober LatencyProber
	use    func(tag string) (restarted bool, err error)
	opLock sync.Locker

	// flight: one check at a time, "select the fastest" with its switch
	// included
	flight sync.Mutex

	mu    sync.Mutex
	last  *LatencyReport // kept in memory only
	ended time.Time      // when the last test instance was done
	// lastEnded: last is the report of that test instance (it may have
	// failed, leaving an older one)
	lastEnded bool
	// stale: the config last was measured on has changed since (the server
	// it chose is gone): still shown, never decided on again
	stale  bool
	cancel context.CancelFunc // of the running check, nil between checks

	// Test hooks
	now      func() time.Time
	limit    time.Duration // the measurement as a whole
	interval time.Duration // between the end of one test instance and the next
	reuse    time.Duration // a confirmation decides on a check this recent
}

// NewLatencyService creates the service. use routes the traffic through a
// server (SettingsService.UseOutbound: the config saved with its checks,
// backup and history, the VPN restarted when it runs); it is called under
// opLock, the lock that serializes every config change (nil: a lock of the
// service's own).
func NewLatencyService(src LatencySource, prober LatencyProber, use func(tag string) (restarted bool, err error), opLock sync.Locker) *LatencyService {
	if opLock == nil {
		opLock = &sync.Mutex{}
	}
	return &LatencyService{
		src:      src,
		prober:   prober,
		use:      use,
		opLock:   opLock,
		now:      time.Now,
		limit:    config.LatencyTestMaxSeconds * time.Second,
		interval: config.LatencyMinIntervalSeconds * time.Second,
		reuse:    config.FastestConfirmSeconds * time.Second,
	}
}

// Test measures the delay of every server of the config. One check at a
// time (ErrLatencyBusy), the test instances at least
// LatencyMinIntervalSeconds apart (ErrLatencyTooSoon: each one connects to
// every server from the user's address), at most LatencyTestMaxSeconds —
// what is not measured by then is LatencyUnfinished. The end of ctx (the
// page went away) or Cancel ends it: ErrLatencyCanceled, nothing kept.
func (s *LatencyService) Test(ctx context.Context) (*LatencyReport, error) {
	if !s.flight.TryLock() {
		return nil, ErrLatencyBusy
	}
	defer s.flight.Unlock()
	ctx, done := s.cancellable(ctx)
	defer done()
	return s.check(ctx)
}

// SelectFastest checks the delays (like Test) and routes the traffic
// through the fastest server when ChooseFastest says so. It decides on the
// last check instead of measuring again while that test instance ended less
// than LatencyMinIntervalSeconds ago ("check latency", then "select the
// fastest" next to it: a new one would be refused as too soon, and none
// could be fresher), and a confirmation (the question ChooseFastest asked
// about a selector group) on the check it was asked about, when that is at
// most FastestConfirmSeconds old (recent). The routing is read again under
// the operation lock, so the decision and the switch see the same config.
// The report comes back with an error from the switch too (GET /api/latency
// shows it as the last one).
func (s *LatencyService) SelectFastest(ctx context.Context, confirm bool) (*LatencyReport, *FastestOutcome, error) {
	if !s.flight.TryLock() {
		return nil, nil, ErrLatencyBusy
	}
	defer s.flight.Unlock()
	ctx, done := s.cancellable(ctx)
	defer done()

	report := s.recent(confirm)
	if report == nil {
		var err error
		if report, err = s.check(ctx); err != nil {
			return nil, nil, err
		}
	}

	s.opLock.Lock()
	defer s.opLock.Unlock()
	// The page may have gone, or the app quit, while a long operation held
	// the lock: nobody asks for the switch any more
	if ctx.Err() != nil {
		return report, nil, ErrLatencyCanceled
	}
	rt, err := s.src.RoutingTarget()
	if err != nil {
		return report, nil, withSetupHint(err)
	}
	outcome := ChooseFastest(report, rt, confirm)
	if !outcome.Switched {
		log.Printf("Latency: the fastest server is %q, the routing is left as it is (%s)", outcome.Tag, oneLine(outcome.Message))
		return report, &outcome, nil
	}

	restarted, err := s.use(outcome.Tag)
	if errors.Is(err, ErrNoSuchOutbound) {
		// The retry the message asks for must measure the new config, not
		// pick the same gone server from this report again
		s.mu.Lock()
		if s.last == report {
			s.stale = true
		}
		s.mu.Unlock()
		return report, nil, fmt.Errorf(msgFastestGone, DisplayName(outcome.Tag))
	}
	if err != nil {
		return report, nil, err
	}
	outcome.Restarted = restarted
	// The chain is the previous server's detour: the switch does not move
	// it, and the new server connects without zapret
	if outcome.Previous != "" && outcome.Previous != outcome.Tag {
		targets, err := s.src.DetourTargets(config.DPIBypassTag)
		if err != nil {
			log.Printf("Warning: latency: the DPI chain could not be read: %v", err)
		} else if slices.Contains(targets, outcome.Previous) {
			outcome.DPIWas = outcome.Previous
		}
	}
	outcome.Message = switchMessage(outcome, report)
	return report, &outcome, nil
}

// Last is the report of the last check, from the page or the tray (nil
// before the first one). It is kept in memory only.
func (s *LatencyService) Last() *LatencyReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}

// Cancel ends a running check (the app quits: the test instance would die
// with the app anyway, its job kills it — this is for speed)
func (s *LatencyService) Cancel() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
	}
}

// cancellable is ctx as Cancel can end it, for one check
func (s *LatencyService) cancellable(parent context.Context) (context.Context, func()) {
	ctx, cancel := context.WithCancel(parent)
	s.mu.Lock()
	s.cancel = cancel
	s.mu.Unlock()
	return ctx, func() {
		s.mu.Lock()
		s.cancel = nil
		s.mu.Unlock()
		cancel()
	}
}

// recent is the last report when "select the fastest" may decide on it
// without measuring again: the last test instance made it and ended less
// than the interval ago, or the request is a confirmation within the reuse
// time of the check it was asked about
func (s *LatencyService) recent(confirm bool) *LatencyReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.last == nil || s.stale:
		return nil
	case s.lastEnded && s.now().Sub(s.ended) < s.interval:
		return s.last
	case confirm && s.now().Sub(s.last.Tested) <= s.reuse:
		return s.last
	}
	return nil
}

// check is one measurement; callers hold flight. A config without a server
// to test gets its report at once: no test instance, no interval.
func (s *LatencyService) check(ctx context.Context) (*LatencyReport, error) {
	plan, err := s.src.ProbePlan()
	if err != nil {
		return nil, withSetupHint(err)
	}
	rt, err := s.src.RoutingTarget()
	if err != nil {
		return nil, withSetupHint(err)
	}

	var delays map[string]Delay
	measured := slices.ContainsFunc(plan.Candidates, func(c LatencyCandidate) bool { return c.Testable })
	if measured {
		s.mu.Lock()
		soon := !s.ended.IsZero() && s.now().Sub(s.ended) < s.interval
		s.mu.Unlock()
		if soon {
			return nil, ErrLatencyTooSoon
		}

		mctx, cancel := context.WithTimeout(ctx, s.limit)
		delays, err = s.prober.Measure(mctx, plan, probeOrder(plan, rt))
		cancel()
		s.mu.Lock()
		s.ended, s.lastEnded = s.now(), false
		s.mu.Unlock()
		if ctx.Err() != nil {
			return nil, ErrLatencyCanceled
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf(msgLatencyNoAnswer, int(s.limit.Round(time.Second)/time.Second))
		}
		if err != nil {
			return nil, withSetupHint(err)
		}
	}

	report := buildReport(plan, rt, delays, s.now())
	s.mu.Lock()
	s.last, s.lastEnded, s.stale = report, measured, false
	s.mu.Unlock()
	return report, nil
}

// probeOrder is the order the servers are measured in: the ones the routing
// uses now first — with hundreds of servers the deadline may come before
// the last ones — then the rest in the order of the config
func probeOrder(plan *ProbePlan, rt RoutingTarget) []string {
	known := make(map[string]bool, len(plan.Candidates))
	for _, c := range plan.Candidates {
		known[c.Tag] = true
	}
	tags := make([]string, 0, len(plan.Candidates))
	seen := make(map[string]bool, len(plan.Candidates))
	add := func(tag string) {
		if known[tag] && !seen[tag] {
			seen[tag] = true
			tags = append(tags, tag)
		}
	}
	for _, tag := range rt.ProxyRefs {
		add(tag)
	}
	for _, c := range plan.Candidates {
		add(c.Tag)
	}
	return tags
}

// buildReport is the report of a check: every candidate in the order of the
// config, its delay as the prober measured it (nil delays: nothing was
// measured). A testable server the prober has no answer for did not get its
// turn. Total counts the servers that were to be measured, Answered the ones
// that answered.
func buildReport(plan *ProbePlan, rt RoutingTarget, delays map[string]Delay, tested time.Time) *LatencyReport {
	r := &LatencyReport{Tested: tested, Results: []LatencyResult{}}
	if rt.Kind == RoutingNode {
		r.Active = rt.Tag
	}
	seen := make(map[string]bool, len(plan.Candidates))
	for _, c := range plan.Candidates {
		if seen[c.Tag] {
			continue
		}
		seen[c.Tag] = true
		res := LatencyResult{Tag: c.Tag, Type: c.Type, Status: LatencySkipped, Eligible: c.Eligible, Note: c.Note}
		if c.Testable {
			r.Total++
			res.Status = LatencyUnfinished
			if d, ok := delays[c.Tag]; ok {
				res.Status = d.Status
				if d.Status == LatencyOK {
					res.DelayMs = d.Ms
					r.Answered++
				}
				// What the test instance found (left out: sing-box's reason)
				if d.Note != "" {
					res.Note = d.Note
				}
			}
		}
		r.Results = append(r.Results, res)
	}
	if best := r.fastest(); best != nil {
		r.Fastest = best.Tag
	}
	return r
}
