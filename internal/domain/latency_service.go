package domain

import (
	"context"
	"time"
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
)

// RoutingTarget is where the routing of config.json sends the traffic: the
// first route rule naming a proxy or a group, otherwise route.final, otherwise
// the first outbound (sing-box's default when route.final is not set)
type RoutingTarget struct {
	Kind string // RoutingNode, RoutingSelector, RoutingURLTest, or "" (no proxy, no group)
	Tag  string
	// ProxyRefs are the distinct proxy servers the rules and route.final
	// (or the default outbound) send traffic to, in order: switching the
	// active server repoints every one of them (SwitchOutbound), so with
	// two or more the routing is split between servers
	ProxyRefs []string
}

// LatencySource reads what the latency test needs from the config; it never
// writes
type LatencySource interface {
	ProbePlan() (*ProbePlan, error)
	RoutingTarget() (RoutingTarget, error)
	ActiveOutbound() (string, error)
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
