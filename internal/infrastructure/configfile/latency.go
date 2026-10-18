package configfile

import (
	"fmt"
	"maps"
	"strings"

	"tray-sing-box/internal/config"
	"tray-sing-box/internal/domain"
)

// The latency test's view of the config (docs/design/latency-test.md §3.3).
// The delays are measured by a separate sing-box started with a config built
// here, in memory: the outbounds to test with everything they need to dial —
// the outbounds they dial through, the DNS servers that resolve their
// servers, the certificate store — and nothing else: no inbound (no TUN, no
// listener but the Clash API the prober adds), no rules, rule sets, cache
// file, log file or services. Every object is copied as config.json has it,
// so the test instance runs a part of what the same sing-box already runs as
// the VPN; an outbound that needs anything that is never copied — an
// endpoint, a type outside the guard's allow-list, a Hysteria 2 realm, a DNS
// server of an endpoint or a service, a network namespace — is not tested.
// Keys are read the way sing-box reads them (foldKey): to sing-box
// {"Detour": "x"} is a detour, and the outbound must not reach the test
// instance without "x".

// The notes of the candidates, shown on the page next to the server
const (
	noteSelector  = "группа — проверяются её серверы"
	noteURLTest   = "группа urltest — выбирает сервер сама"
	noteRelayOnly = "промежуточный узел, только через detour"
	noteType      = "тип «%s» не проверяется"
	noteDepends   = "не проверяется: зависит от «%s»"
	noteFailed    = "не проверяется: sing-box не смог его запустить отдельно: %s"
	noteDPI       = "обход DPI без VPN — не выбирается самым быстрым"
	noteLocal     = "сервер на этом компьютере"
	noteRelay     = "промежуточный узел цепочки — не выбирается самым быстрым"
	// The node dials its server through zapret, the others directly
	noteViaDPI = "проверяется через обход DPI — сравнение с остальными неравное"
)

// probeDNSTypes are the DNS server types the test instance may carry: the
// ones that need nothing but the network. tailscale, openconnect and
// openvpn resolve through an endpoint, resolved is a service — neither is
// copied; a type sing-box adds later is not tested until it is known here.
// "" and "legacy" are the server format before sing-box 1.12 (address,
// address_resolver).
var probeDNSTypes = map[string]bool{
	"": true, "legacy": true, "udp": true, "tcp": true, "tls": true, "https": true,
	"quic": true, "h3": true, "local": true, "hosts": true, "fakeip": true,
	"dhcp": true, "mdns": true,
}

// ProbePlan builds the config of the latency test instance from config.json
// and classifies its outbounds (probePlan). The file is only read: no backup,
// no history entry, nothing written. The plan is built from the decoded copy
// after the lock is released: no save waits for it.
func (e *Editor) ProbePlan() (*domain.ProbePlan, error) {
	e.mu.Lock()
	cfg, _, err := e.load()
	e.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return probePlan(cfg), nil
}

// RoutingTarget tells where the routing of config.json sends the traffic
// (routingTarget)
func (e *Editor) RoutingTarget() (domain.RoutingTarget, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	cfg, _, err := e.load()
	if err != nil {
		return domain.RoutingTarget{}, err
	}
	return routingTarget(cfg), nil
}

// probePlan is the plan of the latency test for a decoded config: every
// tagged outbound as a candidate, in the order of the config, and the
// config of the test instance (see buildProbePlan). cfg is not modified, and
// the plan shares nothing with it.
func probePlan(cfg map[string]any) *domain.ProbePlan {
	snapshot, _ := deepCopy(cfg).(map[string]any)
	return buildProbePlan(snapshot, nil)
}

// probeRef is a node of the closure: an outbound or a DNS server, by tag
type probeRef struct {
	dns bool
	tag string
}

// probeIndex is a config indexed for the closure
type probeIndex struct {
	outbounds   []map[string]any            // the tagged outbounds, in order
	byTag       map[string][]map[string]any // sing-box refuses a tag used twice; all of them are looked at
	edges       map[string][]string         // detours and group members (dependencyGraph)
	dns         map[string]any              // the dns section, nil without one
	servers     []map[string]any            // its servers, in order
	serverByTag map[string][]map[string]any
	route       map[string]any
	// failed are the outbounds a test instance could not create (Exclude),
	// with the reason
	failed map[string]string
	// visits caches what visit said about a ref (but a candidate's own
	// visit): hundreds of nodes dialing through one group would otherwise
	// read every member's keys once per node
	visits map[probeRef]visitResult
}

type visitResult struct {
	next    []probeRef
	problem string
}

func indexProbe(cfg map[string]any, failed map[string]string) *probeIndex {
	x := &probeIndex{
		byTag:       map[string][]map[string]any{},
		edges:       dependencyGraph(cfg),
		dns:         foldedObject(cfg, "dns"),
		serverByTag: map[string][]map[string]any{},
		route:       foldedObject(cfg, "route"),
		failed:      failed,
		visits:      map[probeRef]visitResult{},
	}
	each(cfg, "outbounds", func(o map[string]any) {
		if tag := foldedString(o, "tag"); tag != "" {
			x.outbounds = append(x.outbounds, o)
			x.byTag[tag] = append(x.byTag[tag], o)
		}
	})
	if x.dns != nil {
		each(x.dns, "servers", func(s map[string]any) {
			x.servers = append(x.servers, s)
			tag := foldedString(s, "tag")
			x.serverByTag[tag] = append(x.serverByTag[tag], s)
		})
	}
	return x
}

// globals are the DNS servers every outbound may need: the one that
// resolves server names for outbounds without a domain_resolver of their own
// (route.default_domain_resolver), and the default server — dns.final, or
// without it the first server (sing-box's own choice, dns/transport_manager.go;
// with a single server that is the one, R8 of the design). The DNS rules that
// might send a query elsewhere are not copied.
func (x *probeIndex) globals() []probeRef {
	var refs []probeRef
	if x.dns != nil {
		if final := foldedString(x.dns, "final"); final != "" {
			refs = append(refs, probeRef{dns: true, tag: final})
		} else if len(x.servers) > 0 {
			refs = append(refs, probeRef{dns: true, tag: foldedString(x.servers[0], "tag")})
		}
	}
	if x.route != nil {
		refs = append(refs, resolverRefs(x.route, "default_domain_resolver")...)
	}
	return refs
}

// walk follows the refs from start to a fixed point: an outbound to its
// detour, a group's members and its domain_resolver; a DNS server to its
// detour and its domain_resolver. It returns the refs reached and the first
// one, in the order of the walk, the test instance cannot carry, named for
// the note: "" when there is none. own is the tag of the candidate the walk
// starts from: for a field of its own the note names what it depends on,
// not itself.
func (x *probeIndex) walk(start []probeRef, own string) (map[probeRef]bool, string) {
	reached := map[probeRef]bool{}
	var queue []probeRef
	for _, r := range start {
		if !reached[r] {
			reached[r] = true
			queue = append(queue, r)
		}
	}
	for len(queue) > 0 {
		r := queue[0]
		queue = queue[1:]
		var next []probeRef
		var problem string
		if own != "" && !r.dns && r.tag == own {
			next, problem = x.visit(r, true)
		} else {
			result, done := x.visits[r]
			if !done {
				result.next, result.problem = x.visit(r, false)
				x.visits[r] = result
			}
			next, problem = result.next, result.problem
		}
		if problem != "" {
			return reached, problem
		}
		for _, n := range next {
			if !reached[n] {
				reached[n] = true
				queue = append(queue, n)
			}
		}
	}
	return reached, ""
}

// visit returns what one ref depends on, or why the test instance cannot
// carry it
func (x *probeIndex) visit(r probeRef, own bool) ([]probeRef, string) {
	var next []probeRef
	if r.dns {
		list := x.serverByTag[r.tag]
		if len(list) == 0 {
			return nil, r.tag // no such server: sing-box would not start
		}
		for _, s := range list {
			if typ, ok := dnsType(s); !ok || !probeDNSTypes[typ] {
				return nil, r.tag
			}
			if foldedString(s, "netns") != "" {
				return nil, r.tag
			}
			for _, detour := range stringValues(s, "detour") {
				next = append(next, probeRef{tag: detour})
			}
			next = append(next, resolverRefs(s, "domain_resolver")...)
			next = append(next, resolverRefs(s, "address_resolver")...)
		}
		return next, ""
	}

	list := x.byTag[r.tag]
	if len(list) == 0 {
		// An endpoint (none is copied), or a tag sing-box would not find
		return nil, r.tag
	}
	if _, failed := x.failed[r.tag]; failed && !own {
		return nil, r.tag
	}
	for _, o := range list {
		if typ, ok := singleType(o); !ok || !allowedOutboundTypes[typ] {
			return nil, r.tag
		}
		// A Hysteria 2 realm may name a shared HTTP client (http_clients),
		// which is not copied
		if realm, ok := foldedField(o, "realm"); ok && realm != nil {
			if own {
				return nil, "realm"
			}
			return nil, r.tag
		}
		if netns := foldedString(o, "netns"); netns != "" {
			if own {
				return nil, netns
			}
			return nil, r.tag
		}
		next = append(next, resolverRefs(o, "domain_resolver")...)
	}
	for _, dep := range x.edges[r.tag] {
		next = append(next, probeRef{tag: dep})
	}
	return next, ""
}

// buildProbePlan classifies the outbounds of cfg (the table of §3.3 of the
// design, the first row that applies) and builds the config of the test
// instance from the closures of the testable ones. failed are the outbounds
// earlier test instances could not create (Exclude), by tag. cfg is the
// plan's own copy and is never modified.
func buildProbePlan(cfg map[string]any, failed map[string]string) *domain.ProbePlan {
	x := indexProbe(cfg, failed)
	global, globalProblem := x.walk(x.globals(), "")
	relays := relayTags(cfg, nil)

	plan := &domain.ProbePlan{}
	needed := map[probeRef]bool{}
	testable := false
	listed := map[string]bool{}
	for _, o := range x.outbounds {
		tag := foldedString(o, "tag")
		if listed[tag] {
			continue
		}
		listed[tag] = true
		c := domain.LatencyCandidate{Tag: tag, Type: foldedString(o, "type")}
		if reached := x.classify(o, &c, globalProblem, relays); c.Testable {
			testable = true
			for r := range reached {
				needed[r] = true
			}
		}
		plan.Candidates = append(plan.Candidates, c)
	}
	if testable {
		for r := range global {
			needed[r] = true
		}
	}

	probe := map[string]any{"log": map[string]any{"level": "warn"}}
	outbounds := []any{}
	var tags []string // the tag of each outbound of the test instance, for Exclude
	for _, o := range x.outbounds {
		if tag := foldedString(o, "tag"); needed[probeRef{tag: tag}] {
			outbounds = append(outbounds, deepCopy(o))
			tags = append(tags, tag)
		}
	}
	probe["outbounds"] = outbounds
	if x.dns != nil && testable {
		dns := map[string]any{}
		for k, v := range x.dns {
			switch foldKey(k) {
			case "rules", "servers":
				continue
			}
			dns[k] = deepCopy(v)
		}
		var servers []any
		for _, s := range x.servers {
			if needed[probeRef{dns: true, tag: foldedString(s, "tag")}] {
				servers = append(servers, deepCopy(s))
			}
		}
		if len(servers) > 0 {
			dns["servers"] = servers
		}
		if len(dns) > 0 {
			probe["dns"] = dns
		}
	}
	if certificate, ok := foldedField(cfg, "certificate"); ok {
		probe["certificate"] = deepCopy(certificate)
	}
	// Dialing past the VPN's TUN the way the VPN dials its own servers
	route := map[string]any{"auto_detect_interface": true}
	if x.route != nil {
		for _, name := range []string{"default_interface", "default_domain_resolver"} {
			if v, ok := foldedField(x.route, name); ok {
				route[name] = deepCopy(v)
			}
		}
	}
	probe["route"] = route
	plan.Config = probe

	plan.Redact = func(text string, extra ...string) string {
		// The whole config.json, not only what is copied: an output kept
		// from an earlier test instance may quote a node excluded since. The
		// extra secrets go in under the clash API's key (secretKeys)
		secrets := make([]any, len(extra))
		for i, s := range extra {
			secrets[i] = s
		}
		return redactSecrets(text, []any{cfg, map[string]any{"secret": secrets}})
	}
	plan.Exclude = func(output string) (*domain.ProbePlan, bool) {
		n, ok := refusedIndex(output)
		if !ok || n < 0 || n >= len(tags) {
			return nil, false
		}
		next := maps.Clone(failed)
		if next == nil {
			next = map[string]string{}
		}
		next[tags[n]] = plan.Redact(excludedReason(checkMessage(output)))
		return buildProbePlan(cfg, next), true
	}
	return plan
}

// classify fills in the candidate for the outbound o and returns, for a
// testable one, the refs its closure reaches (the globals aside)
func (x *probeIndex) classify(o map[string]any, c *domain.LatencyCandidate, globalProblem string, relays map[string]bool) map[probeRef]bool {
	typ, single := singleType(o)
	switch {
	case !single:
		c.Note = fmt.Sprintf(noteType, strings.Join(typeValues(o), ","))
		return nil
	case typ == "direct" || typ == "block" || typ == "dns":
		return nil
	case typ == "selector":
		c.Note = noteSelector
		return nil
	case typ == "urltest":
		c.Note = noteURLTest
		return nil
	case relayOnlyTypes[typ]:
		c.Note = noteRelayOnly
		return nil
	case !allowedOutboundTypes[typ]:
		c.Note = fmt.Sprintf(noteType, typ)
		return nil
	}
	if reason, failed := x.failed[c.Tag]; failed {
		c.Note = fmt.Sprintf(noteFailed, reason)
		return nil
	}
	reached, problem := x.walk([]probeRef{{tag: c.Tag}}, c.Tag)
	if problem == "" {
		problem = globalProblem
	}
	switch {
	case problem != "":
		c.Note = fmt.Sprintf(noteDepends, problem)
		return nil
	case c.Tag == config.DPIBypassTag:
		c.Testable, c.Note = true, noteDPI
	case localServer(o):
		// The info node of 3x-ui and the like: nothing to measure
		c.Note = noteLocal
		return nil
	case relays[c.Tag]:
		c.Testable, c.Note = true, noteRelay
	default:
		c.Testable, c.Eligible = true, true
		if reached[probeRef{tag: config.DPIBypassTag}] {
			c.Note = noteViaDPI
		}
	}
	return reached
}

// excludedReason is what sing-box said about the outbound it could not
// create: its message after the outbound's position
func excludedReason(message string) string {
	if loc := indexedEntry.FindStringIndex(message); loc != nil {
		if rest := strings.TrimLeft(message[loc[1]:], ":. "); rest != "" {
			return rest
		}
	}
	return message
}

// routingTarget is where the routing sends the traffic: the first top-level
// route rule naming a proxy or a group, then route.final — or, without it,
// the first outbound, sing-box's default then. ProxyRefs are the distinct
// proxies among all of them, the ones SwitchOutbound would repoint.
func routingTarget(cfg map[string]any) domain.RoutingTarget {
	kinds := map[string]string{} // tag -> kind, "" for direct/block/dns and relays
	first, firstSeen := "", false
	each(cfg, "outbounds", func(o map[string]any) {
		tag := foldedString(o, "tag")
		if !firstSeen {
			first, firstSeen = tag, true
		}
		if _, known := kinds[tag]; known || tag == "" {
			return
		}
		switch typ := foldedString(o, "type"); {
		case typ == "selector":
			kinds[tag] = domain.RoutingSelector
		case typ == "urltest":
			kinds[tag] = domain.RoutingURLTest
		case !systemTypes[typ] && !relayOnlyTypes[typ]:
			kinds[tag] = domain.RoutingNode
		default:
			kinds[tag] = ""
		}
	})

	var refs []string
	final := ""
	if route := foldedObject(cfg, "route"); route != nil {
		each(route, "rules", func(rule map[string]any) {
			if out := foldedString(rule, "outbound"); out != "" {
				refs = append(refs, out)
			}
		})
		final = foldedString(route, "final")
	}
	if final == "" {
		final = first
	}
	if final != "" {
		refs = append(refs, final)
	}

	var rt domain.RoutingTarget
	seen := map[string]bool{}
	for _, ref := range refs {
		kind := kinds[ref]
		if kind == "" {
			continue
		}
		if rt.Kind == "" {
			rt.Kind, rt.Tag = kind, ref
		}
		if kind == domain.RoutingNode && !seen[ref] {
			seen[ref] = true
			rt.ProxyRefs = append(rt.ProxyRefs, ref)
		}
	}
	return rt
}

// singleType is the outbound's type when it has exactly one type key with a
// string (with two spellings sing-box takes the later one, whose order is
// not kept here)
func singleType(o map[string]any) (string, bool) {
	values := fieldValues(o, "type")
	if len(values) != 1 {
		return "", false
	}
	s, ok := values[0].(string)
	return s, ok
}

// typeValues are the type keys' values of an object, for a note
func typeValues(o map[string]any) []string {
	var types []string
	for _, v := range fieldValues(o, "type") {
		types = append(types, fmt.Sprint(v))
	}
	return types
}

// dnsType is a DNS server's type: "" without a type key (the format before
// sing-box 1.12)
func dnsType(s map[string]any) (string, bool) {
	if len(fieldValues(s, "type")) == 0 {
		return "", true
	}
	return singleType(s)
}

// resolverRefs are the DNS servers a domain_resolver names (a tag, or an
// object with the tag as server), at every key that folds to name
func resolverRefs(m map[string]any, name string) []probeRef {
	var refs []probeRef
	for _, v := range fieldValues(m, name) {
		var server string
		switch r := v.(type) {
		case string:
			server = r
		case map[string]any:
			server = foldedString(r, "server")
		}
		if server != "" {
			refs = append(refs, probeRef{dns: true, tag: server})
		}
	}
	return refs
}

// stringValues are the non-empty strings at every key of m that folds to
// name
func stringValues(m map[string]any, name string) []string {
	var found []string
	for _, v := range fieldValues(m, name) {
		if s, ok := v.(string); ok && s != "" {
			found = append(found, s)
		}
	}
	return found
}

// foldedField is the value at the key of m that folds to name: the one
// spelled exactly so when there are several, otherwise the first in sorted
// order (as foldedString)
func foldedField(m map[string]any, name string) (any, bool) {
	if v, ok := m[name]; ok {
		return v, true
	}
	if values := fieldValues(m, name); len(values) > 0 {
		return values[0], true
	}
	return nil, false
}

// foldedObject is the object at the key of m that folds to name, nil when
// there is none
func foldedObject(m map[string]any, name string) map[string]any {
	v, _ := foldedField(m, name)
	o, _ := v.(map[string]any)
	return o
}

// deepCopy copies the objects and arrays of a decoded config; the other
// values (strings, json.Number, bools, nil) are immutable
func deepCopy(v any) any {
	switch x := v.(type) {
	case map[string]any:
		c := make(map[string]any, len(x))
		for k, child := range x {
			c[k] = deepCopy(child)
		}
		return c
	case []any:
		c := make([]any, len(x))
		for i, child := range x {
			c[i] = deepCopy(child)
		}
		return c
	}
	return v
}
