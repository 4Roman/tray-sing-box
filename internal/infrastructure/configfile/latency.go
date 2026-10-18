package configfile

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"tray-sing-box/internal/config"
	"tray-sing-box/internal/domain"
)

// The latency test's view of the config (docs/design/latency-test.md §3.3).
// The delays are measured by a separate sing-box started with a config built
// here, in memory: the outbounds to test with everything they need to dial —
// the outbounds they dial through, the DNS servers that resolve their
// servers (and the DNS rules that pick them, where only the outbound
// decides), the certificate store — and nothing else: no inbound (no TUN, no
// listener but the Clash API the prober adds), no route rules, rule sets,
// cache file, log file or services. Every object is copied as config.json
// has it (a group the test instance carries only for the config's sake
// without the members it cannot carry), so the test instance runs a part of
// what the same sing-box already runs as the VPN; an outbound that needs
// anything that is never copied — an endpoint, a type outside the guard's
// allow-list, a Hysteria 2 realm, a DNS server of an endpoint or a service,
// a network namespace, a DNS rule that decides by more than the outbound —
// is not tested. Keys are read the way sing-box reads them (foldKey): to
// sing-box {"Detour": "x"} is a detour, and the outbound must not reach the
// test instance without "x".

// The notes of the candidates, shown on the page next to the server
const (
	noteSelector  = "группа — проверяются её серверы"
	noteURLTest   = "группа urltest — выбирает сервер сама"
	noteRelayOnly = "промежуточный узел, только через detour"
	noteType      = "тип «%s» не проверяется"
	noteDepends   = "не проверяется: зависит от «%s»"
	noteFailed    = "не проверяется: sing-box не смог его запустить отдельно: %s"
	noteDNSRules  = "не проверяется: имя его сервера разрешается по правилам DNS, которые проверка повторить не может"
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

// problemDNSRules is what visit says of the candidate itself when the DNS
// rules resolve its server's name in a way the test cannot repeat (an
// outbound dialing through it is told its tag instead)
const problemDNSRules = "\x00dns rules"

// dnsRuleActionKeys are the keys of a DNS rule that belong to its action
// "route" or "route-options" (option/rule_action.go), not to its condition
var dnsRuleActionKeys = map[string]bool{
	"action": true, "server": true, "speculative": true, "strategy": true, "timeout": true,
	"disable_cache": true, "disable_optimistic_cache": true, "rewrite_ttl": true,
	"client_subnet": true, "remove_client_subnet": true,
}

// probeIndex is a config indexed for the closure
type probeIndex struct {
	outbounds   []map[string]any            // the tagged outbounds, in order
	byTag       map[string][]map[string]any // sing-box refuses a tag used twice; all of them are looked at
	detours     map[string][]string         // the outbounds an outbound or endpoint dials through
	members     map[string][]string         // a group's members (dependencyNodes)
	dns         map[string]any              // the dns section, nil without one
	servers     []map[string]any            // its servers, in order
	serverByTag map[string][]map[string]any
	route       map[string]any
	// defaultServer is the DNS server sing-box falls back to: dns.final, or
	// without it the first server (dns/transport_manager.go); "" without
	// servers
	defaultServer string
	// resolvers are the servers route.default_domain_resolver names
	resolvers []probeRef
	// defaultOut is the outbound sing-box dials through where nothing else
	// is said (defaultOutbound); defaultOutKnown is false when that is an
	// outbound without a tag
	defaultOut      string
	defaultOutKnown bool
	// rules are the top-level DNS rules; rulesAmbiguous: two keys spell
	// "rules", and which one sing-box reads depends on their order in the
	// file, which is not kept
	rules          []any
	rulesAmbiguous bool
	// failed are the outbounds a test instance could not create (Exclude),
	// with the reason
	failed map[string]string
	// visits caches what visit said about a ref (but a candidate's own
	// visit): hundreds of nodes dialing through one group would otherwise
	// read every member's keys once per node
	visits map[probeRef]visitResult
}

// visitResult is what one ref depends on
type visitResult struct {
	// next are what it cannot do without: a detour, a domain resolver, the
	// DNS server that resolves its server's name, a DNS server's detour
	next []probeRef
	// members are a group's members: sing-box dials through the one
	// selected, and a group the test instance carries only for the
	// config's sake keeps the ones it can carry (carriedGlobals)
	members []probeRef
	group   bool
	problem string
}

func indexProbe(cfg map[string]any, failed map[string]string) *probeIndex {
	x := &probeIndex{
		byTag:       map[string][]map[string]any{},
		detours:     map[string][]string{},
		members:     map[string][]string{},
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
	for _, n := range dependencyNodes(cfg) {
		for _, d := range n.deps {
			if d.group {
				x.members[n.tag] = append(x.members[n.tag], d.tag)
			} else {
				x.detours[n.tag] = append(x.detours[n.tag], d.tag)
			}
		}
	}
	if x.dns != nil {
		each(x.dns, "servers", func(s map[string]any) {
			x.servers = append(x.servers, s)
			tag := foldedString(s, "tag")
			x.serverByTag[tag] = append(x.serverByTag[tag], s)
		})
		if final := foldedString(x.dns, "final"); final != "" {
			x.defaultServer = final
		} else if len(x.servers) > 0 {
			x.defaultServer = foldedString(x.servers[0], "tag")
		}
		lists := fieldValues(x.dns, "rules")
		x.rulesAmbiguous = len(lists) > 1
		if len(lists) == 1 {
			x.rules, _ = lists[0].([]any)
		}
	}
	if x.route != nil {
		x.resolvers = resolverRefs(x.route, "default_domain_resolver")
	}
	x.defaultOut, x.defaultOutKnown = defaultOutbound(cfg, x.route)
	return x
}

// globals are the DNS servers every outbound may need: the default server —
// dns.final, or without it the first server (R8 of the design) — and the one
// route.default_domain_resolver names. The test instance carries them for
// the config's sake when it can (carriedGlobals); a server of the test
// needs one only when it resolves its server's name through it
// (nameResolution), and then it is part of its own closure.
func (x *probeIndex) globals() []probeRef {
	var refs []probeRef
	if x.defaultServer != "" {
		refs = append(refs, probeRef{dns: true, tag: x.defaultServer})
	}
	return append(refs, x.resolvers...)
}

// walk follows the refs from start to a fixed point: an outbound to its
// detour, a group's members, its domain_resolver and the DNS server that
// resolves its server's name; a DNS server to its detour and its
// domain_resolver. It returns the refs reached and the first one, in the
// order of the walk, the test instance cannot carry, named for the note: ""
// when there is none. own is the tag of the candidate the walk starts from:
// for a field of its own the note names what it depends on, not itself.
func (x *probeIndex) walk(start []probeRef, own string) (map[probeRef]bool, string) {
	reached := map[probeRef]bool{}
	var queue []probeRef
	add := func(refs []probeRef) {
		for _, r := range refs {
			if !reached[r] {
				reached[r] = true
				queue = append(queue, r)
			}
		}
	}
	add(start)
	for len(queue) > 0 {
		r := queue[0]
		queue = queue[1:]
		var result visitResult
		if own != "" && !r.dns && r.tag == own {
			result = x.visit(r, true)
		} else {
			result = x.cachedVisit(r)
		}
		if result.problem != "" {
			return reached, result.problem
		}
		add(result.next)
		add(result.members)
	}
	return reached, ""
}

// cachedVisit is visit of a ref that is not the candidate's own
func (x *probeIndex) cachedVisit(r probeRef) visitResult {
	result, done := x.visits[r]
	if !done {
		result = x.visit(r, false)
		x.visits[r] = result
	}
	return result
}

// carriedGlobals are the refs the test instance carries for the config's
// sake: the globals and what they need, where they can be carried. A
// group on the way keeps the members that can be carried — the main
// selector as the detour of dns.final must not take every server along
// for one member that sing-box cannot create on its own, or an endpoint
// among them — and the test instance gets it copied so
// (probeOutbound). A global that cannot be carried is left out: no server
// of the test resolves through it (one that does has it in its own
// closure and is not tested).
func (x *probeIndex) carriedGlobals() map[probeRef]bool {
	// Everything the globals may reach
	universe := map[probeRef]visitResult{}
	queue := x.globals()
	for len(queue) > 0 {
		r := queue[0]
		queue = queue[1:]
		if _, seen := universe[r]; seen {
			continue
		}
		result := x.cachedVisit(r)
		universe[r] = result
		if result.problem == "" {
			queue = append(queue, result.next...)
			queue = append(queue, result.members...)
		}
	}
	// The greatest set of refs that can be carried: no problem of their
	// own, everything they need carried, a group with a member carried
	// (sing-box refuses a group without one). A ring stays (sing-box judges
	// it as it judges config.json).
	ok := map[probeRef]bool{}
	for r, result := range universe {
		if result.problem == "" {
			ok[r] = true
		}
	}
	for changed := true; changed; {
		changed = false
		for r := range ok {
			result := universe[r]
			carried := !slices.ContainsFunc(result.next, func(n probeRef) bool { return !ok[n] })
			if carried && result.group {
				carried = slices.ContainsFunc(result.members, func(m probeRef) bool { return ok[m] })
			}
			if !carried {
				delete(ok, r)
				changed = true
			}
		}
	}
	// What the globals that can be carried reach through them
	reached := map[probeRef]bool{}
	queue = nil
	for _, r := range x.globals() {
		if ok[r] {
			queue = append(queue, r)
		}
	}
	for len(queue) > 0 {
		r := queue[0]
		queue = queue[1:]
		if reached[r] {
			continue
		}
		reached[r] = true
		result := universe[r]
		queue = append(queue, result.next...)
		for _, m := range result.members {
			if ok[m] {
				queue = append(queue, m)
			}
		}
	}
	return reached
}

// visit returns what one ref depends on, or why the test instance cannot
// carry it
func (x *probeIndex) visit(r probeRef, own bool) visitResult {
	var result visitResult
	if r.dns {
		list := x.serverByTag[r.tag]
		if len(list) == 0 {
			return visitResult{problem: r.tag} // no such server: sing-box would not start
		}
		for _, s := range list {
			typ, ok := dnsType(s)
			if !ok || !probeDNSTypes[typ] {
				return visitResult{problem: r.tag}
			}
			if foldedString(s, "netns") != "" {
				return visitResult{problem: r.tag}
			}
			detours := stringValues(s, "detour")
			for _, detour := range detours {
				result.next = append(result.next, probeRef{tag: detour})
			}
			// A server of the format before sing-box 1.14 without a detour
			// dials through the default outbound
			// (docs/configuration/dns/server/legacy.md)
			if (typ == "" || typ == "legacy") && len(detours) == 0 && legacyServerDials(s) {
				tag, known := x.defaultOut, x.defaultOutKnown
				if !known {
					return visitResult{problem: r.tag}
				}
				if tag != "" {
					result.next = append(result.next, probeRef{tag: tag})
				}
			}
			result.next = append(result.next, resolverRefs(s, "domain_resolver")...)
			result.next = append(result.next, resolverRefs(s, "address_resolver")...)
		}
		return result
	}

	list := x.byTag[r.tag]
	if len(list) == 0 {
		// An endpoint (none is copied), or a tag sing-box would not find
		return visitResult{problem: r.tag}
	}
	if _, failed := x.failed[r.tag]; failed && !own {
		return visitResult{problem: r.tag}
	}
	for _, o := range list {
		typ, ok := singleType(o)
		if !ok || !allowedOutboundTypes[typ] {
			return visitResult{problem: r.tag}
		}
		// A Hysteria 2 realm may name a shared HTTP client (http_clients),
		// which is not copied
		if realm, ok := foldedField(o, "realm"); ok && realm != nil {
			if own {
				return visitResult{problem: "realm"}
			}
			return visitResult{problem: r.tag}
		}
		if netns := foldedString(o, "netns"); netns != "" {
			if own {
				return visitResult{problem: netns}
			}
			return visitResult{problem: r.tag}
		}
		result.group = result.group || groupTypes[typ]
		result.next = append(result.next, resolverRefs(o, "domain_resolver")...)
		servers, ok := x.nameResolution(o, r.tag)
		if !ok {
			if own {
				return visitResult{problem: problemDNSRules}
			}
			return visitResult{problem: r.tag}
		}
		result.next = append(result.next, servers...)
	}
	for _, dep := range x.detours[r.tag] {
		result.next = append(result.next, probeRef{tag: dep})
	}
	for _, m := range x.members[r.tag] {
		result.members = append(result.members, probeRef{tag: m})
	}
	return result
}

// nameResolution is the DNS server that resolves the name of the outbound's
// server when the outbound dials it itself (common/dialer: no detour, no
// domain_resolver of its own; a direct outbound resolves every name it
// dials): route.default_domain_resolver; without it, with fewer than two
// DNS servers the default one; otherwise sing-box asks the DNS rules
// (ruleResolution — 1.12 and later only with
// ENABLE_DEPRECATED_MISSING_DOMAIN_RESOLVER, earlier always). false: the
// rules decide in a way the test cannot repeat.
func (x *probeIndex) nameResolution(o map[string]any, tag string) ([]probeRef, bool) {
	switch {
	case !resolvesLocally(o):
		return nil, true
	case len(x.resolvers) > 0:
		return x.resolvers, true
	case len(x.servers) < 2:
		if x.defaultServer == "" {
			return nil, true
		}
		return []probeRef{{dns: true, tag: x.defaultServer}}, true
	}
	servers, _, ok := x.ruleResolution(tag)
	return servers, ok
}

// rulesResolve: sing-box resolves the outbound's server name through the
// DNS rules (nameResolution)
func (x *probeIndex) rulesResolve(o map[string]any) bool {
	return resolvesLocally(o) && len(x.resolvers) == 0 && len(x.servers) >= 2
}

// ruleResolution is the DNS server the rules resolve the server name of the
// outbound tag with (dns/router.go Lookup without a transport: the first
// rule that matches and routes to a server decides, a matching
// route-options rule adds its options, without one the default server
// decides) and the indices of the rules the test instance copies for it.
// It decides only by a rule whose one condition is the outbound ("any" or
// tags; route/rule/rule_item_outbound.go): any other condition might match
// the name or not (a domain, a rule set, the clash mode), and a rule that
// rejects or answers itself would need the test instance to ask the rules
// the same way. A rule routing to a fakeip server or to a tag no server has
// decides no lookup, one whose outbound condition does not name tag never
// matches it — both are passed over, whatever else they say. false: a rule
// it cannot decide by comes first.
func (x *probeIndex) ruleResolution(tag string) ([]probeRef, []int, bool) {
	if x.rulesAmbiguous {
		return nil, nil, false
	}
	var copied []int
	for i, item := range x.rules {
		rule, isObject := item.(map[string]any)
		if !isObject {
			return nil, nil, false
		}
		action, server := foldedString(rule, "action"), foldedString(rule, "server")
		routes := action == "" || action == "route"
		if routes && server != "" && x.skippedServer(server) {
			continue
		}
		outbounds, matches, inverted, other := 0, false, false, false
		for k, v := range rule {
			switch key := foldKey(k); {
			case key == "outbound":
				values := tagList(v)
				if len(values) == 0 {
					continue // no condition: sing-box leaves out an empty list
				}
				outbounds++
				matches = slices.Contains(values, "any") || slices.Contains(values, tag)
			case key == "type":
				if s, _ := v.(string); s != "" && s != "default" {
					other = true // a logical rule
				}
			case key == "invert":
				if b, isBool := v.(bool); !isBool || b {
					inverted = true
				}
			case !dnsRuleActionKeys[key]:
				other = true
			}
		}
		switch {
		case outbounds > 1:
			return nil, nil, false // two spellings: sing-box reads the later one
		case outbounds == 1 && !matches && !inverted:
			continue // its conditions all have to match
		case outbounds == 0 || inverted || other:
			return nil, nil, false
		}
		switch action {
		case "", "route":
			if server == "" {
				return nil, nil, false // sing-box refuses it
			}
			copied = append(copied, i)
			return []probeRef{{dns: true, tag: server}}, copied, true
		case "route-options":
			copied = append(copied, i)
			continue
		}
		return nil, nil, false
	}
	if x.defaultServer == "" {
		return nil, copied, true
	}
	return []probeRef{{dns: true, tag: x.defaultServer}}, copied, true
}

// skippedServer: a DNS rule routing to the server tag decides no name an
// outbound looks up — sing-box passes over a fakeip server there (a lookup
// takes no fake address) and over a tag no server has
func (x *probeIndex) skippedServer(tag string) bool {
	list := x.serverByTag[tag]
	if len(list) == 0 {
		return true
	}
	for _, s := range list {
		typ, _ := dnsType(s)
		if typ == "fakeip" || (typ == "" || typ == "legacy") && strings.EqualFold(foldedString(s, "address"), "fakeip") {
			return true
		}
	}
	return false
}

// resolvesLocally: the outbound resolves the name of its server itself
// (common/dialer NewWithOptions: no detour — through one, the detour gets
// the name — and no domain_resolver of its own): a server by name, or a
// direct outbound, which resolves every name it dials
func resolvesLocally(o map[string]any) bool {
	if len(stringValues(o, "detour")) > 0 || len(resolverRefs(o, "domain_resolver")) > 0 {
		return false
	}
	typ, _ := singleType(o)
	switch {
	case typ == "direct":
		return true
	case systemTypes[typ]:
		return false
	}
	server := foldedString(o, "server")
	if server == "" {
		return false
	}
	_, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(server, "["), "]"))
	return err != nil
}

// defaultOutbound is the outbound sing-box dials through where nothing else
// is said: route.final, otherwise the first outbound (adapter/outbound
// manager.go; an endpoint never is the first). "" and true without
// outbounds (sing-box adds a direct one); false when the first is one
// without a tag, which the test instance cannot carry
func defaultOutbound(cfg, route map[string]any) (string, bool) {
	if route != nil {
		if final := foldedString(route, "final"); final != "" {
			return final, true
		}
	}
	tag, found := "", false
	each(cfg, "outbounds", func(o map[string]any) {
		if !found {
			tag, found = foldedString(o, "tag"), true
		}
	})
	return tag, !found || tag != ""
}

// legacyServerDials: a DNS server of the format before sing-box 1.14 (an
// address) dials its server — it is not the system's resolver, a fakeip
// range or a fixed answer
func legacyServerDials(s map[string]any) bool {
	address := strings.ToLower(foldedString(s, "address"))
	return address != "local" && address != "fakeip" && !strings.HasPrefix(address, "rcode://")
}

// buildProbePlan classifies the outbounds of cfg (the table of §3.3 of the
// design, the first row that applies) and builds the config of the test
// instance from the closures of the testable ones and what the config's
// globals need (carriedGlobals). failed are the outbounds earlier test
// instances could not create (Exclude), by tag. cfg is the plan's own copy
// and is never modified.
func buildProbePlan(cfg map[string]any, failed map[string]string) *domain.ProbePlan {
	x := indexProbe(cfg, failed)
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
		if reached := x.classify(o, &c, relays); c.Testable {
			testable = true
			for r := range reached {
				needed[r] = true
			}
		}
		plan.Candidates = append(plan.Candidates, c)
	}
	if testable {
		for r := range x.carriedGlobals() {
			needed[r] = true
		}
	}

	probe := map[string]any{"log": map[string]any{"level": "warn"}}
	outbounds := []any{}
	var tags []string // the tag of each outbound of the test instance, for Exclude
	for _, o := range x.outbounds {
		if tag := foldedString(o, "tag"); needed[probeRef{tag: tag}] {
			outbounds = append(outbounds, probeOutbound(o, needed))
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
			case "final":
				// Not without the server it names (the only problem of the
				// servers that resolve through it)
				if !needed[probeRef{dns: true, tag: x.defaultServer}] {
					continue
				}
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
		if rules := x.probeRules(needed); len(rules) > 0 {
			dns["rules"] = rules
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
		if v, ok := foldedField(x.route, "default_interface"); ok {
			route["default_interface"] = deepCopy(v)
		}
		if v, ok := foldedField(x.route, "default_domain_resolver"); ok &&
			!slices.ContainsFunc(x.resolvers, func(r probeRef) bool { return !needed[r] }) {
			route["default_domain_resolver"] = deepCopy(v)
		}
	}
	if x.legacyDefaultDetour(needed) {
		route["final"] = x.defaultOut
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

// probeOutbound is the test instance's copy of an outbound: config.json's
// own, but a group keeps only the members the test instance carries — it
// carries all of a group a server of the test dials through, and a group
// reached only for the config's sake without the ones it cannot
// (carriedGlobals) — and a default only among them (without one sing-box
// selects the first member)
func probeOutbound(o map[string]any, needed map[probeRef]bool) any {
	c, _ := deepCopy(o).(map[string]any)
	if typ, _ := singleType(o); !groupTypes[typ] {
		return c
	}
	for k, v := range c {
		switch foldKey(k) {
		case "outbounds":
			list, _ := v.([]any)
			kept := make([]any, 0, len(list))
			for _, m := range list {
				if s, isTag := m.(string); !isTag || needed[probeRef{tag: s}] {
					kept = append(kept, m)
				}
			}
			if len(kept) != len(list) {
				c[k] = kept
			}
		case "default":
			if s, isTag := v.(string); isTag && s != "" && !needed[probeRef{tag: s}] {
				delete(c, k)
			}
		}
	}
	return c
}

// probeRules are the DNS rules the test instance takes from config.json: the
// ones that decide where the outbounds it carries resolve their servers'
// names (ruleResolution), copied as they are, in their order
func (x *probeIndex) probeRules(needed map[probeRef]bool) []any {
	copied := map[int]bool{}
	for _, o := range x.outbounds {
		tag := foldedString(o, "tag")
		if !needed[probeRef{tag: tag}] || !x.rulesResolve(o) {
			continue
		}
		if _, indices, ok := x.ruleResolution(tag); ok {
			for _, i := range indices {
				copied[i] = true
			}
		}
	}
	var rules []any
	for i, rule := range x.rules {
		if copied[i] {
			rules = append(rules, deepCopy(rule))
		}
	}
	return rules
}

// legacyDefaultDetour: the test instance carries a DNS server of the format
// before sing-box 1.14 that dials through the default outbound — which
// then has to be the same as the VPN's (route.final; the first outbound of
// the test instance is another one)
func (x *probeIndex) legacyDefaultDetour(needed map[probeRef]bool) bool {
	if x.defaultOut == "" || !needed[probeRef{tag: x.defaultOut}] {
		return false
	}
	for _, s := range x.servers {
		typ, _ := dnsType(s)
		if needed[probeRef{dns: true, tag: foldedString(s, "tag")}] && (typ == "" || typ == "legacy") &&
			len(stringValues(s, "detour")) == 0 && legacyServerDials(s) {
			return true
		}
	}
	return false
}

// classify fills in the candidate for the outbound o and returns, for a
// testable one, the refs its closure reaches: what it dials through, what
// resolves its server's name — the globals only where it needs them
func (x *probeIndex) classify(o map[string]any, c *domain.LatencyCandidate, relays map[string]bool) map[probeRef]bool {
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
	switch {
	case problem == problemDNSRules:
		c.Note = noteDNSRules
		return nil
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
// proxies among all of them, the ones SwitchOutbound would repoint, Groups
// the distinct groups, which it leaves where they are. An endpoint (a
// WireGuard one) is the target when no proxy or group is: SwitchOutbound
// repoints no rule to one, but with no proxy referenced it sets
// route.final — and so would move the traffic off it. Next to a proxy or a
// group it stays where it is, like direct: no split routing.
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
	// sing-box finds an outbound before an endpoint of the same tag
	// (adapter/outbound/manager.go)
	each(cfg, "endpoints", func(e map[string]any) {
		if tag := foldedString(e, "tag"); tag != "" {
			if _, known := kinds[tag]; !known {
				kinds[tag] = domain.RoutingEndpoint
			}
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
	ruleRefs := len(refs)
	if final == "" {
		final = first
	}
	if final != "" {
		refs = append(refs, final)
	}

	rt := domain.RoutingTarget{Final: final}
	seen := map[string]bool{}
	endpoint := ""
	for _, ref := range refs {
		kind := kinds[ref]
		if kind == domain.RoutingEndpoint && endpoint == "" {
			endpoint = ref
		}
		if kind == "" || kind == domain.RoutingEndpoint {
			continue
		}
		if rt.Kind == "" {
			rt.Kind, rt.Tag = kind, ref
		}
		if seen[ref] {
			continue
		}
		seen[ref] = true
		if kind == domain.RoutingNode {
			rt.ProxyRefs = append(rt.ProxyRefs, ref)
		} else {
			rt.Groups = append(rt.Groups, ref)
		}
	}
	if rt.Kind == "" && endpoint != "" {
		rt.Kind, rt.Tag = domain.RoutingEndpoint, endpoint
	}
	rt.InRules = rt.Tag != "" && slices.Contains(refs[:ruleRefs], rt.Tag)
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
