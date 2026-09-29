package configfile

import (
	"fmt"
	"sort"
	"strings"
)

// Outbound dependencies. sing-box starts an outbound only after the ones it
// depends on — the outbound its detour names, the members of a selector or
// urltest group (adapter/outbound/manager.go, startOutbounds) — and does not
// start at all when one of them does not exist ("dependency[X] not found
// for outbound[Y]") or when they depend on each other in a ring ("circular
// outbound dependency"), whether or not the traffic ever uses them. sing-box
// check builds the outbounds without starting them and passes such a config;
// the VPN restarted into it then does not come up, at every retry. The same
// holds for the references from outside the outbounds that sing-box
// resolves when it starts — to an outbound, a rule set or a shared HTTP
// client (referenceProblems). Outbounds and endpoints share one namespace,
// and keys are matched the way sing-box matches them (foldKey): to sing-box
// {"Detour": "x"} is a detour.

// dependencyProblem is one reason sing-box would not start
type dependencyProblem struct {
	key     string   // the same problem in two configs has the same key
	tags    []string // the outbounds that cannot start because of it; none for a reference from elsewhere (origin)
	missing string   // the tag named but absent; "" for a ring
	group   bool     // missing is a group member, not a detour
	origin  string   // what names missing when that is no outbound: route.final, a DNS server's detour, a route rule's rule_set, …
	kind    string   // what missing should be when not an outbound: "rule-set", "http_client"
	checked bool     // sing-box check refuses it as well; named here for a clearer message
}

// String describes the problem for the user, naming the outbounds by tag
func (p dependencyProblem) String() string {
	switch {
	case p.origin != "":
		kind := p.kind
		if kind == "" {
			kind = "outbound"
		}
		return fmt.Sprintf("%s указывает на «%s», а такого %s нет", p.origin, p.missing, kind)
	case p.missing != "" && p.group:
		return fmt.Sprintf("в группе «%s» есть «%s», а такого outbound нет", p.tags[0], p.missing)
	case p.missing != "":
		return fmt.Sprintf("outbound «%s» работает через «%s» (detour), а такого outbound нет", p.tags[0], p.missing)
	case len(p.tags) == 1:
		return fmt.Sprintf("outbound «%s» подключается через самого себя", p.tags[0])
	}
	return fmt.Sprintf("outbounds %s подключаются друг через друга по кругу (detour, группы)", quoteTags(p.tags))
}

// reason is why one of the outbounds of the problem (tag) was left out of
// an import or a refresh
func (p dependencyProblem) reason(tag string) string {
	const suffix = " — с ним sing-box не запустится"
	switch {
	case p.missing != "":
		return fmt.Sprintf("узел работает через «%s», а его в конфиге нет", p.missing) + suffix
	case len(p.tags) == 1:
		return "узел подключается через самого себя" + suffix
	}
	var others []string
	for _, t := range p.tags {
		if t != tag {
			others = append(others, t)
		}
	}
	return fmt.Sprintf("узел и %s подключаются друг через друга по кругу", quoteTags(others)) + suffix
}

func quoteTags(tags []string) string {
	quoted := make([]string, len(tags))
	for i, t := range tags {
		quoted[i] = "«" + t + "»"
	}
	return strings.Join(quoted, ", ")
}

// dependencyError is a refusal of checkDependencies: the problems the saved
// config would add
type dependencyError struct {
	problems []dependencyProblem
}

func (e *dependencyError) Error() string {
	const limit = 3
	var parts []string
	unnoticed := false
	for i, p := range e.problems {
		unnoticed = unnoticed || !p.checked
		if i < limit {
			parts = append(parts, p.String())
		}
	}
	if len(e.problems) > limit {
		parts = append(parts, fmt.Sprintf("и ещё %d", len(e.problems)-limit))
	}
	suffix := " — с таким конфигом sing-box не запустится"
	if unnoticed {
		suffix += " (sing-box check этого не замечает)"
	}
	return strings.Join(parts, "; ") + suffix
}

// checkDependencies refuses a config with a dependency problem the previous
// config did not have. One it had stays allowed, like the guard does: what
// an administrator wrote by hand must not make every other save fail.
func checkDependencies(previous []byte, cfg map[string]any) error {
	had := map[string]bool{}
	if old, err := decodeConfig(previous); err == nil {
		for _, p := range dependencyProblems(old) {
			had[p.key] = true
		}
	}
	var added []dependencyProblem
	for _, p := range dependencyProblems(cfg) {
		if !had[p.key] {
			added = append(added, p)
		}
	}
	if len(added) == 0 {
		return nil
	}
	return &dependencyError{problems: added}
}

// dependencyNode is an outbound or endpoint and the tags it depends on
type dependencyNode struct {
	tag  string
	deps []dependency
}

type dependency struct {
	tag   string
	group bool // a group member, not a detour
}

// dependencyNodes lists the outbounds and endpoints with a tag, in the order
// of the config. Every key that folds to "detour" counts (with two spellings
// sing-box takes the later one, and the order of keys is not kept here).
func dependencyNodes(cfg map[string]any) []dependencyNode {
	var nodes []dependencyNode
	for _, section := range []string{"outbounds", "endpoints"} {
		for _, value := range fieldValues(cfg, section) {
			list, _ := value.([]any)
			for _, item := range list {
				o, ok := item.(map[string]any)
				if !ok {
					continue
				}
				tag := foldedString(o, "tag")
				if tag == "" {
					continue
				}
				group := section == "outbounds" && groupTypes[foldedString(o, "type")]
				node := dependencyNode{tag: tag}
				for k, v := range o {
					switch foldKey(k) {
					case "detour":
						if s, ok := v.(string); ok && s != "" {
							node.deps = append(node.deps, dependency{tag: s})
						}
					case "outbounds":
						members, _ := v.([]any)
						for _, m := range members {
							if s, ok := m.(string); ok && s != "" && group {
								node.deps = append(node.deps, dependency{tag: s, group: true})
							}
						}
					}
				}
				sort.Slice(node.deps, func(i, j int) bool { return node.deps[i].tag < node.deps[j].tag })
				nodes = append(nodes, node)
			}
		}
	}
	return nodes
}

// dependencyProblems lists what would keep sing-box from starting: every
// dependency on a tag that does not exist, every ring (a strongly connected
// set of outbounds, or one depending on itself), and every reference from
// outside the outbounds to a tag that does not exist (referenceProblems)
func dependencyProblems(cfg map[string]any) []dependencyProblem {
	problems := outboundProblems(cfg)
	return append(problems, referenceProblems(cfg)...)
}

// referenceProblems lists the references from outside the outbounds that
// sing-box resolves when it starts, naming a tag the config does not have.
//
// An outbound or endpoint: route.final ("default outbound not found"), the
// detour of a DNS server and of the NTP client when it is enabled ("outbound
// detour not found"), a route rule's preferred_by ("outbound not found",
// when the rules start, the last thing the router starts), the download
// detour of a rule set (its download_detour, the detour of its own
// http_client) and the detour of a shared HTTP client (http_clients) a rule
// set downloads through (downloadClients) — the first download of a rule
// set fails the start when there is no cached copy ("initial rule-set").
// Whether a copy is cached is only known then, so such a detour counts
// either way. The detour of a shared client no rule set downloads through
// does not: sing-box looks a detour up at the first dial through it.
//
// A rule set: a route rule's rule_set, also in the rules of a logical rule
// ("rule-set not found", when the rules start); a DNS rule's is refused by
// sing-box check already and named here only for a clearer message. A
// shared HTTP client: a rule set's http_client given by tag and
// route.default_http_client ("http_client not found").
//
// sing-box check passes all of these but the DNS rule's, and they are easy
// to make: renaming or deleting on the settings page what they name, where
// the DNS section cannot be edited. A route rule sending traffic to a
// missing outbound is not one: it fails only the connections it matches,
// sing-box starts. The key of each is the kind of reference, its owner when
// it has a tag and the tag missing, never a position: a problem the previous
// config had stays the same problem when the rules are reordered.
func referenceProblems(cfg map[string]any) []dependencyProblem {
	outbounds := map[string]bool{}
	for _, n := range dependencyNodes(cfg) {
		outbounds[n.tag] = true
	}
	ruleSets := map[string]bool{}
	for _, route := range objects(cfg, "route") {
		each(route, "rule_set", func(rs map[string]any) {
			for _, tag := range ruleSetTags(rs) {
				ruleSets[tag] = true
			}
		})
	}
	clients := map[string]bool{}
	each(cfg, "http_clients", func(c map[string]any) {
		if tag := foldedString(c, "tag"); tag != "" {
			clients[tag] = true
		}
	})

	var problems []dependencyProblem
	seen := map[string]bool{}
	// check records each of the tags that present lacks, as the problem p
	// (its key completed with the tag)
	check := func(present map[string]bool, p dependencyProblem, tags []string) {
		for _, tag := range tags {
			key := p.key + "\x00" + tag
			if tag == "" || present[tag] || seen[key] {
				continue
			}
			seen[key] = true
			found := p
			found.key, found.missing = key, tag
			problems = append(problems, found)
		}
	}

	for _, route := range objects(cfg, "route") {
		for _, final := range fieldValues(route, "final") {
			check(outbounds, dependencyProblem{key: "final", origin: "route.final"}, stringTag(final))
		}
		eachRule(route, func(rule map[string]any) {
			for _, v := range fieldValues(rule, "rule_set") {
				check(ruleSets, dependencyProblem{key: "rule rule_set", origin: "rule_set правила маршрутизации", kind: "rule-set"}, tagList(v))
			}
			for _, v := range fieldValues(rule, "preferred_by") {
				check(outbounds, dependencyProblem{key: "rule preferred_by", origin: "preferred_by правила маршрутизации"}, tagList(v))
			}
		})
		each(route, "rule_set", func(rs map[string]any) {
			tags := ruleSetTags(rs)
			id := strings.Join(tags, "\x00")
			owner := "rule-set"
			if len(tags) > 0 {
				owner += " " + quoteTags(tags)
			}
			for _, v := range fieldValues(rs, "download_detour") {
				check(outbounds, dependencyProblem{key: "rule-set download_detour\x00" + id, origin: "download_detour " + owner}, stringTag(v))
			}
			// A tag names a shared client, an object is the rule set's own
			for _, v := range fieldValues(rs, "http_client") {
				switch client := v.(type) {
				case string:
					check(clients, dependencyProblem{key: "rule-set http_client\x00" + id, origin: "http_client " + owner, kind: "http_client"}, stringTag(client))
				case map[string]any:
					for _, detour := range fieldValues(client, "detour") {
						check(outbounds, dependencyProblem{key: "rule-set http_client.detour\x00" + id, origin: "http_client.detour " + owner}, stringTag(detour))
					}
				}
			}
		})
		for _, v := range fieldValues(route, "default_http_client") {
			check(clients, dependencyProblem{key: "default_http_client", origin: "route.default_http_client", kind: "http_client"}, stringTag(v))
		}
	}
	downloading := downloadClients(cfg)
	each(cfg, "http_clients", func(c map[string]any) {
		tag := foldedString(c, "tag")
		if !downloading[tag] {
			return
		}
		for _, detour := range fieldValues(c, "detour") {
			check(outbounds, dependencyProblem{key: "http_client detour\x00" + tag, origin: "detour http_client «" + tag + "»"}, stringTag(detour))
		}
	})
	for _, dns := range objects(cfg, "dns") {
		each(dns, "servers", func(server map[string]any) {
			tag := foldedString(server, "tag")
			origin := "detour DNS-сервера"
			if tag != "" {
				origin += " «" + tag + "»"
			}
			for _, detour := range fieldValues(server, "detour") {
				check(outbounds, dependencyProblem{key: "dns\x00" + tag, origin: origin}, stringTag(detour))
			}
		})
		eachRule(dns, func(rule map[string]any) {
			for _, v := range fieldValues(rule, "rule_set") {
				check(ruleSets, dependencyProblem{key: "dns rule rule_set", origin: "rule_set правила DNS", kind: "rule-set", checked: true}, tagList(v))
			}
		})
	}
	// A disabled NTP client is not created, and its detour never looked up
	for _, ntp := range objects(cfg, "ntp") {
		if !enabled(ntp) {
			continue
		}
		for _, detour := range fieldValues(ntp, "detour") {
			check(outbounds, dependencyProblem{key: "ntp", origin: "ntp.detour"}, stringTag(detour))
		}
	}
	return problems
}

// downloadClients are the tags of the shared HTTP clients (http_clients) a
// rule set downloads through when sing-box starts (rule_set_remote.go,
// resolveTransport): the one its http_client names by tag, and the default
// one (defaultClients) for a remote rule set with neither an http_client of
// its own — an object, even an empty one — nor a download_detour. Another
// shared client serves only what names it outside the rule sets — a
// hysteria2 realm, which no import brings, or what the guard keeps out
// (services) — and is not checked here
func downloadClients(cfg map[string]any) map[string]bool {
	used := map[string]bool{}
	fallback := false
	for _, route := range objects(cfg, "route") {
		each(route, "rule_set", func(rs map[string]any) {
			own := false
			for _, v := range fieldValues(rs, "http_client") {
				switch client := v.(type) {
				case string:
					if client != "" {
						used[client], own = true, true
					}
				case map[string]any:
					own = true
				}
			}
			for _, v := range fieldValues(rs, "download_detour") {
				if s, _ := v.(string); s != "" {
					own = true
				}
			}
			// Only a remote rule set downloads; its type is a value, not folded
			if !own && foldedString(rs, "type") == "remote" {
				fallback = true
			}
		})
	}
	if fallback {
		for _, tag := range defaultClients(cfg) {
			used[tag] = true
		}
	}
	return used
}

// defaultClients is the default shared HTTP client (httpclient.NewManager):
// the one route.default_http_client names, otherwise the first of
// http_clients. More than one only when a key comes in two spellings:
// sing-box takes the later one, the order of keys is not kept here, and a
// detour refused by mistake costs less than a broken start let through.
func defaultClients(cfg map[string]any) []string {
	var tags []string
	empty := false
	for _, route := range objects(cfg, "route") {
		for _, v := range fieldValues(route, "default_http_client") {
			if s, _ := v.(string); s != "" {
				tags = append(tags, s)
			} else {
				empty = true
			}
		}
	}
	if len(tags) > 0 && !empty {
		return tags
	}
	for _, v := range fieldValues(cfg, "http_clients") {
		if list, _ := v.([]any); len(list) > 0 {
			if c, ok := list[0].(map[string]any); ok {
				if tag := foldedString(c, "tag"); tag != "" {
					tags = append(tags, tag)
				}
			}
		}
	}
	return tags
}

// ruleSetTags are the tags of a rule set: in sing-box 1.14 one entry may
// define several (a list; its URL or path takes each in turn)
func ruleSetTags(rs map[string]any) []string {
	var tags []string
	for _, v := range fieldValues(rs, "tag") {
		tags = append(tags, tagList(v)...)
	}
	return tags
}

// stringTag is the tag a field holding one names (none when it holds
// anything else: sing-box check refuses that)
func stringTag(v any) []string {
	if s, ok := v.(string); ok {
		return []string{s}
	}
	return nil
}

// tagList is the tags a field sing-box reads as a tag or a list of them
// names (badoption.Listable: rule_set, preferred_by, a rule set's tag)
func tagList(v any) []string {
	switch v := v.(type) {
	case string:
		return []string{v}
	case []any:
		var tags []string
		for _, item := range v {
			if s, ok := item.(string); ok {
				tags = append(tags, s)
			}
		}
		return tags
	}
	return nil
}

// objects returns the objects at every key of m that folds to name
func objects(m map[string]any, name string) []map[string]any {
	var found []map[string]any
	for _, v := range fieldValues(m, name) {
		if o, ok := v.(map[string]any); ok {
			found = append(found, o)
		}
	}
	return found
}

// each visits the objects of the lists m holds at every key that folds to
// name
func each(m map[string]any, name string, visit func(map[string]any)) {
	for _, v := range fieldValues(m, name) {
		list, _ := v.([]any)
		for _, item := range list {
			if o, ok := item.(map[string]any); ok {
				visit(o)
			}
		}
	}
}

// eachRule visits the rules of a route or DNS section and the rules of the
// logical ones among them, at any depth: sing-box starts a logical rule's
// rules with it
func eachRule(section map[string]any, visit func(rule map[string]any)) {
	var walk func(m map[string]any)
	walk = func(m map[string]any) {
		each(m, "rules", func(rule map[string]any) {
			visit(rule)
			walk(rule)
		})
	}
	walk(section)
}

// enabled: an "enabled" key of the object, in any spelling, is true (with two
// spellings sing-box takes the later one; the order of keys is not kept
// here, and a disabled part refused by mistake costs less than a broken
// start let through)
func enabled(m map[string]any) bool {
	for _, v := range fieldValues(m, "enabled") {
		if b, ok := v.(bool); ok && b {
			return true
		}
	}
	return false
}

// dependencyGraph maps every outbound and endpoint to the tags it depends
// on: its detour, a group's members (dependencyNodes)
func dependencyGraph(cfg map[string]any) map[string][]string {
	edges := map[string][]string{}
	for _, n := range dependencyNodes(cfg) {
		for _, d := range n.deps {
			edges[n.tag] = append(edges[n.tag], d.tag)
		}
	}
	return edges
}

// dependsOn returns every tag the outbound from depends on, directly or
// through others
func dependsOn(edges map[string][]string, from string) map[string]bool {
	found := map[string]bool{}
	stack := append([]string(nil), edges[from]...)
	for len(stack) > 0 {
		tag := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if found[tag] {
			continue
		}
		found[tag] = true
		stack = append(stack, edges[tag]...)
	}
	return found
}

// detourTargets returns the tags another outbound or endpoint of the config
// dials through (its detour)
func detourTargets(cfg map[string]any) map[string]bool {
	targets := map[string]bool{}
	for _, n := range dependencyNodes(cfg) {
		for _, d := range n.deps {
			if !d.group && d.tag != n.tag {
				targets[d.tag] = true
			}
		}
	}
	return targets
}

// relayTags are the outbounds some other one dials through (detourTargets),
// together with the relays of the incoming nodes the check refused: the
// refused node is gone, its relay still works only as one. Kept in one
// place for the two that must agree on it — which incoming outbounds become
// selectable (registerInGroups) and which one removed references go to
// (pruneOutboundReferences).
func relayTags(cfg map[string]any, refused []map[string]any) map[string]bool {
	relays := detourTargets(cfg)
	for _, o := range refused {
		if detour := detourOf(o); detour != "" && detour != tagString(o) {
			relays[detour] = true
		}
	}
	return relays
}

// outboundProblems lists the dependencies of outbounds and endpoints on a
// tag that does not exist, and the rings
func outboundProblems(cfg map[string]any) []dependencyProblem {
	nodes := dependencyNodes(cfg)
	present := map[string]bool{}
	for _, n := range nodes {
		present[n.tag] = true
	}
	var problems []dependencyProblem
	edges := map[string][]string{}
	var order []string
	for _, n := range nodes {
		if _, seen := edges[n.tag]; !seen {
			order = append(order, n.tag)
			edges[n.tag] = nil
		}
		for _, d := range n.deps {
			if !present[d.tag] {
				problems = append(problems, dependencyProblem{
					key: "missing\x00" + n.tag + "\x00" + d.tag, tags: []string{n.tag}, missing: d.tag, group: d.group,
				})
				continue
			}
			edges[n.tag] = append(edges[n.tag], d.tag)
		}
	}
	for _, ring := range rings(order, edges) {
		problems = append(problems, dependencyProblem{key: "ring\x00" + strings.Join(ring, "\x00"), tags: ring})
	}
	return problems
}

// rings returns the strongly connected sets of the graph that are a ring:
// more than one tag, or one with an edge to itself; each sorted (Tarjan)
func rings(order []string, edges map[string][]string) [][]string {
	index := map[string]int{}
	low := map[string]int{}
	onStack := map[string]bool{}
	var stack []string
	var found [][]string
	next := 0

	var visit func(v string)
	visit = func(v string) {
		index[v], low[v] = next, next
		next++
		stack = append(stack, v)
		onStack[v] = true
		self := false
		for _, w := range edges[v] {
			if w == v {
				self = true
			}
			if _, seen := index[w]; !seen {
				visit(w)
				low[v] = min(low[v], low[w])
			} else if onStack[w] {
				low[v] = min(low[v], index[w])
			}
		}
		if low[v] != index[v] {
			return
		}
		var set []string
		for {
			w := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			onStack[w] = false
			set = append(set, w)
			if w == v {
				break
			}
		}
		if len(set) > 1 || self {
			sort.Strings(set)
			found = append(found, set)
		}
	}
	for _, v := range order {
		if _, seen := index[v]; !seen {
			visit(v)
		}
	}
	return found
}

// fieldValues returns the values of every key of m that folds to name
func fieldValues(m map[string]any, name string) []any {
	var keys []string
	for k := range m {
		if foldKey(k) == name {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	values := make([]any, len(keys))
	for i, k := range keys {
		values[i] = m[k]
	}
	return values
}

// foldedString is the string at the key of m that folds to name: the one
// spelled exactly so when there are several, otherwise the first in sorted
// order — the same answer every time
func foldedString(m map[string]any, name string) string {
	if s, ok := m[name].(string); ok {
		return s
	}
	for _, v := range fieldValues(m, name) {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
