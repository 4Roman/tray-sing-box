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
// resolves when it starts (referenceProblems). Outbounds and endpoints share
// one namespace, and keys are matched the way sing-box matches them
// (foldKey): to sing-box {"Detour": "x"} is a detour.

// dependencyProblem is one reason sing-box would not start
type dependencyProblem struct {
	key     string   // the same problem in two configs has the same key
	tags    []string // the outbounds that cannot start because of it; none for a reference from elsewhere (origin)
	missing string   // the tag named but absent; "" for a ring
	group   bool     // missing is a group member, not a detour
	origin  string   // what names missing when that is no outbound: route.final, the detour of a DNS server or of NTP
}

// String describes the problem for the user, naming the outbounds by tag
func (p dependencyProblem) String() string {
	switch {
	case p.origin != "":
		return fmt.Sprintf("%s указывает на «%s», а такого outbound нет", p.origin, p.missing)
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
	for i, p := range e.problems {
		if i == limit {
			parts = append(parts, fmt.Sprintf("и ещё %d", len(e.problems)-limit))
			break
		}
		parts = append(parts, p.String())
	}
	return strings.Join(parts, "; ") + " — с таким конфигом sing-box не запустится (sing-box check этого не замечает)"
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
// sing-box resolves when it starts, naming a tag no outbound or endpoint
// has: route.final ("default outbound not found"), the detour of a DNS server
// and of the NTP client when it is enabled ("outbound detour not found").
// sing-box check passes all of them, and they are easy to make: renaming or
// deleting the outbound they name on the settings page, where the DNS
// section cannot be edited. A route rule naming a missing outbound is not
// one: it fails only the connections it matches, sing-box starts.
func referenceProblems(cfg map[string]any) []dependencyProblem {
	present := map[string]bool{}
	for _, n := range dependencyNodes(cfg) {
		present[n.tag] = true
	}
	var problems []dependencyProblem
	seen := map[string]bool{}
	check := func(key, origin string, value any) {
		tag, _ := value.(string)
		key += "\x00" + tag
		if tag == "" || present[tag] || seen[key] {
			return
		}
		seen[key] = true
		problems = append(problems, dependencyProblem{key: key, missing: tag, origin: origin})
	}

	for _, route := range objects(cfg, "route") {
		for _, final := range fieldValues(route, "final") {
			check("final", "route.final", final)
		}
	}
	for _, dns := range objects(cfg, "dns") {
		for _, value := range fieldValues(dns, "servers") {
			servers, _ := value.([]any)
			for _, item := range servers {
				server, ok := item.(map[string]any)
				if !ok {
					continue
				}
				tag := foldedString(server, "tag")
				origin := "detour DNS-сервера"
				if tag != "" {
					origin += " «" + tag + "»"
				}
				for _, detour := range fieldValues(server, "detour") {
					check("dns\x00"+tag, origin, detour)
				}
			}
		}
	}
	// A disabled NTP client is not created, and its detour never looked up
	for _, ntp := range objects(cfg, "ntp") {
		if !enabled(ntp) {
			continue
		}
		for _, detour := range fieldValues(ntp, "detour") {
			check("ntp", "ntp.detour", detour)
		}
	}
	return problems
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
