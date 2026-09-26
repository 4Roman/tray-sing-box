package configfile

import (
	"fmt"

	"tray-sing-box/internal/config"
	"tray-sing-box/internal/domain"
)

// Merging incoming outbounds (an import, a subscription refresh) into the
// config. sing-box addresses outbounds by tag only, and the tags of incoming
// outbounds are whatever the link or the provider called the server, so the
// merge decides three things by tag: which existing outbound an incoming one
// may replace (suffixTaken), which dropped subscription node is the same
// server under a new name (pairRenamed), and what the references to a tag
// that goes away point to next (applyRenames, pruneOutboundReferences).

func tagString(o map[string]any) string {
	tag, _ := o["tag"].(string)
	return tag
}

func setOf(list []string) map[string]bool {
	set := make(map[string]bool, len(list))
	for _, s := range list {
		set[s] = true
	}
	return set
}

// requireTags refuses outbounds without a tag: nothing could refer to them
func requireTags(outbounds []map[string]any) error {
	for _, o := range outbounds {
		if tagString(o) == "" {
			return fmt.Errorf("outbound has no tag")
		}
	}
	return nil
}

// cloneConfig returns a deep copy of a decoded config
func cloneConfig(cfg map[string]any) (map[string]any, error) {
	raw, err := marshalIndent(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize config: %w", err)
	}
	return decodeConfig(raw)
}

// importReplaceable tells the outbounds a manual import may replace: an
// imported or hand-written server — re-importing a server updates it. Never
// direct, block, dns or a group (a link named "direct" would take over the
// traffic the user sends past the VPN), never the DPI-bypass outbound, never
// a subscription's node (reserved: its refresh would delete or overwrite the
// import, and removing the subscription would take the import along).
func importReplaceable(reserved map[string]bool) func(map[string]any) bool {
	return func(o map[string]any) bool {
		tag := tagString(o)
		typ, _ := o["type"].(string)
		return !systemTypes[typ] && tag != config.DPIBypassTag && !reserved[tag]
	}
}

// suffixTaken renames the incoming outbounds whose tag belongs to an
// existing outbound they may not replace (replaceable false) or to an
// endpoint (sing-box keeps one namespace for both): each gets the first free
// "<tag> (N)" from N = 2 — free when no protected outbound or endpoint and no
// other incoming outbound has it. The same input gives the same names every
// time, so a subscription node renamed this way keeps its tag from one
// refresh to the next. incoming are renamed in place; the renames returned.
func suffixTaken(cfg map[string]any, incoming []map[string]any, replaceable func(map[string]any) bool) []domain.TagRename {
	protected := map[string]bool{}
	outbounds, _ := cfg["outbounds"].([]any)
	for _, item := range outbounds {
		if o, ok := item.(map[string]any); ok && tagString(o) != "" && !replaceable(o) {
			protected[tagString(o)] = true
		}
	}
	endpoints, _ := cfg["endpoints"].([]any)
	for _, item := range endpoints {
		if o, ok := item.(map[string]any); ok && tagString(o) != "" {
			protected[tagString(o)] = true
		}
	}

	taken := map[string]bool{}
	for _, o := range incoming {
		taken[tagString(o)] = true
	}
	var renames []domain.TagRename
	for _, o := range incoming {
		tag := tagString(o)
		if !protected[tag] {
			continue
		}
		name := tag
		for n := 2; protected[name] || taken[name]; n++ {
			name = fmt.Sprintf("%s (%d)", tag, n)
		}
		o["tag"] = name
		taken[name] = true
		renames = append(renames, domain.TagRename{From: tag, To: name})
	}
	return renames
}

// pairRenamed finds the dropped subscription nodes that reappear under a new
// name (3x-ui and others put the traffic and the days left into the node
// names): first the ones equal to an appearing node apart from the tag and
// a detour (contentKey), in order; then, among the rest, the ones with the
// same server and credentials (identityKey) when that identity is unique on
// both sides — providers publish several nodes on one server and uuid that
// differ only in transport or SNI, and a guess could move the user's choice
// to another node. Returns old tag -> new tag, and the pairs in order.
func pairRenamed(dropped, appearing []map[string]any) (map[string]string, []domain.TagRename) {
	renames := map[string]string{}
	var pairs []domain.TagRename
	paired := make([]bool, len(appearing))
	pair := func(from map[string]any, j int) {
		paired[j] = true
		renames[tagString(from)] = tagString(appearing[j])
		pairs = append(pairs, domain.TagRename{From: tagString(from), To: tagString(appearing[j])})
	}

	byContent := map[string][]int{}
	for j, o := range appearing {
		k := contentKey(o)
		byContent[k] = append(byContent[k], j)
	}
	var rest []map[string]any
	for _, o := range dropped {
		k := contentKey(o)
		if js := byContent[k]; len(js) > 0 {
			byContent[k] = js[1:]
			pair(o, js[0])
			continue
		}
		rest = append(rest, o)
	}

	droppedByID := map[string][]map[string]any{}
	for _, o := range rest {
		if k := identityKey(o); k != "" {
			droppedByID[k] = append(droppedByID[k], o)
		}
	}
	appearingByID := map[string][]int{}
	for j, o := range appearing {
		if paired[j] {
			continue
		}
		if k := identityKey(o); k != "" {
			appearingByID[k] = append(appearingByID[k], j)
		}
	}
	for _, o := range rest {
		k := identityKey(o)
		if k != "" && len(droppedByID[k]) == 1 && len(appearingByID[k]) == 1 {
			pair(o, appearingByID[k][0])
		}
	}
	return renames, pairs
}

// contentKey is an outbound without its tag and detour (a detour on a node
// was set by the app or the user, never by the provider)
func contentKey(o map[string]any) string {
	rest := make(map[string]any, len(o))
	for k, v := range o {
		if k != "tag" && k != "detour" {
			rest[k] = v
		}
	}
	return canonical(rest)
}

// identityKey names the server an outbound connects to and the account it
// uses there: type, address, port(s), credentials, the transport and the TLS
// server name. "" for an outbound without a server.
func identityKey(o map[string]any) string {
	server, _ := o["server"].(string)
	typ, _ := o["type"].(string)
	if server == "" || typ == "" {
		return ""
	}
	parts := []any{typ, server, o["server_port"], o["server_ports"], o["uuid"], o["password"], o["method"]}
	if transport, ok := o["transport"].(map[string]any); ok {
		parts = append(parts, transport["type"], transport["path"], transport["service_name"])
	} else {
		parts = append(parts, nil, nil, nil)
	}
	if tls, ok := o["tls"].(map[string]any); ok {
		parts = append(parts, tls["server_name"])
	} else {
		parts = append(parts, nil)
	}
	return canonical(parts)
}

// applyRenames gives outbounds their new tags (old -> new) and follows every
// reference to them: group members (in place) and selector defaults, and
// everything visitRefs walks
func applyRenames(cfg map[string]any, renames map[string]string) {
	if len(renames) == 0 {
		return
	}
	rename := func(tag string) string {
		if to, ok := renames[tag]; ok {
			return to
		}
		return tag
	}

	outbounds, _ := cfg["outbounds"].([]any)
	for _, item := range outbounds {
		o, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if tag, ok := o["tag"].(string); ok {
			o["tag"] = rename(tag)
		}
		if !groupTypes[fmt.Sprint(o["type"])] {
			continue
		}
		members, _ := o["outbounds"].([]any)
		for i, m := range members {
			if tag, ok := m.(string); ok {
				members[i] = rename(tag)
			}
		}
		if def, ok := o["default"].(string); ok {
			o["default"] = rename(def)
		}
	}
	visitRefs(cfg, func(_ refKind, tag string) (string, bool) {
		return rename(tag), true
	})
}

// refKind tells what a reference to an outbound (visitRefs) does with it
type refKind int

const (
	refChain  refKind = iota // an outbound's detour: it dials through that outbound
	refDetour                // the detour of an endpoint, a DNS server, NTP or a rule set download
	refRule                  // the outbound a route rule sends its traffic to
	refNested                // an outbound inside a logical rule's sub-rule
	refFinal                 // route.final
	refMatch                 // a DNS rule condition (legacy): the query came through that outbound
)

// visitRefs calls fn for every outbound tag the config names outside the
// outbounds list and its groups. fn returns the new value and whether to keep
// it: false deletes the field, or drops the route rule it decides.
func visitRefs(cfg map[string]any, fn func(kind refKind, tag string) (string, bool)) {
	field := func(m map[string]any, key string, kind refKind) {
		tag, ok := m[key].(string)
		if !ok || tag == "" {
			return
		}
		if to, keep := fn(kind, tag); keep {
			m[key] = to
		} else {
			delete(m, key)
		}
	}
	each := func(v any, visit func(map[string]any)) {
		list, _ := v.([]any)
		for _, item := range list {
			if m, ok := item.(map[string]any); ok {
				visit(m)
			}
		}
	}

	each(cfg["outbounds"], func(o map[string]any) { field(o, "detour", refChain) })
	each(cfg["endpoints"], func(o map[string]any) { field(o, "detour", refDetour) })
	if ntp, ok := cfg["ntp"].(map[string]any); ok {
		field(ntp, "detour", refDetour)
	}
	if dns, ok := cfg["dns"].(map[string]any); ok {
		each(dns["servers"], func(s map[string]any) { field(s, "detour", refDetour) })
		each(dns["rules"], func(r map[string]any) { visitMatch(r, fn) })
	}
	route, ok := cfg["route"].(map[string]any)
	if !ok {
		return
	}
	if rules, ok := route["rules"].([]any); ok {
		route["rules"] = visitRules(rules, fn, false)
	}
	field(route, "final", refFinal)
	each(route["rule_set"], func(rs map[string]any) { field(rs, "download_detour", refDetour) })
}

// visitRules visits the outbound of each route rule and of the rules nested
// in logical rules. A top-level rule whose outbound fn drops is dropped; in a
// nested rule (sing-box acts on the top-level one) only the field goes.
func visitRules(rules []any, fn func(refKind, string) (string, bool), nested bool) []any {
	kept := make([]any, 0, len(rules))
	for _, item := range rules {
		rule, ok := item.(map[string]any)
		if !ok {
			kept = append(kept, item)
			continue
		}
		if sub, ok := rule["rules"].([]any); ok {
			rule["rules"] = visitRules(sub, fn, true)
		}
		if out, ok := rule["outbound"].(string); ok && out != "" {
			kind := refRule
			if nested {
				kind = refNested
			}
			to, keep := fn(kind, out)
			switch {
			case keep:
				rule["outbound"] = to
			case nested:
				delete(rule, "outbound")
			default:
				continue // nothing left to send this traffic to: the rule goes
			}
		}
		kept = append(kept, rule)
	}
	return kept
}

// visitMatch visits the outbound condition of a DNS rule (a tag or a list of
// them) and of the rules nested in it; conditions are only ever renamed
func visitMatch(rule map[string]any, fn func(refKind, string) (string, bool)) {
	switch out := rule["outbound"].(type) {
	case string:
		if to, keep := fn(refMatch, out); keep {
			rule["outbound"] = to
		}
	case []any:
		for i, item := range out {
			if tag, ok := item.(string); ok {
				if to, keep := fn(refMatch, tag); keep {
					out[i] = to
				}
			}
		}
	}
	if sub, ok := rule["rules"].([]any); ok {
		for _, item := range sub {
			if m, ok := item.(map[string]any); ok {
				visitMatch(m, fn)
			}
		}
	}
}

// pruneOutboundReferences removes every reference to the removed tags:
// selector/urltest membership, a selector default (repointed to the
// replacement when that is a member — sing-box looks the default up among the
// members only and does not start without it, which sing-box check does not
// notice — otherwise dropped: the first member is the default then), the
// detour of outbounds (they dial directly), and route rules/final, the
// detour of DNS servers, NTP, endpoints and rule set downloads (repointed to
// the replacement: the first new outbound, else any surviving proxy, else a
// direct outbound; a detour is not pointed at a direct outbound — sing-box
// refuses that — and a rule with no usable replacement is dropped).
func pruneOutboundReferences(cfg map[string]any, removed map[string]bool, newOutbounds []map[string]any) {
	outbounds, _ := cfg["outbounds"].([]any)

	// Pick the replacement for references that pointed at removed tags
	replacement := ""
	if len(newOutbounds) > 0 {
		replacement, _ = newOutbounds[0]["tag"].(string)
	}
	if replacement == "" {
		proxies := proxyTags(cfg)
		for _, item := range outbounds {
			if o, ok := item.(map[string]any); ok {
				if tag, _ := o["tag"].(string); proxies[tag] {
					replacement = tag
					break
				}
			}
		}
	}
	proxy := replacement != ""
	if replacement == "" {
		for _, item := range outbounds {
			if o, ok := item.(map[string]any); ok && o["type"] == "direct" {
				replacement, _ = o["tag"].(string)
				break
			}
		}
	}

	for _, item := range outbounds {
		o, ok := item.(map[string]any)
		if !ok || !groupTypes[fmt.Sprint(o["type"])] {
			continue
		}
		members, _ := o["outbounds"].([]any)
		filtered := make([]any, 0, len(members))
		member := false
		for _, m := range members {
			if tag, _ := m.(string); !removed[tag] {
				filtered = append(filtered, m)
				member = member || tag == replacement
			}
		}
		o["outbounds"] = filtered
		if def, _ := o["default"].(string); removed[def] {
			if replacement != "" && member {
				o["default"] = replacement
			} else {
				delete(o, "default")
			}
		}
	}

	visitRefs(cfg, func(kind refKind, tag string) (string, bool) {
		if !removed[tag] {
			return tag, true
		}
		switch kind {
		case refChain:
			return "", false
		case refMatch:
			return tag, true
		case refDetour:
			return replacement, proxy
		}
		return replacement, replacement != ""
	})
}
