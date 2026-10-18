package sharelink

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Subscription bodies that are a whole profile rather than share links: a
// sing-box configuration (what Marzban, Remnawave and the like serve at their
// "sing-box" URLs) or its bare outbounds array, SIP008 (the shadowsocks
// online config JSON) and Xray JSON (xray.go). Clash/mihomo YAML is read in
// clash.go.

// profileProxyTypes are the outbound types taken from a sing-box profile;
// the provider's structural ones (profileStructural) are its own plumbing
var profileProxyTypes = map[string]bool{
	"shadowsocks": true, "vmess": true, "vless": true, "trojan": true, "hysteria": true,
	"hysteria2": true, "tuic": true, "anytls": true, "shadowtls": true, "http": true,
	"socks": true, "naive": true, "ssh": true,
}

var profileStructural = map[string]bool{
	"direct": true, "block": true, "dns": true, "selector": true, "urltest": true,
}

var (
	errEmptyProfile = errors.New("в профиле нет серверов, которые приложение может импортировать")
)

// profile reads text as a JSON profile. ok is false when it is none (the
// text is then read as links); err refuses the profile as a whole.
func (c *collector) profile(text string) (ok bool, err error) {
	text = strings.TrimSpace(text)
	if text == "" || (text[0] != '{' && text[0] != '[') || !json.Valid([]byte(text)) {
		return false, nil
	}
	var root any
	decoder := json.NewDecoder(strings.NewReader(text))
	decoder.UseNumber()
	if decoder.Decode(&root) != nil {
		return false, nil
	}

	var entries []any
	switch r := root.(type) {
	case map[string]any:
		if servers, isList := r["servers"].([]any); isList {
			c.sip008(servers)
			return true, errEmptyProfileIfNone(c)
		}
		list, isList := r["outbounds"].([]any)
		endpoints, hasEndpoints := r["endpoints"].([]any)
		if !isList && !hasEndpoints {
			return false, nil
		}
		if xrayOutbounds(list) {
			c.xray(text)
			return true, errEmptyProfileIfNone(c)
		}
		// A whole sing-box config
		c.singBox(list)
		for i, e := range endpoints {
			m, _ := e.(map[string]any)
			tag, _ := m["tag"].(string)
			name := fmt.Sprintf("endpoint %d", i+1)
			if plainName(tag) {
				name = shortName(tag)
			}
			c.skip(name, "endpoint (WireGuard и подобные) приложение не импортирует — только outbound")
		}
		return true, errEmptyProfileIfNone(c)
	case []any:
		// A bare outbounds array, or (3x-ui's JSON subscription) an array
		// of whole Xray configs
		for _, e := range r {
			if m, isMap := e.(map[string]any); isMap {
				if nested, isList := m["outbounds"].([]any); isList {
					entries = append(entries, nested...)
					continue
				}
			}
			entries = append(entries, e)
		}
	default:
		return false, nil
	}
	if xrayOutbounds(entries) {
		c.xray(text)
		return true, errEmptyProfileIfNone(c)
	}
	if !singBoxOutbounds(entries) {
		return false, nil
	}
	c.singBox(entries)
	return true, errEmptyProfileIfNone(c)
}

func errEmptyProfileIfNone(c *collector) error {
	if len(c.outbounds) == 0 && len(c.skipped) == 0 {
		return errEmptyProfile
	}
	return nil
}

// xrayOutbounds: Xray describes an outbound by "protocol" and "settings",
// sing-box by "type"
func xrayOutbounds(entries []any) bool {
	for _, e := range entries {
		m, _ := e.(map[string]any)
		if m == nil {
			continue
		}
		_, hasType := m["type"]
		_, hasProtocol := m["protocol"]
		_, hasSettings := m["settings"]
		if !hasType && (hasProtocol || hasSettings) {
			return true
		}
	}
	return false
}

// singBoxOutbounds: at least one entry is an object with a "type"
func singBoxOutbounds(entries []any) bool {
	for _, e := range entries {
		if m, _ := e.(map[string]any); m != nil {
			if _, hasType := m["type"].(string); hasType {
				return true
			}
		}
	}
	return false
}

// singBox takes the proxy outbounds of a sing-box profile. They are the
// provider's own JSON, so they are checked for what would break the whole
// save (a REALITY short_id sing-box crashes on, a flow or fingerprint it
// refuses, a plugin option naming a file) or what the app never adds (a file
// path — the guard would refuse the whole import for one such node); the
// rest is left to the guard and `sing-box check` of the config editor.
// The keys the app reads are first spelled the way sing-box reads them
// (foldKeys). A detour survives only when it names another node that is
// imported, and not in a ring: sing-box does not start with either, and
// sing-box check does not notice.
func (c *collector) singBox(entries []any) {
	var candidates []candidate
	direct := map[string]bool{}
	for i, e := range entries {
		m, _ := e.(map[string]any)
		if m == nil {
			continue
		}
		foldErr := foldKeys(m) // m is left as it is on an error
		typ, _ := m["type"].(string)
		typ = strings.ToLower(typ)
		tag, _ := m["tag"].(string)
		tag = strings.TrimSpace(tag)
		name := fmt.Sprintf("узел %d", i+1)
		if plainName(tag) {
			name = shortName(tag)
		}
		if profileStructural[typ] {
			if typ == "direct" && tag != "" && foldErr == nil {
				direct[tag] = true
			}
			continue
		}
		if !profileProxyTypes[typ] {
			if typ == "wireguard" {
				c.skip(name, "WireGuard в sing-box — это endpoint, а не outbound; такой узел приложение не импортирует")
			} else {
				c.skip(name, fmt.Sprintf("тип «%s» не поддерживается", token(typ)))
			}
			continue
		}
		if foldErr != nil {
			c.skip(name, foldErr.Error())
			continue
		}
		if tag == "" {
			c.skip(name, "у узла нет тега")
			continue
		}
		outbound := Outbound(m)
		outbound["type"] = typ
		outbound["tag"] = tag
		if err := sanitizeProfileOutbound(outbound); err != nil {
			c.skip(name, err.Error())
			continue
		}
		candidates = append(candidates, candidate{outbound, name})
	}

	// A repeated tag keeps its name on the first node that has it, the later
	// ones get a suffix (add): a detour naming a repeated tag means the first
	// kept node of that name. keepChains takes it for any node of the name,
	// so none of them is left in a ring; a profile sing-box itself runs has
	// no repeated tag (sing-box would keep the last outbound of the tag).
	kept := c.keepChains(candidates, direct)
	for i, cand := range candidates {
		if kept[i] {
			c.add(cand.outbound)
		}
	}
}

// candidate is a node of a profile, converted, before its detour is checked
type candidate struct {
	outbound Outbound
	name     string
}

// keepChains decides which candidates are kept for their detours (a tag
// among the candidates'): kept inside the profile, dropped when they only
// say "direct" (a tag in direct), otherwise the node cannot work as the
// provider meant it and is skipped — and with it every node chained through
// it, the next ones at a time (the report lists them so). The nodes of a
// ring go as well, then the nodes chained into the ring. In linear time: an
// 8 MB profile holds a hundred thousand nodes, and the import runs under the
// app's operation lock.
func (c *collector) keepChains(candidates []candidate, direct map[string]bool) []bool {
	kept := make([]bool, len(candidates))
	target := make([]string, len(candidates)) // the tag a candidate's detour names, "" for none
	holders := map[string][]int{}             // the candidates of a tag
	for i, cand := range candidates {
		kept[i] = true
		tag := cand.outbound.Tag()
		holders[tag] = append(holders[tag], i)
		if detour, hasDetour := cand.outbound["detour"]; hasDetour {
			if t, _ := detour.(string); t != "" && !direct[t] {
				target[i] = t
			} else {
				delete(cand.outbound, "detour")
			}
		}
	}
	left := make(map[string]int, len(holders)) // the kept candidates of a tag
	for tag, of := range holders {
		left[tag] = len(of)
	}
	dependents := map[string][]int{} // the candidates whose detour names a tag
	for i, t := range target {
		if t != "" {
			dependents[t] = append(dependents[t], i)
		}
	}

	var orphans []int // kept candidates whose detour lost its last node
	leave := func(i int, reason string) {
		kept[i] = false
		c.skip(candidates[i].name, reason)
		tag := candidates[i].outbound.Tag()
		if left[tag]--; left[tag] == 0 {
			for _, j := range dependents[tag] {
				if kept[j] {
					orphans = append(orphans, j)
				}
			}
		}
	}
	missing := func(next []int) {
		for len(next) > 0 {
			slices.Sort(next)
			level := next
			orphans = nil
			for _, i := range level {
				if kept[i] {
					leave(i, fmt.Sprintf("узел работает через «%s», которого нет среди импортируемых", quotedName(target[i])))
				}
			}
			next = orphans
		}
	}
	var first []int
	for i, t := range target {
		if t != "" && left[t] == 0 {
			first = append(first, i)
		}
	}
	missing(first)

	// A chain that comes back to its start: every node of the ring goes, the
	// ones chained into it follow
	ring := detourRings(target, kept, holders)
	orphans = nil
	for i := range candidates {
		if ring[i] {
			leave(i, "цепочка detour узла замыкается в кольцо — с ней sing-box не запустится")
		}
	}
	missing(orphans)
	return kept
}

// detourRings marks the kept candidates that lie on a ring of detours. A
// detour names a tag, and a tag given twice may be meant as any of its
// nodes: the graph goes from a node to the tag its detour names and from a
// tag to each of its kept nodes, and a node is on a ring when its strongly
// connected component (Tarjan's, without recursion) holds more than itself.
// Where tags are unique that is a chain coming back to the node. No chain
// comes back to a node without a tag (Xray's may have none): nothing names
// it.
func detourRings(target []string, kept []bool, holders map[string][]int) []bool {
	n := len(target)
	tagNode := map[string]int{} // a tag a detour names -> its vertex, n and up
	var tagHolders [][]int
	for i, t := range target {
		if _, seen := tagNode[t]; kept[i] && t != "" && !seen {
			tagNode[t] = n + len(tagHolders)
			var of []int
			for _, j := range holders[t] {
				if kept[j] {
					of = append(of, j)
				}
			}
			tagHolders = append(tagHolders, of)
		}
	}
	// next is the k-th edge from vertex v
	next := func(v, k int) (int, bool) {
		if v < n {
			return tagNode[target[v]], k == 0 && target[v] != ""
		}
		if of := tagHolders[v-n]; k < len(of) {
			return of[k], true
		}
		return 0, false
	}
	vertices := n + len(tagHolders)
	index, low := make([]int, vertices), make([]int, vertices) // index 0: not reached yet
	onStack := make([]bool, vertices)
	var stack []int
	ring := make([]bool, n)
	reached := 0
	type frame struct{ v, k int }
	for root := range n {
		if !kept[root] || index[root] != 0 {
			continue
		}
		reached++
		index[root], low[root] = reached, reached
		stack, onStack[root] = append(stack, root), true
		path := []frame{{root, 0}}
		for len(path) > 0 {
			top := &path[len(path)-1]
			v := top.v
			if w, ok := next(v, top.k); ok {
				top.k++
				switch {
				case index[w] == 0:
					reached++
					index[w], low[w] = reached, reached
					stack, onStack[w] = append(stack, w), true
					path = append(path, frame{w, 0})
				case onStack[w]:
					low[v] = min(low[v], index[w])
				}
				continue
			}
			path = path[:len(path)-1]
			if len(path) > 0 {
				parent := path[len(path)-1].v
				low[parent] = min(low[parent], low[v])
			}
			if low[v] == index[v] {
				at := len(stack) - 1
				for stack[at] != v {
					at--
				}
				for _, w := range stack[at:] {
					onStack[w] = false
					if w < n && len(stack)-at > 1 {
						ring[w] = true
					}
				}
				stack = stack[:at]
			}
		}
	}
	return ring
}

// quotedName is a node's tag as a reason may quote it: shortened, "…" when
// it is not one line
func quotedName(tag string) string {
	if plainName(tag) {
		return shortName(tag)
	}
	return "…"
}

// foldKey is how sing-box's JSON decoder matches a key to an option:
// case-insensitively, KELVIN SIGN as k (it lowers by itself) and LONG S as s
func foldKey(key string) string {
	return strings.ToLower(strings.ReplaceAll(key, "ſ", "s"))
}

// foldKeys spells the keys of an object of options (an outbound, its tls)
// the way sing-box reads them, so that the app reads what sing-box reads:
// to sing-box {"Detour": "x"} is a detour, and the app's checks of a detour,
// a short_id or a plugin must not miss it. Two keys for one option are
// refused — which one sing-box takes depends on their order in the text —
// and m is then left as it is.
func foldKeys(m map[string]any) error {
	folded := make(map[string]string, len(m))
	for key := range m {
		f := foldKey(key)
		if _, twice := folded[f]; twice {
			if !keyPattern.MatchString(f) {
				f = "…"
			}
			return fmt.Errorf("параметр «%s» указан в узле дважды, в разном написании", f)
		}
		folded[f] = key
	}
	for f, key := range folded {
		if f != key {
			m[f] = m[key]
			delete(m, key)
		}
	}
	return nil
}

// sanitizeProfileOutbound checks and adjusts one proxy outbound of a
// sing-box profile (its keys folded) in place
func sanitizeProfileOutbound(o Outbound) error {
	if key := fileKey(map[string]any(o)); key != "" {
		return fmt.Errorf("узел ссылается на файл на диске («%s»), через приложение такое не добавить", key)
	}
	// A DNS server of the provider's config, absent from the user's
	delete(o, "domain_resolver")

	switch o["type"] {
	case "hysteria2":
		// Like the hysteria2+realm:// links: a rendezvous server with a
		// token of its own the app would have to keep secret
		if _, realm := o["realm"]; realm {
			return errors.New("режим realm Hysteria 2 приложение не импортирует")
		}
	case "vless":
		flow, _ := o["flow"].(string)
		normalized, err := vlessFlow(flow)
		if err != nil {
			return err
		}
		if normalized == "" {
			delete(o, "flow")
		} else {
			o["flow"] = normalized
		}
	case "shadowsocks":
		if method, isString := o["method"].(string); isString {
			normalized, err := ssMethod(method)
			if err != nil {
				return err
			}
			o["method"] = normalized
		}
		plugin, _ := o["plugin"].(string)
		if strings.TrimSpace(plugin) != "" {
			opts, _ := o["plugin_opts"].(string)
			options, err := parsePluginOptions(opts)
			if err != nil {
				return err
			}
			name, pluginOpts, err := pluginConfig(plugin, options)
			if err != nil {
				return err
			}
			o["plugin"] = name
			if pluginOpts == "" {
				delete(o, "plugin_opts")
			} else {
				o["plugin_opts"] = pluginOpts
			}
		}
	}

	// The transport: the app tells nodes apart by its type and path
	if transport, _ := o["transport"].(map[string]any); transport != nil {
		if err := foldKeys(transport); err != nil {
			return err
		}
	}
	tls, _ := o["tls"].(map[string]any)
	if tls == nil {
		return nil
	}
	if err := foldKeys(tls); err != nil {
		return err
	}
	reality, _ := tls["reality"].(map[string]any)
	utls, _ := tls["utls"].(map[string]any)
	for _, m := range []map[string]any{reality, utls} {
		if m != nil {
			if err := foldKeys(m); err != nil {
				return err
			}
		}
	}
	realityOn := reality != nil && reality["enabled"] == true
	if realityOn {
		publicKey, _ := reality["public_key"].(string)
		shortID, isString := reality["short_id"].(string)
		if _, present := reality["short_id"]; present && !isString {
			shortID = "-" // not a string: refused like any malformed short_id
		}
		checked, err := realityConfig(publicKey, shortID)
		if err != nil {
			return err
		}
		reality["public_key"] = checked["public_key"]
	}
	switch {
	case utls != nil && utls["enabled"] == true:
		fp, _ := utls["fingerprint"].(string)
		if name, ok := utlsFingerprint(fp, realityOn); ok {
			utls["fingerprint"] = name
		} else {
			delete(tls, "utls")
		}
	case realityOn:
		// "uTLS is required by reality client"
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": "chrome"}
	}
	return nil
}

// fileKey names the first key of an outbound that points at a file or a
// program (the guard's rule: *_path, *_directory, and a few by name); ""
// when there is none. Named only when it looks like a sing-box key.
func fileKey(v any) string {
	switch x := v.(type) {
	case map[string]any:
		for key, child := range x {
			k := foldKey(key)
			if k == "executable_path" || k == "extra_args" || k == "torrc" ||
				strings.HasSuffix(k, "_path") || strings.HasSuffix(k, "_directory") {
				if keyPattern.MatchString(k) {
					return k
				}
				return "…"
			}
			if found := fileKey(child); found != "" {
				return found
			}
		}
	case []any:
		for _, child := range x {
			if found := fileKey(child); found != "" {
				return found
			}
		}
	}
	return ""
}

var keyPattern = regexp.MustCompile(`^[a-z0-9_]{1,40}$`)

// parsePluginOptions parses a SIP003 plugin_opts string on its own
func parsePluginOptions(opts string) ([]pluginOption, error) {
	if strings.TrimSpace(opts) == "" {
		return nil, nil
	}
	parts, err := splitPluginString("plugin;" + opts)
	if err != nil {
		return nil, err
	}
	return parts[1:], nil
}

// sip008Server is one server of a SIP008 online config
type sip008Server struct {
	Remarks    string          `json:"remarks"`
	Server     string          `json:"server"`
	ServerPort json.RawMessage `json:"server_port"`
	Password   string          `json:"password"`
	Method     string          `json:"method"`
	Plugin     string          `json:"plugin"`
	PluginOpts string          `json:"plugin_opts"`
}

// sip008 converts the servers of a SIP008 JSON into shadowsocks outbounds
func (c *collector) sip008(servers []any) {
	for i, entry := range servers {
		raw, err := json.Marshal(entry)
		var s sip008Server
		if err == nil {
			decoder := json.NewDecoder(bytes.NewReader(raw))
			err = decoder.Decode(&s)
		}
		// Named like a link (linkTitle): the remark on one line, shortened
		// — a provider's text reaches the popups
		name := fmt.Sprintf("узел %d", i+1)
		if plainName(s.Remarks) {
			name = shortName(s.Remarks)
		}
		if err != nil {
			c.skip(name, "запись сервера повреждена")
			continue
		}
		outbound, err := sip008Outbound(s)
		if err != nil {
			c.skip(name, err.Error())
			continue
		}
		c.add(outbound)
	}
}

func sip008Outbound(s sip008Server) (Outbound, error) {
	server := strings.TrimSpace(s.Server)
	if server == "" {
		return nil, errors.New("не указан адрес сервера")
	}
	port, err := rawInt(s.ServerPort)
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("неверный порт")
	}
	if s.Password == "" {
		return nil, errors.New("не указан пароль")
	}
	method, err := ssMethod(s.Method)
	if err != nil {
		return nil, err
	}
	tag := strings.TrimSpace(s.Remarks)
	if tag == "" {
		tag = fmt.Sprintf("ss-%s-%d", server, port)
	}
	outbound := Outbound{
		"type":        "shadowsocks",
		"tag":         tag,
		"server":      server,
		"server_port": port,
		"method":      method,
		"password":    s.Password,
	}
	if strings.TrimSpace(s.Plugin) != "" {
		options, err := parsePluginOptions(s.PluginOpts)
		if err != nil {
			return nil, err
		}
		plugin, pluginOpts, err := pluginConfig(s.Plugin, options)
		if err != nil {
			return nil, err
		}
		outbound["plugin"] = plugin
		if pluginOpts != "" {
			outbound["plugin_opts"] = pluginOpts
		}
	}
	return outbound, nil
}
