package sharelink

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

// Clash/mihomo YAML profiles: the "proxies" list of a Clash configuration
// (what 3x-ui, Marzban, Remnawave and the subscription converters serve at
// their "clash" URLs) or of a proxy-provider file. Every entry is translated
// into the share link that says the same thing and read by the link
// parsers, so every mapping and every refusal of the links applies to it
// unchanged. What no link can carry is refused with the reason when the
// node cannot work without it (ShadowTLS, a client certificate, SOCKS over
// TLS), and left out when it is the client's own business (multiplexing,
// UDP relay hints, buffer sizes, Hysteria 2 bandwidth). The groups and the
// rules of a profile are the provider's routing, not servers: not read. Of
// its proxy-providers the inline lists are read, their nodes being entries
// as well; a list mihomo would download is not followed.
//
// Values are read as the provider wrote them, not as YAML types them: an
// unquoted short-id 2351e1 is a float to YAML (mihomo then gets
// "2.351E+04") and a password 0123 an octal number, while the generator
// meant the text; only a value tagged !!binary is decoded, mihomo gets the
// decoded value as well. Keys are matched the way mihomo matches them:
// case-insensitively and with '_' for '-'.

var (
	// clashProxies: the top-level proxy list (or lists, proxy-providers) of
	// a Clash/mihomo YAML profile, how a profile the YAML parser cannot read
	// is still recognized
	clashProxies = regexp.MustCompile(`(?m)^(proxies|proxy-providers):`)
	// yamlErrorLine: the line number in a YAML parser error (the rest of
	// the message may quote the text, credentials included)
	yamlErrorLine = regexp.MustCompile(`line (\d+)`)

	errClashBroken    = errors.New("профиль Clash/mihomo (YAML) повреждён")
	errClashProviders = errors.New("в профиле Clash/mihomo нет самих серверов, только ссылки на внешние списки (proxy-providers), " +
		"а их приложение не загружает: нужна ссылка на подписку, которая отдаёт серверы")
	errClashEntry     = errors.New("запись узла повреждена")
	errClashExpansion = fmt.Errorf("%w: якоря и ссылки YAML (&, *, <<) разворачивают его в слишком большой объём", errClashBroken)
)

// How far the aliases of a profile may expand it. Each repetition of an
// entry is translated again (a link, an outbound) and a merge key copies
// the fields it merges, so a few lines of anchors can stand for gigabytes,
// and the app does not survive running out of memory. The entries with
// every alias and merge expanded (clashValue.size, about their bytes) may
// come to twice the text and clashExpansionAllowance on top, and the merges
// may copy half as many fields as the text has bytes and
// clashMergeAllowance on top. A provider merging a common block into its
// entries stays far below; yaml.v3's own check (mihomo's "excessive
// aliasing") is not used: it does not see one large value repeated, and it
// does not run inside a mapping with a repeated key.
const (
	clashExpansionAllowance = 4 << 20
	clashMergeAllowance     = 1 << 20
	clashSizeCap            = 1 << 50 // where a size stops counting: aliases nest exponentially
)

// clash reads text as a Clash/mihomo YAML profile. ok is false when it is
// none (the text is then read as links); err refuses the profile as a whole.
func (c *collector) clash(text string) (ok bool, err error) {
	if !strings.Contains(text, "proxies") && !strings.Contains(text, "proxy-providers") {
		return false, nil
	}
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		// A list of links is no YAML as a rule, even with a line that
		// starts with "proxies:"
		if !clashProxies.MatchString(text) || len(extractLinks(text)) > 0 {
			return false, nil
		}
		if m := yamlErrorLine.FindStringSubmatch(err.Error()); m != nil {
			return true, fmt.Errorf("%w (строка %s)", errClashBroken, m[1])
		}
		return true, errClashBroken
	}
	root := &doc
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		root = root.Content[0]
	}
	if root.Kind != yaml.MappingNode {
		return false, nil
	}
	var proxies, providers *yaml.Node
	for i := 0; i+1 < len(root.Content); i += 2 {
		switch root.Content[i].Value {
		case "proxies":
			if proxies != nil {
				return true, errClashBroken // which list mihomo takes: none, it refuses the profile
			}
			proxies = root.Content[i+1]
		case "proxy-providers":
			providers = root.Content[i+1]
		}
	}
	if proxies == nil && providers == nil {
		return false, nil
	}
	if proxies != nil && proxies.Kind == yaml.AliasNode && proxies.Alias != nil {
		proxies = proxies.Alias
	}
	r := newYAMLReader(len(text))
	lists, listsErr := r.providers(providers)
	if errors.Is(listsErr, errClashExpansion) {
		return true, listsErr
	}
	// Share links under a "proxies:" line may be YAML as well, a list or a
	// text: the entries of a profile are mappings
	entries := proxies != nil && holdsMapping(proxies)
	for _, list := range lists {
		for _, v := range list.entries {
			entries = entries || v.kind == yaml.MappingNode
		}
	}
	if !entries && len(extractLinks(text)) > 0 {
		return false, nil
	}
	if listsErr != nil {
		return true, listsErr
	}
	var items []*yaml.Node
	switch {
	case proxies == nil:
	case proxies.Kind == yaml.SequenceNode:
		items = proxies.Content
	case proxies.Kind == yaml.ScalarNode && proxies.ShortTag() == "!!null":
		// "proxies:" with nothing under it
	default:
		return true, errClashBroken
	}

	// The entries are read first: a profile that expands too far is refused
	// before anything of it is translated (the lists' nodes are charged as
	// they are read). The nodes of the inline lists follow the proxies.
	type clashItem struct {
		n   *yaml.Node // nil for a list's node
		v   *clashValue
		err error
	}
	var all []clashItem
	for _, item := range items {
		v, err := r.value(item)
		if errors.Is(err, errClashExpansion) || err == nil && !r.entry(v) {
			return true, errClashExpansion
		}
		all = append(all, clashItem{item, v, err})
	}
	for _, list := range lists {
		for _, v := range list.entries {
			all = append(all, clashItem{v: v})
		}
	}
	external, refused := false, false
	for _, list := range lists {
		external = external || list.external
		refused = refused || list.reason != "" && !list.external
	}
	if len(all) == 0 && external && !refused {
		return true, errClashProviders
	}
	for _, list := range lists {
		if list.reason != "" {
			c.skip(list.name, list.reason)
		}
	}

	// The outbounds then go the way of a sing-box profile's: a dialer-proxy
	// is a detour, kept only when it names another node that is imported
	// and not in a ring (sing-box does not start otherwise, and sing-box
	// check does not notice); the tags are made unique there
	var outbounds []any
	for i, item := range all {
		v, err := item.v, item.err
		if err == nil && v.kind != yaml.MappingNode {
			err = errClashEntry
		}
		if err != nil {
			c.skip(clashName(nil, item.n, i), err.Error())
			continue
		}
		outbound, err := clashOutbound(v, i)
		if err != nil {
			c.skip(clashName(v, item.n, i), err.Error())
			continue
		}
		if outbound != nil {
			outbounds = append(outbounds, map[string]any(outbound))
		}
	}
	c.singBox(outbounds)
	return true, errEmptyProfileIfNone(c)
}

// holdsMapping reports whether a YAML list holds a mapping, what the entry
// of a node is
func holdsMapping(list *yaml.Node) bool {
	if list.Kind != yaml.SequenceNode {
		return false
	}
	for _, item := range list.Content {
		if item.Kind == yaml.AliasNode && item.Alias != nil {
			item = item.Alias
		}
		if item.Kind == yaml.MappingNode {
			return true
		}
	}
	return false
}

// clashProvider is one of a profile's proxy-providers, read: the nodes of an
// inline list, with what the list sets for them applied, or why the list
// gives none
type clashProvider struct {
	name     string        // what the report calls it
	entries  []*clashValue // an inline list's
	reason   string        // why its nodes are not read
	external bool          // a list to download (http, file)
}

// clashOverrides are the options of a list's override that set a field of
// each of its nodes (mihomo's overrideSchema.Apply): the entry is then read
// as if it had the field itself
var clashOverrides = []string{
	"tfo", "mptcp", "udp", "udp-over-tcp", "up", "down", "dialer-proxy",
	"skip-cert-verify", "name-cert-verify", "interface-name", "routing-mark", "ip-version",
}

// providers reads the proxy-providers of a profile. The nodes of an inline
// list (payload) are entries of the profile, with what the list sets for
// them applied as mihomo applies it; a list mihomo downloads (http, file)
// is not followed, and the fallback nodes such a list may carry are no
// more than a stand-in for it. Lists that choose or rename their nodes by
// mihomo's regular expressions or expressions are refused: the app would
// take other nodes, or under other names.
func (r *yamlReader) providers(n *yaml.Node) ([]clashProvider, error) {
	if n == nil {
		return nil, nil
	}
	if n.Kind == yaml.AliasNode && n.Alias != nil {
		n = n.Alias
	}
	switch {
	case n.Kind == yaml.ScalarNode && n.ShortTag() == "!!null":
		return nil, nil
	case n.Kind != yaml.MappingNode:
		return nil, errClashBroken
	}
	var lists []clashProvider
	for i := 0; i+1 < len(n.Content); i += 2 {
		list := clashProvider{name: fmt.Sprintf("список %d", len(lists)+1)}
		if name, _, ok := scalarText(n.Content[i]); ok && plainName(name) {
			list.name = shortName(name)
		}
		if n.Content[i].ShortTag() == "!!merge" {
			list.reason = "списки серверов (proxy-providers), взятые ссылкой YAML (<<), приложение не читает"
			lists = append(lists, list)
			continue
		}
		v, err := r.value(n.Content[i+1])
		if err == nil && v.kind == yaml.MappingNode {
			err = r.inline(&list, v)
		} else if !errors.Is(err, errClashExpansion) {
			list.reason, err = "список серверов (proxy-providers) повреждён", nil
		}
		if err != nil {
			return nil, err
		}
		lists = append(lists, list)
	}
	return lists, nil
}

// inline reads the nodes of an inline list into list, after mihomo's
// ProxiesParser: exclude-type leaves nodes out, and so does a name the list
// already gave; then the list's dialer-proxy is set, then the override.
// Each node is an entry of the profile and charged as one as it is read:
// aliases may repeat a list, an error refuses the profile.
func (r *yamlReader) inline(list *clashProvider, v *clashValue) error {
	e := &clashEntry{}
	m := clashMap{v: v, e: e}
	if typ := m.str("type"); e.err != nil {
		list.reason = e.err.Error()
		return nil
	} else if typ != "inline" {
		list.external = true
		list.reason = "это внешний список серверов (proxy-providers), а его приложение не загружает"
		return nil
	}
	override := m.sub("override")
	for _, key := range []string{"filter", "exclude-filter"} {
		if m.str(key) != "" {
			list.reason = fmt.Sprintf("список серверов (proxy-providers) отбирает узлы выражением mihomo (%s) — так приложение не умеет", key)
			return nil
		}
	}
	for _, key := range []string{"proxy-name", "override-expr"} {
		if override.has(key) {
			list.reason = fmt.Sprintf("список серверов (proxy-providers) меняет узлы выражением mihomo (override.%s) — так приложение не умеет", key)
			return nil
		}
	}
	var excluded []string
	if s := m.str("exclude-type"); s != "" {
		excluded = strings.Split(s, "|")
	}
	set := map[string]*clashValue{}
	if dialer := m.v.field("dialer-proxy"); dialer != nil && dialer.kind == yaml.ScalarNode && dialer.text != "" {
		set["dialer-proxy"] = dialer
	}
	for _, key := range clashOverrides {
		if f := override.v.field(key); f != nil {
			set[key] = f
		}
	}
	prefix, suffix := override.str("additional-prefix"), override.str("additional-suffix")
	payload := m.v.field("payload")
	if payload != nil && payload.kind != yaml.SequenceNode {
		m.bad("payload")
	}
	if e.err != nil {
		list.reason = e.err.Error()
		return nil
	}
	if payload == nil {
		return nil
	}
	seen := map[string]bool{}
	left := 0
	for _, entry := range payload.items {
		if !r.entry(entry) {
			return errClashExpansion
		}
		if entry.kind != yaml.MappingNode {
			list.entries = append(list.entries, entry) // reported as a broken entry
			continue
		}
		if typ := entry.field("type"); len(excluded) > 0 && (typ == nil || typ.kind != yaml.ScalarNode || slices.ContainsFunc(excluded, func(t string) bool {
			return strings.EqualFold(typ.text, t)
		})) {
			left++
			continue
		}
		name := entry.field("name")
		if name != nil && name.kind == yaml.ScalarNode {
			if seen[name.text] {
				left++
				continue
			}
			seen[name.text] = true
		}
		list.entries = append(list.entries, overridden(entry, set, name, prefix, suffix))
	}
	if left > 0 {
		log.Printf("Clash profile: an inline list leaves out %d of its nodes (exclude-type, repeated names)", left)
	}
	return nil
}

// overridden is an entry with the fields a list sets for its nodes, and the
// prefix and the suffix of the name around it
func overridden(entry *clashValue, set map[string]*clashValue, name *clashValue, prefix, suffix string) *clashValue {
	if len(set) == 0 && (prefix == "" && suffix == "" || name == nil || name.kind != yaml.ScalarNode) {
		return entry
	}
	v := &clashValue{kind: yaml.MappingNode, fields: maps.Clone(entry.fields), size: entry.size}
	if name != nil && name.kind == yaml.ScalarNode && (prefix != "" || suffix != "") {
		text := prefix + name.text + suffix
		v.fields["name"] = &clashValue{kind: yaml.ScalarNode, text: text, tag: "!!str", size: 1 + int64(len(text))}
		v.size = sizeAdd(v.size, int64(len(prefix)+len(suffix)))
	}
	for key, f := range set {
		v.fields[key] = f
		v.size = sizeAdd(v.size, sizeAdd(int64(len(key)), f.size))
	}
	return v
}

// clashName is what an entry is called in the report: its name on one
// line, shortened (a provider's text reaches the popups), else its number
func clashName(v *clashValue, n *yaml.Node, index int) string {
	if f := v.field("name"); f != nil && f.kind == yaml.ScalarNode && plainName(f.text) {
		return shortName(f.text)
	}
	if v == nil && n != nil && n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			key, _, _ := scalarText(n.Content[i])
			if value := n.Content[i+1]; clashKey(key) == "name" && value.Kind == yaml.ScalarNode {
				if name, _, ok := scalarText(value); ok && plainName(name) {
					return shortName(name)
				}
			}
		}
	}
	return fmt.Sprintf("узел %d", index+1)
}

// clashOutbound converts one entry of the proxy list; nil, nil for
// mihomo's own plumbing (direct, reject, dns)
func clashOutbound(v *clashValue, index int) (Outbound, error) {
	e := &clashEntry{}
	m := clashMap{v: v, e: e}
	typ := strings.ToLower(strings.TrimSpace(m.str("type")))
	name := strings.TrimSpace(m.str("name"))
	detour := strings.TrimSpace(m.str("dialer-proxy"))
	if e.err != nil {
		return nil, e.err
	}
	switch typ {
	case "direct", "reject", "reject-drop", "pass", "dns", "rematch", "compatible":
		return nil, nil
	case "":
		return nil, errors.New("у узла не указан тип (type)")
	}
	if name == "" {
		return nil, errors.New("у узла нет имени (name)")
	}
	if m.sub("smux").flag("enabled") {
		// The client's choice: the server takes the connections without it
		m.drop("smux")
	}
	link, err := clashLink(m, typ)
	if e.err != nil {
		return nil, e.err // a malformed field explains the refusal best
	}
	if err != nil {
		return nil, err
	}
	outbound, err := parseLink(link)
	if err != nil {
		return nil, err
	}
	outbound["tag"] = name
	if detour != "" && detour != "DIRECT" {
		outbound["detour"] = detour
	}
	if len(e.dropped) > 0 {
		// Only the keys: their values may be credentials
		log.Printf("Clash profile: node %d: left out %s (no share link carries it)", index+1, strings.Join(e.dropped, ", "))
	}
	return outbound, nil
}

// clashLink is the share link an entry means
func clashLink(m clashMap, typ string) (string, error) {
	switch typ {
	case "vless":
		return clashVLESS(m)
	case "vmess":
		return clashVMess(m)
	case "trojan":
		return clashTrojan(m)
	case "ss":
		return clashShadowsocks(m)
	case "hysteria2":
		return clashHysteria2(m)
	case "hysteria":
		return clashHysteria(m)
	case "tuic":
		return clashTUIC(m)
	case "anytls":
		return clashAnyTLS(m)
	case "socks5":
		return clashSOCKS(m)
	case "ssr":
		return "", errors.New("ShadowsocksR не поддерживается sing-box")
	case "wireguard":
		return "", errors.New("WireGuard в sing-box — это endpoint, а не outbound; такой узел приложение не импортирует")
	case "http":
		// No share link either: a bare http(s) URL is a subscription
		return "", errors.New("узлы HTTP-прокси приложение не импортирует")
	}
	return "", fmt.Errorf("тип «%s» не поддерживается", token(typ))
}

// clashEndpoint is the entry's server and port; the server is checked to be
// a host name or an IP address, nothing a link would read otherwise
func clashEndpoint(m clashMap) (host string, port int, err error) {
	if host, err = clashHost(m.str("server")); err != nil {
		return "", 0, err
	}
	if !m.has("port") {
		return "", 0, errors.New("не указан порт (port)")
	}
	if port = m.integer("port"); port < 1 || port > 65535 {
		return "", 0, errors.New("неверный порт (port)")
	}
	return host, port, nil
}

// hostPattern: a host name as a link's authority may carry it
var hostPattern = regexp.MustCompile(`^[\p{L}\p{N}._-]+$`)

func clashHost(s string) (string, error) {
	host := strings.TrimSpace(s)
	// mihomo wants an IPv6 address bare; 3x-ui used to write it bracketed
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	bad := errors.New("неверный адрес сервера (server)")
	switch {
	case host == "":
		return "", errors.New("не указан адрес сервера (server)")
	case strings.Contains(host, ":"):
		if addr, err := netip.ParseAddr(host); err != nil || addr.Zone() != "" {
			return "", bad
		}
	case !hostPattern.MatchString(host):
		return "", bad
	}
	return host, nil
}

// setIf sets a query parameter that has a value
func setIf(q url.Values, key, value string) {
	if strings.TrimSpace(value) != "" {
		q.Set(key, value)
	}
}

func clashVLESS(m clashMap) (string, error) {
	server, port, err := clashEndpoint(m)
	if err != nil {
		return "", err
	}
	uuid := strings.TrimSpace(m.str("uuid"))
	if uuid == "" {
		return "", errors.New("не указан uuid")
	}
	q, err := clashV2Ray(m, "vless", server)
	if err != nil {
		return "", err
	}
	setIf(q, "flow", m.str("flow"))
	setIf(q, "encryption", m.str("encryption"))
	return "vless://" + url.User(uuid).String() + "@" + net.JoinHostPort(server, strconv.Itoa(port)) + "?" + q.Encode(), nil
}

// clashVMess writes the v2rayN JSON form: the URL form has no alterId
func clashVMess(m clashMap) (string, error) {
	server, port, err := clashEndpoint(m)
	if err != nil {
		return "", err
	}
	uuid := strings.TrimSpace(m.str("uuid"))
	if uuid == "" {
		return "", errors.New("не указан uuid")
	}
	q, err := clashV2Ray(m, "vmess", server)
	if err != nil {
		return "", err
	}
	network, path := q.Get("type"), q.Get("path")
	switch {
	case network == "grpc":
		path = q.Get("serviceName")
	case q.Get("ed") != "":
		// The JSON form has no ed and eh of its own: v2rayN writes them
		// into the path, where the link parser looks for them too
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		path += sep + url.Values{"ed": {q.Get("ed")}, "eh": {q.Get("eh")}}.Encode()
	}
	security := q.Get("security")
	if security == "none" {
		security = ""
	}
	payload := map[string]any{
		"v": "2", "add": server, "port": port, "id": uuid, "aid": m.integer("alterid"), "scy": m.str("cipher"),
		"net": network, "type": q.Get("headerType"), "host": q.Get("host"), "path": path,
		"tls": security, "sni": q.Get("sni"), "alpn": q.Get("alpn"), "fp": q.Get("fp"),
		"pcs": q.Get("pinSHA256"), "vcn": q.Get("vcn"), "pbk": q.Get("pbk"), "sid": q.Get("sid"),
	}
	if q.Get("insecure") != "" {
		payload["insecure"] = "1"
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", errClashEntry
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(data), nil
}

func clashTrojan(m clashMap) (string, error) {
	server, port, err := clashEndpoint(m)
	if err != nil {
		return "", err
	}
	password := m.str("password")
	if password == "" {
		return "", errors.New("не указан пароль (password)")
	}
	if m.sub("ss-opts").flag("enabled") {
		return "", errors.New("шифрование Shadowsocks внутри trojan (ss-opts, из trojan-go) не поддерживается sing-box")
	}
	q, err := clashV2Ray(m, "trojan", server)
	if err != nil {
		return "", err
	}
	return "trojan://" + url.User(password).String() + "@" + net.JoinHostPort(server, strconv.Itoa(port)) + "?" + q.Encode(), nil
}

// clashV2Ray is the query of the vless, vmess or trojan link of an entry:
// TLS or REALITY, the certificate check and the transport. The server name
// is set as mihomo picks it — servername (trojan: sni), for a WebSocket then
// its Host header, then the server — and not left to the link parser, which
// falls back to the Host header for every transport.
func clashV2Ray(m clashMap, typ, server string) (url.Values, error) {
	q := url.Values{}
	tlsOn := m.flag("tls")
	if typ == "trojan" {
		// Trojan is TLS to mihomo whatever tls says; 3x-ui writes tls: false
		// for its trojan without TLS, which sing-box runs
		tlsOn = tlsOn || !m.has("tls")
	}
	if err := clashTLSAddons(m); err != nil {
		return nil, err
	}
	reality := m.sub("reality-opts")
	switch publicKey := reality.str("public-key"); {
	case publicKey != "":
		if !tlsOn {
			return nil, errors.New("REALITY (reality-opts) указан без tls: true — такой узел не работает и в mihomo")
		}
		q.Set("security", "reality")
		q.Set("pbk", publicKey)
		setIf(q, "sid", reality.str("short-id"))
	case tlsOn:
		q.Set("security", "tls")
	default:
		q.Set("security", "none")
	}
	wsHost, err := clashTransport(m, q, tlsOn)
	if err != nil {
		return nil, err
	}
	if !tlsOn {
		return q, nil
	}
	if err := clashCertificate(m, q); err != nil {
		return nil, err
	}
	setIf(q, "fp", m.str("client-fingerprint"))
	// mihomo reads servername for vless and vmess, sni for trojan; the other
	// key is taken when the right one is missing, it is what the generator meant
	sni := clashFirst(m, "servername", "sni")
	if typ == "trojan" {
		sni = clashFirst(m, "sni", "servername")
	} else if sni == "" {
		sni = wsHost
	}
	if sni == "" {
		sni = server
	}
	q.Set("sni", sni)
	return q, nil
}

// clashFirst is the first of the keys that has a value
func clashFirst(m clashMap, keys ...string) string {
	for _, key := range keys {
		if s := strings.TrimSpace(m.str(key)); s != "" {
			return s
		}
	}
	return ""
}

// clashTransport sets the transport of a vless, vmess or trojan entry in the
// link's query, under the names the link parser reads. wsHost is the Host
// header of a WebSocket or an HTTPUpgrade: mihomo's server name for TLS when
// the entry names none.
func clashTransport(m clashMap, q url.Values, tlsOn bool) (wsHost string, err error) {
	network := strings.ToLower(strings.TrimSpace(m.str("network")))
	switch network {
	case "", "tcp":
		return "", nil
	case "ws":
		ws := m.sub("ws-opts")
		path := ws.str("path")
		if !ws.has("path") {
			path = m.str("ws-path") // Clash's keys from before ws-opts
		}
		headers := ws.sub("headers")
		if headers.v == nil {
			headers = m.sub("ws-headers")
		}
		host := clashHostHeader(headers)
		if ws.flag("v2ray-http-upgrade") {
			q.Set("type", "httpupgrade")
		} else {
			q.Set("type", "ws")
			if ed := ws.integer("max-early-data"); ed > 0 {
				if name := strings.TrimSpace(ws.str("early-data-header-name")); name != "" {
					q.Set("ed", strconv.Itoa(ed))
					q.Set("eh", name)
				} else {
					// mihomo then appends the early data to the path, which no
					// link says (ed means the header). Early data is only a
					// shortcut: the server takes the connection without it
					ws.drop("max-early-data")
				}
			}
		}
		setIf(q, "path", path)
		setIf(q, "host", host)
		return host, nil
	case "httpupgrade":
		// 3x-ui's own spelling; mihomo calls it ws with v2ray-http-upgrade
		opts := m.sub("http-upgrade-opts")
		host := strings.TrimSpace(opts.str("host"))
		if headers := clashHostHeader(opts.sub("headers")); host == "" {
			host = headers
		}
		q.Set("type", "httpupgrade")
		setIf(q, "path", opts.str("path"))
		setIf(q, "host", host)
		return host, nil
	case "http":
		// Plain TCP with an HTTP/1.1 request in front: v2ray's "http"
		// header of TCP. mihomo sends one of the paths and hosts at random,
		// the link parser takes the first path — the server checks none
		opts := m.sub("http-opts")
		headers := opts.sub("headers")
		q.Set("type", "tcp")
		q.Set("headerType", "http")
		setIf(q, "path", strings.Join(opts.list("path"), ","))
		setIf(q, "host", strings.Join(headers.list("host"), ","))
		if method := strings.TrimSpace(opts.str("method")); method != "" && !strings.EqualFold(method, "GET") {
			opts.drop("method")
		}
		clashOtherHeaders(headers)
		return "", nil
	case "h2":
		if !tlsOn {
			// HTTP/2 without TLS (h2c): sing-box's HTTP transport speaks
			// HTTP/1.1 there
			return "", errors.New("транспорт h2 без TLS не поддерживается sing-box")
		}
		opts := m.sub("h2-opts")
		q.Set("type", "http")
		setIf(q, "host", strings.Join(opts.list("host"), ","))
		setIf(q, "path", opts.str("path"))
		return "", nil
	case "grpc":
		q.Set("type", "grpc")
		setIf(q, "serviceName", m.sub("grpc-opts").str("grpc-service-name"))
		return "", nil
	}
	// The rest (xhttp, mkcp, quic, …) under its own name: the link parser
	// knows which of them sing-box has and why the others cannot be imported
	q.Set("type", network)
	return "", nil
}

// clashHostHeader is the Host header of a WebSocket's header map. No link
// carries the other headers (servers rarely check them): they are left out.
func clashHostHeader(headers clashMap) string {
	clashOtherHeaders(headers)
	return strings.TrimSpace(headers.str("host"))
}

// clashOtherHeaders notes the headers other than Host as left out
func clashOtherHeaders(headers clashMap) {
	if headers.v == nil {
		return
	}
	others := 0
	for key := range headers.v.fields {
		if key != "host" {
			others++
		}
	}
	if others > 0 {
		headers.e.dropped = append(headers.e.dropped, fmt.Sprintf("%s (%d)", strings.TrimSuffix(headers.path, "."), others))
	}
}

// clashTLSAddons refuses mihomo's TLS camouflages: no link carries them,
// and the server answers nothing else
func clashTLSAddons(m clashMap) error {
	for _, addon := range []struct{ key, name string }{
		{"shadow-tls-opts", "ShadowTLS"}, {"restls-opts", "Restls"}, {"jls-opts", "JLS"}, {"tlsmirror-opts", "TLSMirror"},
	} {
		if m.set(addon.key) {
			return fmt.Errorf("%s (%s) приложение не импортирует", addon.name, addon.key)
		}
	}
	return nil
}

// clashCertificate sets the certificate check of a TLS entry in the link's
// query, where certificateCheck decides it as for the links:
// skip-cert-verify, the pin (fingerprint, or the pin-sha256 list 3x-ui
// writes) and name-cert-verify (Xray's vcn). A client certificate no link
// carries, and the server refuses the node without it; nor ECH, which is
// there to hide the server name from the network.
func clashCertificate(m clashMap, q url.Values) error {
	if m.str("certificate") != "" || m.str("private-key") != "" {
		return errors.New("клиентский сертификат (certificate, private-key) приложение не импортирует")
	}
	if m.sub("ech-opts").flag("enable") {
		return errors.New("ECH (ech-opts) приложение не импортирует")
	}
	if m.flag("skip-cert-verify") {
		q.Set("insecure", "1")
	}
	pin := m.str("fingerprint")
	if pins := m.list("pin-sha256"); pin == "" && len(pins) > 0 {
		pin = pins[0]
	}
	setIf(q, "pinSHA256", pin)
	setIf(q, "vcn", m.str("name-cert-verify"))
	setIf(q, "alpn", strings.Join(m.list("alpn"), ","))
	return nil
}

func clashShadowsocks(m clashMap) (string, error) {
	server, port, err := clashEndpoint(m)
	if err != nil {
		return "", err
	}
	cipher := strings.TrimSpace(m.str("cipher"))
	password := m.str("password")
	if password == "" && !strings.EqualFold(cipher, "none") {
		return "", errors.New("не указан пароль (password)")
	}
	q := url.Values{}
	if plugin := strings.TrimSpace(m.str("plugin")); plugin != "" {
		spec, err := clashPlugin(plugin, m.sub("plugin-opts"))
		if err != nil {
			return "", err
		}
		q.Set("plugin", spec)
	}
	// 3x-ui writes its Shadowsocks over an Xray transport or TLS here too
	// (mihomo ignores both); the link parser refuses them, as it does on
	// 3x-ui's ss:// links
	if network := strings.ToLower(strings.TrimSpace(m.str("network"))); network != "" && network != "tcp" {
		q.Set("type", network)
	}
	if m.flag("tls") {
		q.Set("security", "tls")
	}
	if m.flag("udp-over-tcp") {
		// UDP then goes to the server as UDP, which a Shadowsocks server
		// takes as well
		m.drop("udp-over-tcp")
	}
	link := "ss://" + base64.RawURLEncoding.EncodeToString([]byte(cipher+":"+password)) + "@" + net.JoinHostPort(server, strconv.Itoa(port))
	if len(q) > 0 {
		link += "?" + q.Encode()
	}
	return link, nil
}

// clashPlugin is the SIP003 string of a shadowsocks entry's plugin and
// plugin-opts, for pluginConfig to check as a link's plugin. mihomo's
// defaults are written out: its obfs and v2ray-plugin send Host bing.com
// when none is given, and its v2ray-plugin multiplexes unless mux is off.
func clashPlugin(name string, opts clashMap) (string, error) {
	var parts []string
	add := func(key, value string) {
		parts = append(parts, escapePluginValue(key)+"="+escapePluginValue(value))
	}
	host := strings.TrimSpace(opts.str("host"))
	if host == "" {
		host = "bing.com"
	}
	switch strings.ToLower(name) {
	case "obfs", "obfs-local", "simple-obfs":
		add("obfs", strings.TrimSpace(opts.str("mode")))
		add("obfs-host", host)
		return "obfs-local;" + strings.Join(parts, ";"), nil
	case "v2ray-plugin":
		if opts.flag("tls") {
			// sing-box's v2ray-plugin checks the certificate for the host
			// against the system roots, nothing else
			switch {
			case opts.flag("skip-cert-verify"):
				return "", errors.New("отключение проверки сертификата (skip-cert-verify) для плагина v2ray-plugin не поддерживается sing-box")
			case opts.str("certificate") != "" || opts.str("private-key") != "":
				return "", errors.New("клиентский сертификат (certificate, private-key) приложение не импортирует")
			case opts.sub("ech-opts").flag("enable"):
				return "", errors.New("ECH (ech-opts) приложение не импортирует")
			}
			if name := strings.TrimSpace(opts.str("name-cert-verify")); name != "" && !strings.EqualFold(name, host) {
				return "", errors.New("проверка сертификата по другому имени (name-cert-verify) не поддерживается sing-box")
			}
			if opts.str("fingerprint") != "" {
				// A pin is dropped as on the links: the chain is checked instead
				opts.drop("fingerprint")
			}
		}
		if opts.flag("v2ray-http-upgrade") {
			return "", errors.New("режим v2ray-http-upgrade плагина v2ray-plugin не поддерживается sing-box")
		}
		mode := strings.TrimSpace(opts.str("mode"))
		if mode == "" {
			mode = "websocket"
		}
		add("mode", mode)
		add("host", host)
		if path := opts.str("path"); path != "" {
			add("path", path)
		}
		if opts.flag("tls") {
			parts = append(parts, "tls")
		}
		mux := "1"
		if opts.has("mux") && !opts.flag("mux") {
			mux = "0"
		}
		add("mux", mux)
		clashOtherHeaders(opts.sub("headers"))
		return "v2ray-plugin;" + strings.Join(parts, ";"), nil
	}
	// Any other plugin under its own name: pluginConfig refuses it by name
	return escapePluginValue(name), nil
}

func clashHysteria2(m clashMap) (string, error) {
	server, err := clashHost(m.str("server"))
	if err != nil {
		return "", err
	}
	ports := clashPorts(m)
	port, err := clashHopPort(m, ports)
	if err != nil {
		return "", err
	}
	if m.sub("realm-opts").flag("enable") {
		return "", errors.New("режим realm Hysteria 2 приложение не импортирует")
	}
	q := url.Values{}
	if err := clashCertificate(m, q); err != nil {
		return "", err
	}
	setIf(q, "sni", m.str("sni"))
	setIf(q, "obfs", m.str("obfs"))
	setIf(q, "obfs-password", m.str("obfs-password"))
	setIf(q, "mport", ports)
	setIf(q, "mportHopInt", m.str("hop-interval"))
	userinfo := ""
	if password := m.str("password"); password != "" {
		userinfo = url.User(password).String() + "@"
	}
	return "hysteria2://" + userinfo + net.JoinHostPort(server, strconv.Itoa(port)) + "/?" + q.Encode(), nil
}

// clashPorts is a Hysteria entry's port-hopping list as the links write it;
// mihomo separates the ranges by ',' or '/'
func clashPorts(m clashMap) string {
	return strings.ReplaceAll(strings.TrimSpace(m.str("ports")), "/", ",")
}

// clashHopPort is the port of a Hysteria entry: port, or with a hopping
// list and no port the first port of the list (with a list mihomo ignores
// port, and so does sing-box)
func clashHopPort(m clashMap, ports string) (int, error) {
	if ports == "" {
		_, port, err := clashEndpoint(m)
		return port, err
	}
	_, first, err := parsePortList(ports)
	if err != nil {
		return 0, err
	}
	if port := m.integer("port"); port >= 1 && port <= 65535 {
		return port, nil
	}
	return first, nil
}

func clashHysteria(m clashMap) (string, error) {
	server, err := clashHost(m.str("server"))
	if err != nil {
		return "", err
	}
	ports := clashPorts(m)
	port, err := clashHopPort(m, ports)
	if err != nil {
		return "", err
	}
	up, down := clashMbps(m, "up", "up-speed"), clashMbps(m, "down", "down-speed")
	if up <= 0 || down <= 0 {
		return "", errors.New("не указана скорость канала (up и down), без неё sing-box не запускает Hysteria")
	}
	// auth is the password in base64 and wins over auth-str, as in mihomo
	auth := m.str("auth-str")
	if raw := strings.TrimSpace(m.str("auth")); raw != "" {
		decoded, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return "", errors.New("поле «auth» повреждено (нужен base64)")
		}
		if !utf8.Valid(decoded) {
			return "", errors.New("пароль Hysteria (auth) — не текст, такой приложение не импортирует")
		}
		auth = string(decoded)
	}
	q := url.Values{}
	if err := clashCertificate(m, q); err != nil {
		return "", err
	}
	setIf(q, "protocol", clashFirst(m, "obfs-protocol", "protocol"))
	setIf(q, "auth", auth)
	setIf(q, "peer", m.str("sni"))
	q.Set("upmbps", strconv.Itoa(up))
	q.Set("downmbps", strconv.Itoa(down))
	if obfs := m.str("obfs"); obfs != "" {
		// mihomo's obfs is the password of xplus, the only Hysteria obfuscation
		q.Set("obfs", "xplus")
		q.Set("obfsParam", obfs)
	}
	setIf(q, "mport", ports)
	setIf(q, "mportHopInt", m.str("hop-interval"))
	return "hysteria://" + net.JoinHostPort(server, strconv.Itoa(port)) + "?" + q.Encode(), nil
}

// ratePattern: a speed with its unit, as mihomo reads it ("30 Mbps": bits,
// "10 MBps": bytes)
var ratePattern = regexp.MustCompile(`^(\d+)\s*([KMGTkmgt]?)([Bb])ps$`)

// clashMbps is a Hysteria speed in Mbps: Stash's speedKey (a number of
// Mbps), else key — a bare number of Mbps or a rate with its unit
func clashMbps(m clashMap, key, speedKey string) int {
	if n := m.integer(speedKey); n > 0 {
		return n
	}
	s := strings.TrimSpace(m.str(key))
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	match := ratePattern.FindStringSubmatch(s)
	if match == nil {
		return 0
	}
	rate, err := strconv.ParseFloat(match[1], 64)
	if err != nil || rate <= 0 {
		return 0
	}
	rate *= map[string]float64{"": 1e-6, "k": 1e-3, "m": 1, "g": 1e3, "t": 1e6}[strings.ToLower(match[2])]
	if match[3] == "B" {
		rate *= 8
	}
	// A slower line is at least 1 Mbps: sing-box takes whole numbers only
	return max(int(rate), 1)
}

func clashTUIC(m clashMap) (string, error) {
	server, port, err := clashEndpoint(m)
	if err != nil {
		return "", err
	}
	// mihomo dials ip when it is given; the server stays the TLS name
	dial := server
	if ip := strings.TrimSpace(m.str("ip")); ip != "" {
		if dial, err = clashHost(ip); err != nil {
			return "", err
		}
	}
	var userinfo string
	if token := m.str("token"); token != "" {
		// A token means TUIC v4 to mihomo, whatever else the entry has: the
		// link parser says why sing-box cannot take it
		userinfo = url.User(token).String()
	} else {
		uuid, password := strings.TrimSpace(m.str("uuid")), m.str("password")
		if uuid == "" {
			return "", errors.New("не указан uuid")
		}
		if password == "" {
			return "", errors.New("не указан пароль (password)")
		}
		userinfo = url.UserPassword(uuid, password).String()
	}
	q := url.Values{}
	if err := clashCertificate(m, q); err != nil {
		return "", err
	}
	sni := strings.TrimSpace(m.str("sni"))
	if sni == "" {
		sni = server
	}
	q.Set("sni", sni)
	if m.flag("disable-sni") {
		// mihomo then also skips the certificate check; sing-box keeps it
		// for the server name (a self-signed certificate fails closed)
		q.Set("disable_sni", "1")
	}
	setIf(q, "congestion_control", m.str("congestion-controller"))
	setIf(q, "udp_relay_mode", m.str("udp-relay-mode"))
	return "tuic://" + userinfo + "@" + net.JoinHostPort(dial, strconv.Itoa(port)) + "?" + q.Encode(), nil
}

func clashAnyTLS(m clashMap) (string, error) {
	server, port, err := clashEndpoint(m)
	if err != nil {
		return "", err
	}
	password := m.str("password")
	if password == "" {
		return "", errors.New("не указан пароль (password)")
	}
	if err := clashTLSAddons(m); err != nil {
		return "", err
	}
	q := url.Values{}
	if err := clashCertificate(m, q); err != nil {
		return "", err
	}
	setIf(q, "sni", m.str("sni"))
	setIf(q, "fp", m.str("client-fingerprint"))
	return "anytls://" + url.User(password).String() + "@" + net.JoinHostPort(server, strconv.Itoa(port)) + "/?" + q.Encode(), nil
}

func clashSOCKS(m clashMap) (string, error) {
	server, port, err := clashEndpoint(m)
	if err != nil {
		return "", err
	}
	if m.flag("tls") {
		return "", errors.New("SOCKS поверх TLS не поддерживается sing-box")
	}
	// mihomo authenticates only with a user name
	userinfo := ""
	if user := m.str("username"); user != "" {
		userinfo = url.UserPassword(user, m.str("password")).String() + "@"
	}
	return "socks5://" + userinfo + net.JoinHostPort(server, strconv.Itoa(port)), nil
}

// clashValue is a YAML value of a proxy entry: a scalar as the provider
// wrote it, a mapping (keys folded as mihomo matches them, clashKey) or a
// list. Values are shared where YAML aliases repeat them: read only.
type clashValue struct {
	kind   yaml.Kind
	text   string // a scalar, quotes removed
	tag    string // YAML's type of the scalar: !!str, !!int, !!bool, !!null, …
	fields map[string]*clashValue
	items  []*clashValue
	// size is the value with its aliases expanded, about its bytes: what
	// reading and translating it may cost (capped at clashSizeCap)
	size int64
}

// sizeAdd adds sizes, the sum capped at clashSizeCap (both are)
func sizeAdd(a, b int64) int64 {
	return min(a+b, clashSizeCap)
}

// field is the value of a mapping's key, nil when the key is absent or null
func (v *clashValue) field(key string) *clashValue {
	if v == nil {
		return nil
	}
	f := v.fields[key]
	if f == nil || f.kind == yaml.ScalarNode && f.tag == "!!null" {
		return nil
	}
	return f
}

// clashKey is how mihomo matches a key to an option: case-insensitively
// (strings.EqualFold: KELVIN SIGN is k, LONG S is s), '_' as '-'
func clashKey(key string) string {
	return foldKey(strings.ReplaceAll(key, "_", "-"))
}

// clashEntry is the state of one entry's translation: the first malformed
// field (it explains a refusal best) and the options left out (logged)
type clashEntry struct {
	err     error
	dropped []string
}

// clashMap is a mapping of an entry — the entry itself or one of its option
// maps, path being its keys for the reasons ("ws-opts.") — read the way
// mihomo's decoder reads it
type clashMap struct {
	v    *clashValue
	path string
	e    *clashEntry
}

// clashFieldPattern: a key path that can be named in a reason
var clashFieldPattern = regexp.MustCompile(`^[a-z0-9.-]{1,60}$`)

func clashField(path string) string {
	if clashFieldPattern.MatchString(path) {
		return path
	}
	return "…"
}

func (m clashMap) bad(key string) {
	if m.e.err == nil {
		m.e.err = fmt.Errorf("поле «%s» повреждено", clashField(m.path+key))
	}
}

func (m clashMap) drop(key string) {
	m.e.dropped = append(m.e.dropped, m.path+key)
}

func (m clashMap) has(key string) bool {
	return m.v.field(key) != nil
}

// str is a scalar as written: a number or a boolean too, as mihomo's weak
// decoding takes them
func (m clashMap) str(key string) string {
	v := m.v.field(key)
	if v == nil {
		return ""
	}
	if v.kind != yaml.ScalarNode {
		m.bad(key)
		return ""
	}
	return v.text
}

// integer is a decimal number, written as one or as a string
func (m clashMap) integer(key string) int {
	v := m.v.field(key)
	if v == nil {
		return 0
	}
	if v.kind == yaml.ScalarNode && (v.tag == "!!int" || v.tag == "!!str") {
		if n, err := strconv.Atoi(strings.ReplaceAll(strings.TrimSpace(v.text), "_", "")); err == nil {
			return n
		}
	}
	m.bad(key)
	return 0
}

// flag is a boolean: YAML's, a number (non-zero is true, as in mihomo) or
// the words YAML 1.1 has for them
func (m clashMap) flag(key string) bool {
	v := m.v.field(key)
	if v == nil {
		return false
	}
	if v.kind == yaml.ScalarNode {
		switch s := strings.ToLower(strings.TrimSpace(v.text)); s {
		case "true", "yes", "on":
			return true
		case "false", "no", "off":
			return false
		default:
			if n, err := strconv.Atoi(s); err == nil {
				return n != 0
			}
		}
	}
	m.bad(key)
	return false
}

// list is a list of scalars; a single scalar is read as a comma-separated
// list
func (m clashMap) list(key string) []string {
	v := m.v.field(key)
	if v == nil {
		return nil
	}
	switch v.kind {
	case yaml.ScalarNode:
		return splitList(v.text)
	case yaml.SequenceNode:
		var items []string
		for _, item := range v.items {
			if item.kind != yaml.ScalarNode {
				m.bad(key)
				return nil
			}
			if s := strings.TrimSpace(item.text); s != "" && item.tag != "!!null" {
				items = append(items, s)
			}
		}
		return items
	}
	m.bad(key)
	return nil
}

// sub is an option map of the mapping; an empty one when it is absent
func (m clashMap) sub(key string) clashMap {
	v := m.v.field(key)
	if v != nil && v.kind != yaml.MappingNode {
		m.bad(key)
		v = nil
	}
	return clashMap{v: v, path: m.path + key + ".", e: m.e}
}

// set reports whether an option map has any of its fields set: mihomo turns
// such an option on then. One level deep — aliases may make the values a
// graph far larger than the text.
func (m clashMap) set(key string) bool {
	v := m.v.field(key)
	if v == nil {
		return false
	}
	if v.kind != yaml.MappingNode {
		m.bad(key)
		return false
	}
	for _, f := range v.fields {
		if f.kind != yaml.ScalarNode {
			return true
		}
		if s := strings.ToLower(strings.TrimSpace(f.text)); f.tag != "!!null" && s != "" && s != "false" && s != "0" {
			return true
		}
	}
	return false
}

// yamlReader converts YAML nodes into clashValues. Each node is converted
// once however often aliases repeat it (a few lines of anchors can stand
// for billions of values), and an alias pointing back into the node that
// holds it is refused. What the expanded values may cost is budgeted (see
// clashExpansionAllowance).
type yamlReader struct {
	done   map[*yaml.Node]yamlResult
	active map[*yaml.Node]bool
	// expansion is what the entries may still come to (entry), merges the
	// fields merge keys may still copy
	expansion int64
	merges    int
}

type yamlResult struct {
	v   *clashValue
	err error
}

// newYAMLReader is a reader for a profile text of the given length
func newYAMLReader(textLen int) *yamlReader {
	return &yamlReader{
		done:      map[*yaml.Node]yamlResult{},
		active:    map[*yaml.Node]bool{},
		expansion: 2*int64(textLen) + clashExpansionAllowance,
		merges:    textLen/2 + clashMergeAllowance,
	}
}

// entry charges an entry of the profile, converted, to the expansion: false
// once the entries come to more than the profile may expand to
func (r *yamlReader) entry(v *clashValue) bool {
	r.expansion -= v.size
	return r.expansion >= 0
}

func (r *yamlReader) value(n *yaml.Node) (*clashValue, error) {
	if n.Kind == yaml.AliasNode {
		if n.Alias == nil {
			return nil, errClashEntry
		}
		n = n.Alias
	}
	if res, seen := r.done[n]; seen {
		return res.v, res.err
	}
	if r.active[n] {
		return nil, errClashEntry
	}
	r.active[n] = true
	v, err := r.convert(n)
	delete(r.active, n)
	r.done[n] = yamlResult{v, err}
	return v, err
}

func (r *yamlReader) convert(n *yaml.Node) (*clashValue, error) {
	switch n.Kind {
	case yaml.ScalarNode:
		text, tag, ok := scalarText(n)
		if !ok {
			// A value of no kind: every reader takes it for a malformed field
			return &clashValue{size: 1}, nil
		}
		return &clashValue{kind: yaml.ScalarNode, text: text, tag: tag, size: 1 + int64(len(text))}, nil
	case yaml.SequenceNode:
		v := &clashValue{kind: yaml.SequenceNode, items: make([]*clashValue, 0, len(n.Content)), size: 1}
		for _, item := range n.Content {
			iv, err := r.value(item)
			if err != nil {
				return nil, err
			}
			v.items = append(v.items, iv)
			v.size = sizeAdd(v.size, iv.size)
		}
		return v, nil
	case yaml.MappingNode:
		return r.mapping(n)
	}
	return nil, errClashEntry
}

// scalarText is the value of a scalar as YAML gives it, with its type
// (ShortTag). An explicit !!binary is base64, line breaks ignored, as
// yaml.v3 decodes it for mihomo; ok is false when it is none or does not
// come to text (the bytes would not survive the config's JSON).
func scalarText(n *yaml.Node) (text, tag string, ok bool) {
	if tag = n.ShortTag(); tag != "!!binary" {
		return n.Value, tag, true
	}
	data, err := base64.StdEncoding.DecodeString(n.Value)
	if err != nil || !utf8.Valid(data) {
		return "", "", false
	}
	return string(data), "!!str", true
}

// mapping converts a YAML mapping with its merge keys ("<<: *base"): the
// keys of the mapping itself win, then the merged maps in their order, as
// YAML merges them. A key given twice (in any spelling mihomo matches the
// same) is refused: which one mihomo takes is a matter of chance.
func (r *yamlReader) mapping(n *yaml.Node) (*clashValue, error) {
	v := &clashValue{kind: yaml.MappingNode, fields: make(map[string]*clashValue, len(n.Content)/2)}
	var merges []*yaml.Node
	for i := 0; i+1 < len(n.Content); i += 2 {
		k := n.Content[i]
		if k.Kind != yaml.ScalarNode {
			return nil, errClashEntry
		}
		if k.ShortTag() == "!!merge" {
			merges = append(merges, n.Content[i+1])
			continue
		}
		text, _, ok := scalarText(k)
		if !ok {
			return nil, errClashEntry
		}
		key := clashKey(text)
		if _, twice := v.fields[key]; twice {
			return nil, fmt.Errorf("параметр «%s» указан в узле дважды", clashField(key))
		}
		fv, err := r.value(n.Content[i+1])
		if err != nil {
			return nil, err
		}
		v.fields[key] = fv
	}
	for _, merge := range merges {
		sources := []*yaml.Node{merge}
		if merge.Kind == yaml.SequenceNode {
			sources = merge.Content
		}
		for _, source := range sources {
			sv, err := r.value(source)
			if err != nil {
				return nil, err
			}
			if sv.kind != yaml.MappingNode {
				return nil, errClashEntry
			}
			if r.merges -= len(sv.fields); r.merges < 0 {
				return nil, errClashExpansion
			}
			for key, fv := range sv.fields {
				if _, set := v.fields[key]; !set {
					v.fields[key] = fv
				}
			}
		}
	}
	v.size = 1
	for key, fv := range v.fields {
		v.size = sizeAdd(v.size, sizeAdd(int64(len(key)), fv.size))
	}
	return v, nil
}
