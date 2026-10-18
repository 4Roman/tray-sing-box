package sharelink

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Xray JSON profiles: one Xray configuration, or 3x-ui's JSON subscription —
// an array of whole configurations, one node each, named by its "remarks".
// Each proxy outbound is translated into the share link that says the same
// (vless://, vmess://, trojan://, ss://, socks5://) and that link goes
// through the link parsers: what they map or refuse, they map or refuse here
// too. Checked here is what a link cannot say: the chain of a dialer proxy
// (sockopt.dialerProxy, sing-box's detour), the HTTP proxy outbound (there is
// no link for it), and what would make the node connect elsewhere than, or
// not as, Xray connects.
//
// The outbounds are decoded as Xray decodes them, with encoding/json into
// structs (Xray-core infra/conf): a key matches in any case, of two
// spellings of one key the last wins.

// xrayStructural are the outbounds of the profile's own plumbing (direct,
// block, the DNS hijack, the loopback to the routing)
var xrayStructural = map[string]bool{"freedom": true, "blackhole": true, "dns": true, "loopback": true}

var errXrayBroken = errors.New("запись outbound повреждена")

// xrayStringList is Xray's StringList: an array of strings or one string of
// comma-separated items — kept as it is, the link joins the items with
// commas anyway (joined)
type xrayStringList []string

func (l *xrayStringList) UnmarshalJSON(data []byte) error {
	var list []string
	if json.Unmarshal(data, &list) == nil {
		*l = list
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	*l = xrayStringList{s}
	return nil
}

// joined is the items of the lists as one comma-separated value, empty ones
// dropped
func joined(lists ...xrayStringList) string {
	var items []string
	for _, list := range lists {
		for _, item := range list {
			if item = strings.TrimSpace(item); item != "" {
				items = append(items, item)
			}
		}
	}
	return strings.Join(items, ",")
}

// present: a JSON value that is there and is not null
func present(raw json.RawMessage) bool {
	s := bytes.TrimSpace(raw)
	return len(s) > 0 && !bytes.Equal(s, []byte("null"))
}

type xrayHead struct {
	Protocol string `json:"protocol"`
	Tag      string `json:"tag"`
}

type xrayOutbound struct {
	Settings       json.RawMessage `json:"settings"`
	StreamSettings *xrayStream     `json:"streamSettings"`
	ProxySettings  json.RawMessage `json:"proxySettings"`
}

// xrayAccount is a user of an outbound, or the flat settings that carry it
type xrayAccount struct {
	ID         string          `json:"id"`
	Flow       string          `json:"flow"`
	Encryption string          `json:"encryption"`
	Security   string          `json:"security"`
	Password   string          `json:"password"`
	Method     string          `json:"method"`
	User       string          `json:"user"`
	Pass       string          `json:"pass"`
	Reverse    json.RawMessage `json:"reverse"`
}

// xrayServer is an entry of vnext or servers, or the flat settings
type xrayServer struct {
	Address *string         `json:"address"`
	Port    json.RawMessage `json:"port"`
	Users   []xrayAccount   `json:"users"`
	xrayAccount
}

type xraySettings struct {
	xrayServer
	Vnext   []xrayServer      `json:"vnext"`
	Servers []xrayServer      `json:"servers"`
	Headers map[string]string `json:"headers"`
}

// server is the outbound's server: the settings themselves in Xray's flat
// form — it wins whenever it names an address, as in Xray — else the first
// of the list. Xray runs one server only; an older one balanced between
// several, and any of them is a working node.
func (s *xraySettings) server(list []xrayServer) xrayServer {
	if s.Address != nil {
		return s.xrayServer
	}
	if len(list) == 0 {
		return xrayServer{}
	}
	if len(list) > 1 {
		log.Printf("Xray profile: %d more server(s) of an outbound left out, the first one is taken", len(list)-1)
	}
	return list[0]
}

// user is the server's user (vless, vmess, socks, http): the flat settings
// themselves, else the first of its users
func (s *xraySettings) user(server xrayServer) xrayAccount {
	if s.Address != nil {
		return s.xrayAccount
	}
	if len(server.Users) == 0 {
		return xrayAccount{}
	}
	if len(server.Users) > 1 {
		log.Printf("Xray profile: %d more user(s) of an outbound left out, the first one is taken", len(server.Users)-1)
	}
	return server.Users[0]
}

type xrayStream struct {
	Address             json.RawMessage `json:"address"`
	Method              *string         `json:"method"`
	Network             *string         `json:"network"`
	Security            string          `json:"security"`
	FinalMask           json.RawMessage `json:"finalmask"`
	TLSSettings         *xrayTLS        `json:"tlsSettings"`
	XTLSSettings        *xrayTLS        `json:"xtlsSettings"`
	RealitySettings     *xrayReality    `json:"realitySettings"`
	RawSettings         *xrayRaw        `json:"rawSettings"`
	TCPSettings         *xrayRaw        `json:"tcpSettings"`
	WSSettings          *xrayWS         `json:"wsSettings"`
	HTTPUpgradeSettings *xrayWS         `json:"httpupgradeSettings"`
	GRPCSettings        *xrayGRPC       `json:"grpcSettings"`
	HTTPSettings        *xrayH2         `json:"httpSettings"`
	QUICSettings        *xrayQUIC       `json:"quicSettings"`
	Sockopt             *xraySockopt    `json:"sockopt"`
}

type xrayTLS struct {
	ServerName           string          `json:"serverName"`
	AllowInsecure        json.RawMessage `json:"allowInsecure"`
	ALPN                 xrayStringList  `json:"alpn"`
	Fingerprint          string          `json:"fingerprint"`
	PinnedPeerCertSha256 xrayStringList  `json:"pinnedPeerCertSha256"`
	VerifyPeerCertByName xrayStringList  `json:"verifyPeerCertByName"`
	ECHConfigList        string          `json:"echConfigList"`
	Certificates         json.RawMessage `json:"certificates"`
	// The same checks under the names of earlier Xray versions
	PinnedChain        xrayStringList `json:"pinnedPeerCertificateChainSha256"`
	PinnedPublicKey    xrayStringList `json:"pinnedPeerCertificatePublicKeySha256"`
	VerifyInNames      xrayStringList `json:"verifyPeerCertInNames"`
	ServerNameToVerify string         `json:"serverNameToVerify"`
}

type xrayReality struct {
	ServerName    string `json:"serverName"`
	Fingerprint   string `json:"fingerprint"`
	PublicKey     string `json:"publicKey"`
	Password      string `json:"password"`
	ShortID       string `json:"shortId"`
	SpiderX       string `json:"spiderX"`
	Mldsa65Verify string `json:"mldsa65Verify"`
}

type xrayRaw struct {
	Header json.RawMessage `json:"header"`
}

type xrayWS struct {
	Host    string            `json:"host"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
}

type xrayGRPC struct {
	ServiceName string `json:"serviceName"`
	Authority   string `json:"authority"`
	MultiMode   bool   `json:"multiMode"`
}

type xrayH2 struct {
	Host xrayStringList `json:"host"`
	Path string         `json:"path"`
}

type xrayQUIC struct {
	Security string `json:"security"`
	Key      string `json:"key"`
	Header   struct {
		Type string `json:"type"`
	} `json:"header"`
}

type xraySockopt struct {
	DialerProxy         string `json:"dialerProxy"`
	AddressPortStrategy string `json:"addressPortStrategy"`
}

// xrayProfile is one Xray configuration: its outbounds and its name
type xrayProfile struct {
	remarks   string
	outbounds []json.RawMessage
	balancer  bool // its routing balances between its outbounds
}

// xrayConfigOf reads raw as a whole configuration: an object whose
// "outbounds" is an array, the way profile() recognized it
func xrayConfigOf(raw json.RawMessage) (xrayProfile, bool) {
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		return xrayProfile{}, false
	}
	list := bytes.TrimSpace(obj["outbounds"])
	var p xrayProfile
	if len(list) == 0 || list[0] != '[' || json.Unmarshal(list, &p.outbounds) != nil {
		return xrayProfile{}, false
	}
	_ = json.Unmarshal(obj["remarks"], &p.remarks) // a name, when it is a string
	var routing struct {
		Balancers []json.RawMessage `json:"balancers"`
	}
	p.balancer = json.Unmarshal(obj["routing"], &routing) == nil && len(routing.Balancers) > 0
	return p, true
}

// xray takes the nodes of an Xray profile: one configuration, an array of
// them (3x-ui), or a bare array of outbounds.
//
// A configuration that balances (routing.balancers) is a group, its remarks
// the group's name: 3x-ui's balancer documents carry copies of the other
// documents' nodes, retagged. Such a configuration is read after the others,
// its remarks name no node, and a node the profile already gave is not taken
// twice.
func (c *collector) xray(text string) {
	var profiles []xrayProfile
	if text = strings.TrimSpace(text); strings.HasPrefix(text, "{") {
		if p, ok := xrayConfigOf(json.RawMessage(text)); ok {
			profiles = append(profiles, p)
		}
	} else {
		var items []json.RawMessage
		_ = json.Unmarshal([]byte(text), &items)
		// Bare outbounds between the configurations are one configuration:
		// their dialer chains name each other
		var bare []json.RawMessage
		for _, item := range items {
			if p, ok := xrayConfigOf(item); ok {
				if len(bare) > 0 {
					profiles = append(profiles, xrayProfile{outbounds: bare})
					bare = nil
				}
				profiles = append(profiles, p)
				continue
			}
			bare = append(bare, item)
		}
		if len(bare) > 0 {
			profiles = append(profiles, xrayProfile{outbounds: bare})
		}
	}
	counter := 0
	taken := map[string]string{} // the content of every node the profile gave -> its tag
	for _, balancers := range []bool{false, true} {
		for _, p := range profiles {
			if p.balancer == balancers {
				c.xrayConfig(p, &counter, taken)
			}
		}
	}
}

// xrayContent is what tells an outbound from another: all but its tag
func xrayContent(o Outbound) string {
	other := maps.Clone(o)
	delete(other, "tag")
	data, _ := json.Marshal(other)
	return string(data)
}

// xrayConfig takes the proxy outbounds of one configuration. Its first one
// is named by the remarks (3x-ui's node, tagged "proxy" in every
// configuration of the array), the others by their tags. The tags of a
// configuration name each other in the dialer chains; the chains are checked
// as those of a sing-box profile (keepChains) and point at the tags the nodes
// get when they are added. counter numbers the outbounds of the whole
// profile, for the names of nodes without one; taken holds the nodes the
// profile gave so far (see xray).
func (c *collector) xrayConfig(p xrayProfile, counter *int, taken map[string]string) {
	type entry struct {
		raw      json.RawMessage
		head     xrayHead
		protocol string
		broken   bool
		n        int
	}
	var entries []entry
	freedoms := map[string]xrayFreedom{} // a freedom's tag -> what it does besides the direct connection
	for _, raw := range p.outbounds {
		if trimmed := bytes.TrimSpace(raw); len(trimmed) == 0 || trimmed[0] != '{' {
			continue // no outbound at all, as in a sing-box profile
		}
		*counter++
		e := entry{raw: raw, n: *counter}
		e.broken = json.Unmarshal(raw, &e.head) != nil
		e.protocol = strings.ToLower(strings.TrimSpace(e.head.Protocol))
		if e.protocol == "freedom" && !e.broken {
			freedoms[strings.TrimSpace(e.head.Tag)] = freedomOf(raw)
		}
		entries = append(entries, e)
	}

	var candidates []candidate
	var tags []string // the tag each candidate gets
	named := false
	for _, e := range entries {
		if xrayStructural[e.protocol] && !e.broken {
			continue
		}
		localTag := strings.TrimSpace(e.head.Tag)
		main := !named && !p.balancer
		named = true
		name, tag := fmt.Sprintf("узел %d", e.n), localTag
		if plainName(localTag) {
			name = shortName(localTag)
		}
		if remarks := strings.TrimSpace(p.remarks); main && remarks != "" {
			tag = remarks
			if plainName(remarks) {
				name = shortName(remarks)
			}
		}
		if e.broken {
			c.skip(name, errXrayBroken.Error())
			continue
		}

		outbound, dialer, err := xrayNode(e.raw, e.protocol)
		if err != nil {
			c.skip(name, err.Error())
			continue
		}
		if dialer != "" {
			if freedom, isFreedom := freedoms[dialer]; isFreedom {
				// The direct connection sing-box makes anyway, with what the
				// freedom adds to it
				if reason := freedom.dial(outbound, dialer); reason != "" {
					c.skip(name, reason)
					continue
				}
			} else {
				outbound["detour"] = dialer // checked by keepChains
			}
		}
		if tag == "" {
			tag = outbound.Tag() // the link parser's own
		}
		outbound["tag"] = localTag
		candidates = append(candidates, candidate{outbound, name})
		tags = append(tags, tag)
	}

	kept := c.keepChains(candidates, nil)
	final := map[string]string{} // a local tag -> the tag its node got
	for i, cand := range candidates {
		if !kept[i] {
			continue
		}
		local := cand.outbound.Tag()
		cand.outbound["tag"] = tags[i]
		content := xrayContent(cand.outbound)
		tag, copied := taken[content]
		if copied && p.balancer {
			log.Printf("Xray profile: a balancer's copy of a node is left out, the node is imported once")
			kept[i] = false
		} else {
			c.add(cand.outbound)
			tag = cand.outbound.Tag()
			if !copied {
				taken[content] = tag
			}
		}
		if _, seen := final[local]; !seen {
			final[local] = tag
		}
	}
	for i, cand := range candidates {
		if detour, chained := cand.outbound["detour"].(string); kept[i] && chained {
			cand.outbound["detour"] = final[detour]
		}
	}
}

// xrayFreedom is what a freedom outbound does to the connections it makes
// besides connecting directly: a node dialing through it (its dialerProxy)
// is the direct node with that
type xrayFreedom struct {
	// extra is what sing-box cannot do as Xray does it: "broken", the key of
	// the setting, a mask by its type; "" when nothing
	extra string
	// fragment is Xray's fragmentation of its TCP connections (in either of
	// Xray's spellings: settings.fragment, a "fragment" mask of its
	// finalmask)
	fragment *xrayFragment
	// udpMask is the type of the first mask of its finalmask's "udp" layer,
	// which Xray applies to what it sends over UDP only
	udpMask string
}

// freedomOf reads a freedom outbound
func freedomOf(raw json.RawMessage) xrayFreedom {
	broken := xrayFreedom{extra: "broken"}
	var f struct {
		Settings struct {
			Redirect      string          `json:"redirect"`
			Fragment      json.RawMessage `json:"fragment"`
			ProxyProtocol json.RawMessage `json:"proxyProtocol"`
		} `json:"settings"`
		StreamSettings *xrayStream `json:"streamSettings"`
	}
	if json.Unmarshal(raw, &f) != nil {
		return broken
	}
	var free xrayFreedom
	// Xray fragments when the key is there at all
	if present(f.Settings.Fragment) {
		fragment, err := fragmentOf(f.Settings.Fragment, false)
		if err != nil {
			return broken
		}
		free.fragment = free.fragment.with(fragment)
	}
	if strings.TrimSpace(f.Settings.Redirect) != "" {
		free.extra = "redirect"
		return free
	}
	// Xray sends a PROXY protocol header of version 1 or 2, ignores others
	if v, err := rawInt(f.Settings.ProxyProtocol); err == nil && (v == 1 || v == 2) {
		free.extra = "proxyProtocol"
		return free
	}
	st := f.StreamSettings
	if st == nil {
		return free
	}
	if present(st.FinalMask) {
		var layers struct {
			TCP json.RawMessage `json:"tcp"`
			UDP json.RawMessage `json:"udp"`
		}
		var udp []xrayMask
		if json.Unmarshal(st.FinalMask, &layers) != nil || len(layers.UDP) > 0 && json.Unmarshal(layers.UDP, &udp) != nil {
			return broken
		}
		// Newer Xray fragments by a mask of the stream
		fragment, other, err := tcpMasks(layers.TCP)
		if err != nil {
			return broken
		}
		if other != "" {
			free.extra = fmt.Sprintf("finalmask «%s»", token(other))
			return free
		}
		if fragment != nil {
			free.fragment = free.fragment.with(*fragment)
		}
		if len(udp) > 0 {
			free.udpMask = udp[0].kind()
		}
	}
	security := strings.ToLower(strings.TrimSpace(st.Security))
	switch {
	case st.Sockopt != nil && strings.TrimSpace(st.Sockopt.DialerProxy) != "":
		free.extra = "dialerProxy"
	case present(st.Address):
		free.extra = "address"
	case security != "" && security != "none":
		free.extra = "security"
	}
	return free
}

// dial applies the freedom tagged dialer to the node dialing through it: the
// reason the node is refused, "" when it is not. Its fragmentation goes to
// the node's TLS as the node's own would (fragmentTLS). Its UDP masks touch
// only a node that sends UDP itself: a node over QUIC sends nothing else and
// is refused, a Shadowsocks or SOCKS node keeps its TCP (UDP off, as with an
// ss:// link's own UDP mask); the others carry UDP inside their TCP
// connection.
func (f xrayFreedom) dial(outbound Outbound, dialer string) string {
	switch f.extra {
	case "":
	case "broken":
		return fmt.Sprintf("узел подключается через «%s», а его запись повреждена", quotedName(dialer))
	default:
		return fmt.Sprintf("узел подключается через «%s» с параметром %s — такого в sing-box нет", quotedName(dialer), f.extra)
	}
	if f.udpMask != "" {
		switch {
		case overQUIC(outbound):
			return fmt.Sprintf("узел подключается через «%s» с маскировкой finalmask «%s» — такого в sing-box нет",
				quotedName(dialer), token(f.udpMask))
		case outbound["type"] == "shadowsocks" || outbound["type"] == "socks":
			log.Printf("Xray profile: UDP of a node left off, its dialer masks UDP (finalmask %q)", token(f.udpMask))
			outbound["network"] = "tcp"
		}
	}
	fragmentTLS(outbound, f.fragment)
	return ""
}

// xrayNode converts one proxy outbound; dialer is the tag its connection is
// made through (sockopt.dialerProxy), "" for the direct one
func xrayNode(raw json.RawMessage, protocol string) (Outbound, string, error) {
	switch protocol {
	case "vless", "vmess", "trojan", "shadowsocks", "socks", "http":
	case "":
		return nil, "", errors.New("в записи outbound не указан протокол (protocol)")
	case "wireguard":
		return nil, "", errors.New("WireGuard в sing-box — это endpoint, а не outbound; такой узел приложение не импортирует")
	case "hysteria":
		// Xray's Hysteria 2 keeps its speed, congestion control and port
		// hopping in the transport and the finalmask, in a model of its own
		return nil, "", errors.New("Hysteria 2 из профиля Xray приложение не переносит — нужна ссылка hysteria2://")
	default:
		return nil, "", fmt.Errorf("протокол «%s» не поддерживается", token(protocol))
	}

	var o xrayOutbound
	var s xraySettings
	if json.Unmarshal(raw, &o) != nil || (present(o.Settings) && json.Unmarshal(o.Settings, &s) != nil) {
		return nil, "", errXrayBroken
	}
	// Removed from Xray (an error there now); without transportLayer it also
	// dropped the outbound's own stream settings
	if present(o.ProxySettings) {
		return nil, "", errors.New("цепочка proxySettings (в Xray её заменил sockopt.dialerProxy) не поддерживается")
	}
	st := o.StreamSettings
	if st == nil {
		st = &xrayStream{}
	}
	if present(st.Address) {
		return nil, "", errors.New("подключение к другому адресу (streamSettings.address) не поддерживается sing-box")
	}
	dialer := ""
	if st.Sockopt != nil {
		dialer = strings.TrimSpace(st.Sockopt.DialerProxy)
		// Xray looks the server's address and port up in DNS SRV or TXT
		// records instead
		if strategy := strings.ToLower(strings.TrimSpace(st.Sockopt.AddressPortStrategy)); strategy != "" && strategy != "none" {
			return nil, "", errors.New("поиск адреса и порта сервера в DNS (sockopt.addressPortStrategy) не поддерживается sing-box")
		}
	}

	list := s.Servers
	if protocol == "vless" || protocol == "vmess" {
		list = s.Vnext
	}
	server := s.server(list)
	address, err := xrayAddress(server.Address)
	if err != nil {
		return nil, "", err
	}
	port, err := rawInt(server.Port)
	if err != nil || port < 1 || port > 65535 {
		return nil, "", errors.New("неверный порт")
	}
	hostPort := net.JoinHostPort(address, strconv.Itoa(port))

	q, headers, err := streamQuery(st, address)
	if err != nil {
		return nil, "", err
	}
	var link string
	switch protocol {
	case "vless", "vmess":
		user := s.user(server)
		if user.ID == "" {
			return nil, "", errors.New("не указан uuid")
		}
		if present(user.Reverse) || present(s.Reverse) {
			return nil, "", errors.New("обратный прокси VLESS (reverse) не поддерживается sing-box")
		}
		if protocol == "vless" {
			setIf(q, "encryption", user.Encryption)
			setIf(q, "flow", user.Flow)
		} else {
			q.Set("encryption", xrayVMessSecurity(user.Security))
		}
		link = protocol + "://" + url.User(user.ID).String() + "@" + hostPort
	case "trojan":
		if server.Password == "" {
			return nil, "", errors.New("не указан пароль")
		}
		// Trojan's flows were the old XTLS (an error in Xray now): such a
		// server speaks nothing sing-box does
		if flow := strings.TrimSpace(server.Flow); flow != "" {
			return nil, "", fmt.Errorf("flow «%s» для Trojan не поддерживается sing-box", token(flow))
		}
		link = "trojan://" + url.User(server.Password).String() + "@" + hostPort
	case "shadowsocks":
		if server.Password == "" {
			return nil, "", errors.New("не указан пароль")
		}
		userinfo := xraySSMethod(server.Method) + ":" + server.Password
		link = "ss://" + base64.RawURLEncoding.EncodeToString([]byte(userinfo)) + "@" + hostPort
	case "socks", "http":
		outbound, err := xrayPlainProxy(protocol, q, s, server, address, port)
		return outbound, dialer, err
	}

	outbound, err := parseLink(link + "?" + q.Encode())
	if err != nil {
		return nil, "", err
	}
	addHeaders(outbound, headers)
	return outbound, dialer, nil
}

// xrayAddress is a server address as Xray reads it, refused when a URL host
// cannot hold it: a ':' only in an IPv6 address — which also refuses Xray's
// "env:NAME", the address taken from the environment
func xrayAddress(raw *string) (string, error) {
	if raw == nil || strings.TrimSpace(*raw) == "" {
		return "", errors.New("не указан адрес сервера")
	}
	address := strings.TrimSpace(*raw)
	if strings.HasPrefix(address, "[") && strings.HasSuffix(address, "]") {
		address = address[1 : len(address)-1]
	}
	if !plainName(address) || strings.ContainsAny(address, "/?#@[]% \\") ||
		strings.Contains(address, ":") && net.ParseIP(address) == nil {
		return "", errors.New("неверный адрес сервера")
	}
	return address, nil
}

// xrayVMessSecurity is the VMess cipher Xray runs: it knows aes-128-gcm,
// chacha20-poly1305 and auto, and takes anything else for auto. An alterId
// it does not read at all (VMess AEAD only): the link's alter_id is 0.
func xrayVMessSecurity(raw string) string {
	switch security := strings.ToLower(raw); security {
	case "aes-128-gcm", "chacha20-poly1305":
		return security
	}
	return "auto"
}

// xraySSMethod spells Xray's aliases of the Shadowsocks ciphers the way
// sing-box does; ssMethod checks the result
func xraySSMethod(raw string) string {
	method := strings.ToLower(strings.TrimSpace(raw))
	switch method {
	case "aead_aes_128_gcm":
		return "aes-128-gcm"
	case "aead_aes_256_gcm":
		return "aes-256-gcm"
	case "chacha20-poly1305", "aead_chacha20_poly1305":
		return "chacha20-ietf-poly1305"
	case "xchacha20-poly1305", "aead_xchacha20_poly1305":
		return "xchacha20-ietf-poly1305"
	}
	return method
}

// streamQuery is the share-link query that says what the stream settings
// say: type and the transport's parameters, security and the TLS or REALITY
// ones, fm. What the link parsers do not read (spx, pqv, authority, mode)
// goes along all the same, as a link carries it; headers are the
// transport's headers besides Host, which a link has no place for.
func streamQuery(st *xrayStream, address string) (url.Values, map[string]string, error) {
	q := url.Values{}
	network := "tcp" // Xray's default; "method" is its newer name for "network"
	if st.Network != nil {
		network = *st.Network
	}
	if st.Method != nil {
		network = *st.Method
	}
	network = strings.ToLower(strings.TrimSpace(network))

	var tls *xrayTLS
	security := strings.ToLower(strings.TrimSpace(st.Security))
	switch security {
	case "", "none":
		q.Set("security", "none")
	case "tls", "xtls":
		tls = st.TLSSettings
		if security == "xtls" && st.XTLSSettings != nil {
			tls = st.XTLSSettings
		}
		if tls == nil {
			tls = &xrayTLS{}
		}
		if err := tlsQuery(q, security, tls, address); err != nil {
			return nil, nil, err
		}
	case "reality":
		r := st.RealitySettings
		if r == nil {
			r = &xrayReality{}
		}
		q.Set("security", "reality")
		// Like TLS: the address when no server name is given
		q.Set("sni", firstNonEmpty(r.ServerName, address))
		setIf(q, "fp", r.Fingerprint)
		// Xray takes "password" over "publicKey"
		setIf(q, "pbk", firstNonEmpty(r.Password, r.PublicKey))
		setIf(q, "sid", r.ShortID)
		setIf(q, "spx", r.SpiderX)
		setIf(q, "pqv", r.Mldsa65Verify)
	default:
		q.Set("security", security) // refused by the link parsers, named
	}

	var headers map[string]string
	switch network {
	case "", "tcp", "raw":
		q.Set("type", "tcp")
		raw := st.RawSettings // Xray takes rawSettings over tcpSettings
		if raw == nil {
			raw = st.TCPSettings
		}
		if raw != nil && present(raw.Header) {
			if err := tcpHeaderQuery(q, raw.Header); err != nil {
				return nil, nil, err
			}
		}
	case "ws", "websocket", "httpupgrade":
		ws := st.WSSettings
		q.Set("type", "ws")
		if network == "httpupgrade" {
			ws = st.HTTPUpgradeSettings
			q.Set("type", "httpupgrade")
		}
		if ws == nil {
			ws = &xrayWS{}
		}
		host := strings.TrimSpace(ws.Host)
		for key, value := range ws.Headers {
			if strings.EqualFold(key, "host") {
				if host == "" {
					host = strings.TrimSpace(value)
				}
				continue
			}
			if headers == nil {
				headers = map[string]string{}
			}
			headers[key] = value
		}
		// Xray's Host: host, else the TLS server name, else the address; a
		// sing-box WebSocket sends the address unless told otherwise
		if host == "" && tls != nil && network != "httpupgrade" {
			host = strings.TrimSpace(tls.ServerName)
		}
		setIf(q, "host", host)
		setIf(q, "path", ws.Path)
	case "grpc":
		q.Set("type", "grpc")
		if g := st.GRPCSettings; g != nil {
			setIf(q, "serviceName", g.ServiceName)
			setIf(q, "authority", g.Authority)
			if g.MultiMode {
				q.Set("mode", "multi")
			}
		}
	case "h2", "http":
		// Removed from Xray; sing-box's http transport is v2ray's HTTP/2
		q.Set("type", "http")
		if h := st.HTTPSettings; h != nil {
			setIf(q, "host", joined(h.Host))
			setIf(q, "path", h.Path)
		}
	case "quic":
		q.Set("type", "quic")
		if quic := st.QUICSettings; quic != nil {
			setIf(q, "quicSecurity", quic.Security)
			setIf(q, "key", quic.Key)
			setIf(q, "headerType", quic.Header.Type)
		}
	default:
		// XHTTP, mKCP, Hysteria, MASQUE and the rest: refused by the link
		// parsers, by name
		q.Set("type", network)
	}

	if present(st.FinalMask) {
		q.Set("fm", string(bytes.TrimSpace(st.FinalMask)))
	}
	return q, headers, nil
}

// tlsQuery sets the TLS parameters of a link. The server name is the
// address when none is given, as Xray has it (a link would take the ws
// host). The certificate checks become the link's pcs and vcn, so that
// certificateCheck treats them as it treats a link's.
func tlsQuery(q url.Values, security string, tls *xrayTLS, address string) error {
	var certificates []json.RawMessage
	if present(tls.Certificates) && (json.Unmarshal(tls.Certificates, &certificates) != nil || len(certificates) > 0) {
		// A CA of the provider's (or a client certificate, a file): without
		// it the server's certificate fails the check
		return errors.New("собственные сертификаты TLS (certificates) приложение не переносит")
	}
	q.Set("security", security)
	q.Set("sni", firstNonEmpty(tls.ServerName, address))
	setIf(q, "fp", tls.Fingerprint)
	setIf(q, "alpn", joined(tls.ALPN))
	// Removed from Xray (an error there now) for the certificate checks
	// below; a provider writes it for the clients that still honour it, and
	// a link's allowInsecure is honoured too
	if rawFlag(tls.AllowInsecure) {
		q.Set("allowInsecure", "1")
	}
	setIf(q, "pcs", joined(tls.PinnedPeerCertSha256, tls.PinnedChain, tls.PinnedPublicKey))
	setIf(q, "vcn", joined(tls.VerifyPeerCertByName, tls.VerifyInNames, xrayStringList{tls.ServerNameToVerify}))
	setIf(q, "ech", tls.ECHConfigList)
	return nil
}

// tcpHeaderQuery sets the link's headerType (and for "http" its path and
// host) from a raw/tcp header. Xray picks the header kind by the exact key
// "type".
func tcpHeaderQuery(q url.Values, header json.RawMessage) error {
	var obj map[string]json.RawMessage
	var kind string
	if json.Unmarshal(header, &obj) != nil || (obj["type"] != nil && json.Unmarshal(obj["type"], &kind) != nil) {
		return errXrayBroken
	}
	kind = strings.ToLower(strings.TrimSpace(kind))
	setIf(q, "headerType", kind)
	if kind != "http" {
		return nil
	}
	var http struct {
		Request struct {
			Path    xrayStringList            `json:"path"`
			Headers map[string]xrayStringList `json:"headers"`
		} `json:"request"`
	}
	if json.Unmarshal(header, &http) != nil {
		return errXrayBroken
	}
	setIf(q, "path", joined(http.Request.Path))
	for key, values := range http.Request.Headers {
		if strings.EqualFold(key, "host") {
			setIf(q, "host", joined(values))
		}
	}
	return nil
}

// addHeaders adds the transport headers a link cannot carry to the
// WebSocket or HTTPUpgrade transport the link parser built
func addHeaders(outbound Outbound, headers map[string]string) {
	transport, _ := outbound["transport"].(map[string]any)
	if transport == nil || len(headers) == 0 {
		return
	}
	switch transport["type"] {
	case "ws", "httpupgrade":
		all, _ := transport["headers"].(map[string]any)
		if all == nil {
			all = map[string]any{}
		}
		for key, value := range headers {
			all[key] = value
		}
		transport["headers"] = all
	}
}

// xrayPlainProxy builds a SOCKS or HTTP proxy outbound. SOCKS goes through
// the socks5:// link; an HTTP proxy has no link and is built here, its TLS
// by the link's builder. sing-box runs neither over a transport, SOCKS not
// over TLS either.
func xrayPlainProxy(protocol string, q url.Values, s xraySettings, server xrayServer, address string, port int) (Outbound, error) {
	kind := "SOCKS"
	if protocol == "http" {
		kind = "HTTP-прокси"
	}
	if network := q.Get("type"); network != "tcp" {
		return nil, fmt.Errorf("транспорт «%s» для %s не поддерживается sing-box", token(network), kind)
	}
	if header := q.Get("headerType"); header != "" && header != "none" {
		return nil, fmt.Errorf("маскировка TCP «%s» для %s не поддерживается sing-box", token(header), kind)
	}
	if security := q.Get("security"); security != "none" && (protocol == "socks" || security != "tls") {
		return nil, fmt.Errorf("режим защиты «%s» для %s не поддерживается sing-box", token(security), kind)
	}
	// As on an ss:// link: a TCP mask is refused, a UDP one leaves UDP off
	fragment, err := finalMask(q.Get("fm"), false)
	if err != nil {
		return nil, err
	}
	_, err = finalMask(q.Get("fm"), true)
	udpMasked := err != nil

	user := s.user(server)
	if protocol == "socks" {
		link := "socks5://"
		if user.User != "" || user.Pass != "" {
			// With the password always, empty or not: a lone user name the
			// parser would try as v2rayN's base64
			link += url.UserPassword(user.User, user.Pass).String() + "@"
		}
		outbound, err := parseLink(link + net.JoinHostPort(address, strconv.Itoa(port)))
		if err != nil {
			return nil, err
		}
		if udpMasked {
			outbound["network"] = "tcp"
		}
		fragmentTLS(outbound, fragment) // no TLS here: dropped
		return outbound, nil
	}

	outbound := Outbound{
		"type":        "http",
		"tag":         fmt.Sprintf("http-%s-%d", address, port),
		"server":      address,
		"server_port": port,
	}
	if user.User != "" {
		outbound["username"] = user.User
	}
	if user.Pass != "" {
		outbound["password"] = user.Pass
	}
	if len(s.Headers) > 0 {
		headers := map[string]any{}
		for key, value := range s.Headers {
			headers[key] = value
		}
		outbound["headers"] = headers
	}
	if q.Get("security") == "tls" {
		tls, err := tlsConfig(q, address)
		if err != nil {
			return nil, err
		}
		// sing-box's HTTP proxy speaks HTTP/1.1 only, Xray's also HTTP/2
		// when the server picks it: offered h2 (or a fingerprint's list
		// with it) the server might
		tls["alpn"] = []string{"http/1.1"}
		outbound["tls"] = tls
	}
	fragmentTLS(outbound, fragment)
	if err := linkECH(outbound, q.Get("ech")); err != nil {
		return nil, err
	}
	return outbound, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}
