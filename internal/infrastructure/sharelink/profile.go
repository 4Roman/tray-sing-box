package sharelink

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Subscription bodies that are a whole profile rather than share links: a
// sing-box configuration (what Marzban, Remnawave and the like serve at their
// "sing-box" URLs) or its bare outbounds array, and SIP008 (the shadowsocks
// online config JSON). Clash/mihomo YAML and Xray JSON are recognized and
// refused with a hint: reading them would need a YAML parser and a
// converter of Xray's whole config model.

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
	errXrayProfile = errors.New("провайдер прислал профиль Xray (JSON), приложение его не читает: " +
		"нужна ссылка на подписку в формате v2rayN (список ссылок или base64) или sing-box")
	errClashProfile = errors.New("провайдер прислал профиль Clash/mihomo (YAML), приложение его не читает: " +
		"нужна ссылка на подписку в формате v2rayN (список ссылок или base64) или sing-box")
	errEmptyProfile = errors.New("в профиле нет серверов, которые приложение может импортировать")
)

// clashProxies: the top-level proxy list of a Clash/mihomo YAML profile
var clashProxies = regexp.MustCompile(`(?m)^proxies:`)

// foreignProfile recognizes a profile the app cannot read that carries no
// share links (Clash YAML) and says so; nil otherwise
func foreignProfile(text string) error {
	if clashProxies.MatchString(text) {
		return errClashProfile
	}
	return nil
}

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
			return true, errXrayProfile
		}
		// A whole sing-box config
		c.singBox(list)
		for i, e := range endpoints {
			m, _ := e.(map[string]any)
			tag, _ := m["tag"].(string)
			if strings.TrimSpace(tag) == "" {
				tag = fmt.Sprintf("endpoint %d", i+1)
			}
			c.skip(strings.TrimSpace(tag), "endpoint (WireGuard и подобные) приложение не импортирует — только outbound")
		}
		return true, errEmptyProfileIfNone(c)
	case []any:
		// A bare outbounds array, or (3x-ui's JSON subscription) an array
		// of whole Xray configs
		for _, e := range r {
			if m, isMap := e.(map[string]any); isMap {
				if nested, isList := m["outbounds"].([]any); isList {
					if xrayOutbounds(nested) {
						return true, errXrayProfile
					}
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
		return true, errXrayProfile
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
// A detour survives only when it names another node that is imported.
func (c *collector) singBox(entries []any) {
	type candidate struct {
		outbound Outbound
		name     string
	}
	var candidates []candidate
	direct := map[string]bool{}
	for i, e := range entries {
		m, _ := e.(map[string]any)
		if m == nil {
			continue
		}
		typ, _ := m["type"].(string)
		typ = strings.ToLower(typ)
		tag, _ := m["tag"].(string)
		tag = strings.TrimSpace(tag)
		name := tag
		if name == "" {
			name = fmt.Sprintf("узел %d", i+1)
		}
		if profileStructural[typ] {
			if typ == "direct" && tag != "" {
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

	// Detours: kept inside the profile, dropped when they only say "direct",
	// otherwise the node cannot work as the provider meant it. Repeated, as
	// leaving out one node breaks the chains through it.
	kept := make([]bool, len(candidates))
	for i := range kept {
		kept[i] = true
	}
	for changed := true; changed; {
		changed = false
		tags := map[string]bool{}
		for i, cand := range candidates {
			if kept[i] {
				tags[cand.outbound.Tag()] = true
			}
		}
		for i, cand := range candidates {
			if !kept[i] {
				continue
			}
			detour, hasDetour := cand.outbound["detour"]
			if !hasDetour {
				continue
			}
			target, _ := detour.(string)
			switch {
			case target == "" || direct[target]:
				delete(cand.outbound, "detour")
			case !tags[target]:
				kept[i], changed = false, true
				c.skip(cand.name, fmt.Sprintf("узел работает через «%s», которого нет среди импортируемых", target))
			}
		}
	}
	for i, cand := range candidates {
		if kept[i] {
			c.add(cand.outbound)
		}
	}
}

// sanitizeProfileOutbound checks and adjusts one proxy outbound of a
// sing-box profile in place
func sanitizeProfileOutbound(o Outbound) error {
	if key := fileKey(map[string]any(o)); key != "" {
		return fmt.Errorf("узел ссылается на файл на диске («%s»), через приложение такое не добавить", key)
	}
	// A DNS server of the provider's config, absent from the user's
	delete(o, "domain_resolver")

	switch o["type"] {
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

	tls, _ := o["tls"].(map[string]any)
	if tls == nil {
		return nil
	}
	reality, _ := tls["reality"].(map[string]any)
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
	utls, _ := tls["utls"].(map[string]any)
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
			// Folded as sing-box's JSON decoder matches keys (KELVIN SIGN
			// lowers to k by itself)
			k := strings.ToLower(strings.ReplaceAll(key, "ſ", "s"))
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
		name := strings.TrimSpace(s.Remarks)
		if name == "" {
			name = fmt.Sprintf("узел %d", i+1)
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
