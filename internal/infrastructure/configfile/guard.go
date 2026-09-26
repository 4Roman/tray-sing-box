package configfile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

// The guard: sing-box runs elevated, so its config is as powerful as an
// administrator — some fields make it start programs (the tor outbound:
// executable_path, extra_args), read and write files anywhere (log.output,
// the cache file, the external UI download, certificate/key paths, local
// rule sets, geoip/geosite databases, state directories, an inbound's
// masquerade file server), change the machine (ntp write_to_system) or open
// it to the network (a listener off the loopback, an overlay network
// endpoint, server inbounds and services). The config is written through
// the web UI, whose session a non-elevated program of the user can get hold
// of (the login link passes through the non-elevated browser), and through
// imports and subscriptions. The section editors reach outbounds and route;
// a first config (CreateConfig) and a history restore bring a whole config.
// So a save may not ADD any of these: whatever the config already contains
// (written by an administrator by hand) stays allowed, compared item by item
// with the config being replaced. For the parts a whole config reaches the
// rules are allow-lists (sections, inbound and endpoint types): a VPN client
// needs little of what sing-box offers, and a list of what is forbidden is
// never complete.

// allowedSections are the top-level sections a client config consists of
// (services — ssm-api, derp, resolved, ccm — are servers or file features)
var allowedSections = map[string]bool{
	"log": true, "dns": true, "ntp": true, "certificate": true, "inbounds": true,
	"outbounds": true, "endpoints": true, "route": true, "experimental": true,
}

// allowedOutboundTypes are the outbound types the app itself produces or
// that need nothing beyond network access
var allowedOutboundTypes = map[string]bool{
	"direct": true, "block": true, "dns": true, "selector": true, "urltest": true,
	"socks": true, "http": true, "shadowsocks": true, "vmess": true, "vless": true,
	"trojan": true, "naive": true, "hysteria": true, "hysteria2": true, "tuic": true,
	"wireguard": true, "shadowtls": true, "ssh": true, "anytls": true,
}

// allowedInboundTypes: how a client takes the traffic in. The server
// inbounds (shadowsocks, vmess, trojan, hysteria2, …) accept connections from
// the network and bring masquerade file servers, ACME and certificate files
var allowedInboundTypes = map[string]bool{
	"tun": true, "mixed": true, "socks": true, "http": true, "direct": true,
}

// allowedEndpointTypes: wireguard (since sing-box 1.13 the only way to run
// it). tailscale joins the machine to someone's tailnet with its identity
var allowedEndpointTypes = map[string]bool{"wireguard": true}

// typedSections are the lists whose entries are checked by type
var typedSections = map[string]map[string]bool{
	"outbounds": allowedOutboundTypes,
	"inbounds":  allowedInboundTypes,
	"endpoints": allowedEndpointTypes,
}

// riskyKeys name files, programs or system changes wherever they appear;
// every *_path and *_directory key is risky as well (riskyKey)
var riskyKeys = map[string]bool{
	"executable_path": true, "extra_args": true, "torrc": true,
	"output":      true, // log.output
	"external_ui": true, "external_ui_download_url": true,
	"masquerade": true, // an inbound serving files or proxying for unauthenticated clients
}

// riskyKey: a key naming a file, a directory or a program. process_path is a
// route/DNS rule condition (the path of a running program), not a file access
func riskyKey(k string) bool {
	if riskyKeys[k] {
		return true
	}
	if k == "process_path" {
		return false
	}
	return strings.HasSuffix(k, "_path") || strings.HasSuffix(k, "_directory")
}

// foldKey normalizes an object key the way encoding/json — and sing-box's
// fork of it — matches struct fields: case-insensitively, with the Unicode
// simple folds of k (KELVIN SIGN) and s (LATIN SMALL LETTER LONG S). To
// sing-box "Certificate_Path" is certificate_path, and so it must be here.
func foldKey(k string) string {
	return strings.ToLower(strings.Map(func(r rune) rune {
		switch r {
		case 'K':
			return 'k'
		case 'ſ':
			return 's'
		}
		return r
	}, k))
}

// field returns the value of an object key as sing-box would match it
func field(m map[string]any, name string) (any, bool) {
	for k, v := range m {
		if foldKey(k) == name {
			return v, true
		}
	}
	return nil, false
}

// tagOf names the list entry an item belongs to, for the refusal message
func tagOf(m map[string]any) string {
	if tag, ok := field(m, "tag"); ok {
		if s, ok := tag.(string); ok && s != "" {
			return fmt.Sprintf(" (tag %q)", s)
		}
	}
	return ""
}

// riskyItems lists the risky constructs of a config as canonical strings
// (folded key + value, no position: an item that only moved is still the
// same), each mapped to how a refusal names it — without the value: it may
// carry a credential, and the refusal reaches the settings page (a history
// restore can bring back an item with a secret the page never showed)
func riskyItems(cfg map[string]any) map[string]string {
	items := map[string]string{}
	for key, value := range cfg {
		section := foldKey(key)
		if !allowedSections[section] {
			items[fmt.Sprintf("section %s %s", section, canonical(value))] = "раздел " + section
			continue
		}
		allowed := typedSections[section]
		if allowed == nil {
			continue
		}
		list, _ := value.([]any)
		for _, o := range list {
			m, _ := o.(map[string]any)
			if m == nil {
				continue
			}
			var types []string
			for k, v := range m {
				if foldKey(k) == "type" {
					s, _ := v.(string)
					types = append(types, strings.ToLower(s))
				}
			}
			if len(types) != 1 || !allowed[types[0]] {
				tag, _ := m["tag"].(string)
				items[fmt.Sprintf("%s: type %q %s", section, strings.Join(types, ","), canonical(m))] =
					fmt.Sprintf("%s: type %q, tag %q", section, strings.Join(types, ","), tag)
			}
		}
	}
	walkRisky(cfg, "", items)
	return items
}

func walkRisky(v any, parentKey string, items map[string]string) {
	switch x := v.(type) {
	case map[string]any:
		for key, child := range x {
			k := foldKey(key)
			risky := func() {
				items[fmt.Sprintf("%s.%s=%s", parentKey, k, canonical(child))] = parentKey + "." + k + tagOf(x)
			}
			switch {
			case riskyKey(k):
				risky()
				continue
			case k == "write_to_system":
				// ntp: sets the machine's clock
				if child != false {
					risky()
				}
				continue
			case k == "geoip" || k == "geosite":
				// route.geoip / route.geosite (deprecated databases: a path
				// and a download URL) — as rule conditions they are lists
				if _, isDB := child.(map[string]any); isDB {
					risky()
					continue
				}
			case k == "path":
				// A URL path on an outbound (http), its transport (ws,
				// httpupgrade) or a DNS-over-HTTPS/HTTP3 server; a local rule
				// set or the cache file may name a file in the data directory
				// (sing-box's working directory). A hosts server's path is a
				// list of files
				if parentKey == "transport" || parentKey == "outbounds" || parentKey == "endpoints" ||
					(parentKey == "servers" && urlServer(x)) ||
					((parentKey == "rule_set" || parentKey == "cache_file") && bareFileName(child)) {
					continue
				}
				risky()
				continue
			case k == "plugin_opts":
				// shadowsocks: a SIP003 string sing-box parses itself; the
				// v2ray-plugin's "cert" is a certificate file the elevated
				// sing-box reads (and quotes back when it is no certificate)
				if s, ok := child.(string); ok {
					for _, o := range pluginFileOptions(s) {
						items[fmt.Sprintf("%s.plugin_opts.%s=%s", parentKey, o.key, canonical(o.value))] =
							parentKey + ".plugin_opts: " + o.key + tagOf(x)
					}
				}
				continue
			case k == "listen_port" && parentKey == "endpoints":
				// A wireguard endpoint listening for peers on every interface
				risky()
				continue
			case k == "listen" || k == "external_controller":
				// A listener off the loopback opens the elevated sing-box to
				// the network: an inbound (a proxy anyone on the LAN may use),
				// the clash/v2ray API (control over it and the destinations of
				// all traffic; an empty address disables it). The debug
				// listener (pprof: the process's memory profile, goroutine
				// stacks) is refused on any address — the loopback includes
				// every local program.
				switch parentKey {
				case "debug":
					risky()
					continue
				case "inbounds":
					if !loopbackListen(child, false) {
						risky()
						continue
					}
				case "clash_api", "v2ray_api":
					if s, ok := child.(string); !(ok && strings.TrimSpace(s) == "") && !loopbackListen(child, true) {
						risky()
						continue
					}
				}
			}
			walkRisky(child, k, items)
		}
	case []any:
		for _, child := range x {
			walkRisky(child, parentKey, items)
		}
	}
}

// urlServer: a DNS server whose path is a URL path (https, h3), not a file
// (hosts)
func urlServer(m map[string]any) bool {
	t, _ := field(m, "type")
	s, _ := t.(string)
	switch strings.ToLower(s) {
	case "https", "h3":
		return true
	}
	return false
}

// loopbackListen: a listen address (or "host:port" for the APIs) that only
// this machine can reach. An empty host means every interface.
func loopbackListen(v any, hostPort bool) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	host := strings.TrimSpace(s)
	if hostPort {
		h, _, err := net.SplitHostPort(host)
		if err != nil {
			return false
		}
		host = h
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// pluginOption is one option of a shadowsocks plugin_opts string
type pluginOption struct {
	key, value string
}

// pluginFileOptions returns the options of a plugin_opts string that name a
// file: "cert" (v2ray-plugin), compared loosely — sing-box itself matches the
// key exactly, a wider net costs nothing
func pluginFileOptions(s string) []pluginOption {
	var files []pluginOption
	for _, o := range parsePluginOptions(s) {
		if strings.EqualFold(strings.TrimSpace(o.key), "cert") {
			files = append(files, o)
		}
	}
	return files
}

// parsePluginOptions splits a plugin_opts string exactly as sing-box does
// (transport/sip003 ParsePluginOptions: "k=v;flag", a backslash escapes the
// next byte, a key without "=" is "1"), so that no spelling reaches sing-box
// as another key than the guard saw. A string sing-box cannot parse makes it
// refuse the outbound before any plugin runs: nil.
func parsePluginOptions(s string) []pluginOption {
	// indexUnescaped: the index of the first unescaped terminator (or the
	// end) and the unescaped text before it; ok is false for a trailing "\"
	indexUnescaped := func(s string, term string) (int, string, bool) {
		var unesc []byte
		i := 0
		for ; i < len(s); i++ {
			b := s[i]
			if strings.IndexByte(term, b) >= 0 {
				break
			}
			if b == '\\' {
				i++
				if i >= len(s) {
					return 0, "", false
				}
				b = s[i]
			}
			unesc = append(unesc, b)
		}
		return i, string(unesc), true
	}
	var opts []pluginOption
	for i := 0; i < len(s); {
		offset, key, ok := indexUnescaped(s[i:], "=;")
		if !ok || key == "" {
			return nil
		}
		i += offset
		if i >= len(s) || s[i] != '=' {
			opts = append(opts, pluginOption{key, "1"})
			i++
			continue
		}
		i++
		offset, value, ok := indexUnescaped(s[i:], ";")
		if !ok {
			return nil
		}
		i += offset
		opts = append(opts, pluginOption{key, value})
		i++
	}
	return opts
}

// bareFileName: a plain file name (resolved against sing-box's working
// directory, the data directory), not a path
func bareFileName(v any) bool {
	s, ok := v.(string)
	if !ok || s == "" || s == "." || s == ".." {
		return false
	}
	return !strings.ContainsAny(s, `/\:`) && filepath.Base(s) == s
}

func canonical(v any) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return fmt.Sprint(v)
	}
	return strings.TrimSpace(b.String())
}

// riskyError is a refusal of the guard: the items (named without values)
type riskyError struct {
	items []string
}

// listed names the first items and how many more there are
func (e *riskyError) listed() string {
	const limit = 6
	if len(e.items) <= limit {
		return strings.Join(e.items, "; ")
	}
	return fmt.Sprintf("%s; и ещё %d", strings.Join(e.items[:limit], "; "), len(e.items)-limit)
}

func (e *riskyError) Error() string {
	return fmt.Sprintf("изменение отклонено: sing-box работает с правами администратора, а эти параметры позволили бы запускать программы, читать и писать файлы от его имени, менять систему или открыть его в сеть; через приложение их не добавить — только правкой config.json администратором (%s)", e.listed())
}

// checkNoNewRisky refuses a config that contains risky items the previous
// one did not
func checkNoNewRisky(previous []byte, updated map[string]any) error {
	var old map[string]any
	decoder := json.NewDecoder(bytes.NewReader(previous))
	decoder.UseNumber()
	if err := decoder.Decode(&old); err != nil {
		old = nil // an unreadable previous config allows nothing risky
	}
	had := riskyItems(old)
	var added []string
	for item, shown := range riskyItems(updated) {
		if _, ok := had[item]; !ok && !slices.Contains(added, shown) {
			added = append(added, shown)
		}
	}
	if len(added) == 0 {
		return nil
	}
	sort.Strings(added)
	return &riskyError{items: added}
}
