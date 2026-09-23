package configfile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

// The guard: sing-box runs elevated, so its config is as powerful as an
// administrator — some fields make it start programs (the tor outbound:
// executable_path, extra_args) or read and write files anywhere (log.output,
// the cache file, the external UI download, certificate/key paths, local
// rule sets, geoip/geosite databases, state directories). The config is
// written through the web UI, whose token a non-elevated program of the user
// can get hold of (it is handed to the non-elevated browser), and through
// imports and subscriptions. None of those needs any of these fields. So a
// save may not ADD them: whatever the config already contains (written by an
// administrator by hand) stays allowed, compared item by item with the
// config being replaced.

// allowedOutboundTypes are the outbound types the app itself produces or
// that need nothing beyond network access
var allowedOutboundTypes = map[string]bool{
	"direct": true, "block": true, "dns": true, "selector": true, "urltest": true,
	"socks": true, "http": true, "shadowsocks": true, "vmess": true, "vless": true,
	"trojan": true, "naive": true, "hysteria": true, "hysteria2": true, "tuic": true,
	"wireguard": true, "shadowtls": true, "ssh": true, "anytls": true,
}

// riskyKeys name files or programs wherever they appear
var riskyKeys = map[string]bool{
	"executable_path": true, "extra_args": true, "data_directory": true, "torrc": true,
	"state_directory": true, "working_directory": true,
	"certificate_path": true, "key_path": true, "private_key_path": true, "config_path": true,
	"client_certificate_path": true, "client_key_path": true, "certificate_directory_path": true,
	"output":      true, // log.output
	"external_ui": true, "external_ui_download_url": true,
}

// foldKey normalizes an object key the way encoding/json — and sing-box's
// fork of it — matches struct fields: case-insensitively, with the Unicode
// simple folds of k (KELVIN SIGN) and s (LATIN SMALL LETTER LONG S). To
// sing-box "Certificate_Path" is certificate_path, and so it must be here.
func foldKey(k string) string {
	return strings.ToLower(strings.Map(func(r rune) rune {
		switch r {
		case '\u212A':
			return 'k'
		case '\u017F':
			return 's'
		}
		return r
	}, k))
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
		if section != "outbounds" && section != "endpoints" {
			continue
		}
		list, _ := value.([]any)
		for _, o := range list {
			m, _ := o.(map[string]any)
			if m == nil || section != "outbounds" {
				continue
			}
			var types []string
			for k, v := range m {
				if foldKey(k) == "type" {
					s, _ := v.(string)
					types = append(types, strings.ToLower(s))
				}
			}
			if len(types) != 1 || !allowedOutboundTypes[types[0]] {
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
			switch {
			case riskyKeys[k]:
				items[fmt.Sprintf("%s.%s=%s", parentKey, k, canonical(child))] = parentKey + "." + k
				continue
			case k == "geoip" || k == "geosite":
				// route.geoip / route.geosite (deprecated databases: a path
				// and a download URL) — as rule conditions they are lists
				if _, isDB := child.(map[string]any); isDB {
					items[fmt.Sprintf("%s.%s=%s", parentKey, k, canonical(child))] = parentKey + "." + k
					continue
				}
			case k == "path":
				// A URL path on an outbound (http) or its transport (ws,
				// httpupgrade); a local rule set may name a file in the data
				// directory
				if parentKey == "transport" || parentKey == "outbounds" || parentKey == "endpoints" ||
					(parentKey == "rule_set" && bareFileName(child)) {
					continue
				}
				items[fmt.Sprintf("%s.path=%s", parentKey, canonical(child))] = parentKey + ".path"
				continue
			case k == "cache_file":
				if m, ok := child.(map[string]any); ok {
					for ck, p := range m {
						if foldKey(ck) == "path" {
							items[fmt.Sprintf("cache_file.path=%s", canonical(p))] = "cache_file.path"
						}
					}
					continue
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
	const limit = 5
	shown := added
	if len(shown) > limit {
		shown = shown[:limit]
	}
	return fmt.Errorf("изменение отклонено: sing-box работает с правами администратора, а эти параметры позволили бы запускать программы или читать и писать файлы от его имени; через приложение их не добавить — только правкой config.json администратором (%s)", strings.Join(shown, "; "))
}
