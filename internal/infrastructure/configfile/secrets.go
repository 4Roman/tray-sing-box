package configfile

import (
	"fmt"
	"sort"
	"strings"
)

// Secret masking: the settings page shows config sections in the user's
// non-elevated browser, and whatever reaches that page — the page itself,
// its URL with the token, the API behind it — any program of the user can
// read or drive. The credentials in the config (server passwords, UUIDs,
// private keys) must not leave the elevated process that way, so ReadSection
// replaces them with SecretPlaceholder, and WriteSection puts the stored
// value back where a save keeps the placeholder.
//
// That restore is the delicate part: it must not let a program that drives
// the API send a credential it cannot read somewhere else. It could change the
// server of an outbound (or tls.insecure, the transport, the detour...) and
// keep the placeholder, and the elevated sing-box would present the real
// credential to the new server. So a placeholder is restored only in an
// outbound that is unchanged apart from its secrets, matched to the stored one
// by tag, and only while every outbound it dials through (detour, a group's
// members, transitively) is unchanged too — otherwise the user has to type the
// secrets again.

// SecretPlaceholder stands in for a credential in the text ReadSection
// returns; a WriteSection that keeps it keeps the stored value
const SecretPlaceholder = "(скрыто)"

// secretKeys name credentials wherever they appear (folded, see foldKey):
// vless/vmess/tuic uuid; shadowsocks, trojan, hysteria2 (and its obfs),
// tuic, naive, shadowtls, anytls, socks, http, ssh password; the socks,
// http and naive username; the reality short_id; wireguard keys (peers
// included); hysteria auth/auth_str; ssh private key and passphrase; the
// TLS client key; an authorization header of an http outbound or a
// transport; the token of a Hysteria 2 realm (its server_url stays visible
// and compared). The values may be a string or a line array (ssh
// private_key, tls client_key).
//
// Only fields that do not decide where the connection goes: a secret is left
// out of the "unchanged apart from its secrets" comparison, so a masked
// Host header or shadowsocks plugin_opts ("host=" of v2ray-plugin: which
// backend behind a CDN) could be pointed elsewhere with the placeholder
// kept. Such fields — other headers, plugin_opts, a transport path that
// repeats the uuid, a rule set URL with a token — stay visible.
var secretKeys = map[string]bool{
	"password": true, "uuid": true, "private_key": true, "pre_shared_key": true,
	"auth": true, "auth_str": true, "private_key_passphrase": true,
	"client_key": true, "authorization": true, "proxy-authorization": true,
	"username": true, "short_id": true, "token": true,
}

// isSecret reports whether value, found under key, is a credential: a string
// or a string array at a secret key, or a string under "obfs" (hysteria's
// obfuscation password; hysteria2's obfs is an object, whose password the
// first rule catches). Other values at those keys are ordinary data.
func isSecret(key string, value any) bool {
	k := foldKey(key)
	switch v := value.(type) {
	case string:
		return secretKeys[k] || k == "obfs"
	case []any:
		if !secretKeys[k] || len(v) == 0 {
			return false
		}
		for _, line := range v {
			if _, ok := line.(string); !ok {
				return false
			}
		}
		return true
	}
	return false
}

// maskSecrets returns a deep copy of v with every non-empty credential string
// replaced by SecretPlaceholder (a line array keeps its length)
func maskSecrets(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, child := range x {
			if isSecret(k, child) {
				out[k] = maskValue(child)
				continue
			}
			out[k] = maskSecrets(child)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, child := range x {
			out[i] = maskSecrets(child)
		}
		return out
	}
	return v
}

func maskValue(v any) any {
	switch x := v.(type) {
	case string:
		if x == "" {
			return x // nothing to hide
		}
		return SecretPlaceholder
	case []any:
		out := make([]any, len(x))
		for i, line := range x {
			out[i] = maskValue(line)
		}
		return out
	}
	return v
}

// stripSecrets returns a deep copy of v without its credentials: what must
// stay unchanged for a placeholder to be restored
func stripSecrets(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, child := range x {
			if !isSecret(k, child) {
				out[k] = stripSecrets(child)
			}
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, child := range x {
			out[i] = stripSecrets(child)
		}
		return out
	}
	return v
}

// placeholderFields collects the (folded) secret keys in v that hold the
// placeholder. The placeholder anywhere else is ordinary data.
func placeholderFields(v any, found map[string]bool) {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			if !isSecret(k, child) {
				placeholderFields(child, found)
				continue
			}
			switch s := child.(type) {
			case string:
				if s == SecretPlaceholder {
					found[foldKey(k)] = true
				}
			case []any:
				for _, line := range s {
					if line == any(SecretPlaceholder) {
						found[foldKey(k)] = true
					}
				}
			}
		}
	case []any:
		for _, child := range x {
			placeholderFields(child, found)
		}
	}
}

// restoreSecrets replaces every placeholder in submitted with the value stored
// at the same path. The two are equal apart from their secrets (checked by
// the caller), so the trees pair up key by key and index by index. Secret
// keys whose stored value is missing or empty are collected in missing.
func restoreSecrets(submitted, stored any, missing map[string]bool) {
	switch x := submitted.(type) {
	case map[string]any:
		old, _ := stored.(map[string]any)
		for k, child := range x {
			if isSecret(k, child) {
				x[k] = restoreValue(child, old[k], foldKey(k), missing)
				continue
			}
			restoreSecrets(child, old[k], missing)
		}
	case []any:
		old, _ := stored.([]any)
		for i, child := range x {
			var oldChild any
			if i < len(old) {
				oldChild = old[i]
			}
			restoreSecrets(child, oldChild, missing)
		}
	}
}

func restoreValue(v, stored any, key string, missing map[string]bool) any {
	switch x := v.(type) {
	case string:
		if x != SecretPlaceholder {
			return x // typed by the user
		}
		if s, ok := stored.(string); ok && s != "" {
			return s
		}
		missing[key] = true
	case []any:
		old, _ := stored.([]any)
		for i, line := range x {
			if line != any(SecretPlaceholder) {
				continue
			}
			if i < len(old) {
				if s, ok := old[i].(string); ok && s != "" {
					x[i] = s
					continue
				}
			}
			missing[key] = true
		}
	}
	return v
}

// restorePlaceholders gives the placeholders of a submitted section their
// stored values back, or refuses the save. An array section (outbounds) is
// restored item by item, each matched to the stored item with the same tag;
// an object section (route) as a whole.
func restorePlaceholders(name string, submitted, stored any) error {
	list, isArray := submitted.([]any)
	if !isArray {
		found := map[string]bool{}
		placeholderFields(submitted, found)
		if len(found) == 0 {
			return nil
		}
		if canonical(stripSecrets(submitted)) != canonical(stripSecrets(stored)) {
			return fmt.Errorf("раздел «%s»: скрытые поля (%s) сохраняются только без изменения остальных параметров раздела — введите их заново", name, fieldList(found))
		}
		return restoreFrom(fmt.Sprintf("раздел «%s»", name), submitted, stored, found)
	}

	storedList, _ := stored.([]any)
	for _, item := range list {
		found := map[string]bool{}
		placeholderFields(item, found)
		if len(found) == 0 {
			continue // saved as submitted: the user typed the secrets
		}
		o, _ := item.(map[string]any)
		tag, _ := o["tag"].(string)
		if tag == "" {
			return fmt.Errorf("сервер без тега: скрытые поля (%s) сохраняются только у сохранённого сервера с тем же тегом — введите их значения", fieldList(found))
		}

		var candidates []map[string]any
		for _, s := range storedList {
			if so, ok := s.(map[string]any); ok && so["tag"] == tag {
				candidates = append(candidates, so)
			}
		}
		if len(candidates) == 0 {
			return fmt.Errorf("сервер «%s»: сохранённого сервера с таким тегом нет, скрытым полям (%s) неоткуда взять значения — введите их", tag, fieldList(found))
		}
		want := canonical(stripSecrets(o))
		var match map[string]any
		for _, c := range candidates {
			if canonical(stripSecrets(c)) == want {
				match = c
				break
			}
		}
		if match == nil {
			return fmt.Errorf("сервер «%s»: скрытые поля (%s) сохраняются только без изменения остальных параметров сервера — введите их заново", tag, fieldList(found))
		}
		if dep := changedDependency(match, storedList, list); dep != "" {
			return fmt.Errorf("сервер «%s» подключается через «%s», а он изменён: скрытые поля (%s) сохраняются только без таких изменений — введите их заново", tag, dep, fieldList(found))
		}
		if err := restoreFrom(fmt.Sprintf("сервер «%s»", tag), o, match, found); err != nil {
			return err
		}
	}
	return nil
}

func restoreFrom(label string, submitted, stored any, found map[string]bool) error {
	missing := map[string]bool{}
	restoreSecrets(submitted, stored, missing)
	if len(missing) > 0 {
		return fmt.Errorf("%s: у сохранённой версии нет значения для скрытых полей (%s) — введите их", label, fieldList(missing))
	}
	return nil
}

// changedDependency returns the tag of an outbound that o's connections go
// through (see dialsThrough, followed transitively) and that differs between
// the stored and the submitted list apart from secrets, or "". A tag found in
// neither list (an endpoint) is outside the section and cannot have changed.
func changedDependency(o map[string]any, stored, submitted []any) string {
	seen := map[string]bool{}
	queue := dialsThrough(o)
	for len(queue) > 0 {
		tag := queue[0]
		queue = queue[1:]
		if seen[tag] {
			continue
		}
		seen[tag] = true
		before, after := withTag(stored, tag), withTag(submitted, tag)
		if canonical(stripSecrets(before)) != canonical(stripSecrets(after)) {
			return tag
		}
		for _, item := range before {
			if dep, ok := item.(map[string]any); ok {
				queue = append(queue, dialsThrough(dep)...)
			}
		}
	}
	return ""
}

// dialsThrough lists the outbound tags o's connections go through: its
// detour and, for a group, its members
func dialsThrough(o map[string]any) []string {
	var tags []string
	for k, v := range o {
		switch foldKey(k) {
		case "detour":
			if s, ok := v.(string); ok && s != "" {
				tags = append(tags, s)
			}
		case "outbounds":
			members, _ := v.([]any)
			for _, m := range members {
				if s, ok := m.(string); ok && s != "" {
					tags = append(tags, s)
				}
			}
		}
	}
	sort.Strings(tags)
	return tags
}

// withTag returns the items of list tagged tag. The key is matched the way
// sing-box matches it (foldKey): an added {"Tag": ...} is the same outbound
// to sing-box and must count as a change.
func withTag(list []any, tag string) []any {
	var out []any
	for _, item := range list {
		o, ok := item.(map[string]any)
		if !ok {
			continue
		}
		for k, v := range o {
			if foldKey(k) == "tag" && v == any(tag) {
				out = append(out, item)
				break
			}
		}
	}
	return out
}

func fieldList(found map[string]bool) string {
	names := make([]string, 0, len(found))
	for name := range found {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}
