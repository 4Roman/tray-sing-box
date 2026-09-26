package sharelink

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ssMethods are the ciphers sing-box's shadowsocks outbound accepts
var ssMethods = map[string]bool{
	"none": true, "aes-128-gcm": true, "aes-192-gcm": true, "aes-256-gcm": true,
	"chacha20-ietf-poly1305": true, "xchacha20-ietf-poly1305": true,
	"2022-blake3-aes-128-gcm": true, "2022-blake3-aes-256-gcm": true, "2022-blake3-chacha20-poly1305": true,
	"aes-128-ctr": true, "aes-192-ctr": true, "aes-256-ctr": true,
	"aes-128-cfb": true, "aes-192-cfb": true, "aes-256-cfb": true,
	"rc4-md5": true, "chacha20-ietf": true, "xchacha20": true,
}

// ssMethod normalizes and checks a shadowsocks cipher. Not named in the
// refusal: in a malformed link the "method" may well be the password.
func ssMethod(raw string) (string, error) {
	method := strings.ToLower(strings.TrimSpace(raw))
	if method == "chacha20-poly1305" {
		// shadowsocks-rust's alias
		method = "chacha20-ietf-poly1305"
	}
	if !ssMethods[method] {
		return "", errors.New("метод шифрования Shadowsocks не поддерживается sing-box")
	}
	return method, nil
}

func parseShadowsocks(link string) (Outbound, error) {
	raw := strings.TrimPrefix(link, "ss://")

	// Legacy format: the whole authority is base64(method:password@host:port)
	if beforeName, _, _ := strings.Cut(raw, "#"); !strings.Contains(beforeName, "@") {
		body := raw
		var fragment, query string
		if idx := strings.Index(body, "#"); idx >= 0 {
			fragment = body[idx+1:]
			body = body[:idx]
		}
		if idx := strings.Index(body, "?"); idx >= 0 {
			query = body[idx:]
			body = body[:idx]
		}
		decoded, err := decodeBase64(strings.TrimSuffix(body, "/"))
		if err != nil {
			return nil, errors.New("ссылка повреждена (не base64)")
		}
		// Re-encoded into the SIP002 form below: the password may contain
		// '/', '?' or '#' (base64-generated ones do), which would end the
		// authority of a URL
		at := strings.LastIndex(string(decoded), "@")
		if at < 0 {
			return nil, errors.New("в ссылке нет метода и пароля")
		}
		raw = base64.RawURLEncoding.EncodeToString(decoded[:at]) + string(decoded[at:]) + query
		if fragment != "" {
			raw += "#" + fragment
		}
	}

	u, err := parseURL("ss://" + raw)
	if err != nil {
		return nil, err
	}
	if u.User == nil {
		return nil, errors.New("в ссылке нет метода и пароля")
	}
	host, err := serverHost(u)
	if err != nil {
		return nil, err
	}
	port, err := parsePort(u.Port())
	if err != nil {
		return nil, err
	}

	var method, password string
	if pw, ok := u.User.Password(); ok {
		// Plain method:password in userinfo
		method = u.User.Username()
		password = pw
	} else {
		// SIP002: userinfo is base64(method:password)
		decoded, err := decodeBase64(u.User.Username())
		if err != nil {
			return nil, errors.New("метод и пароль в ссылке повреждены (не base64)")
		}
		method, password, ok = strings.Cut(string(decoded), ":")
		if !ok {
			return nil, errors.New("метод и пароль в ссылке повреждены (нужно метод:пароль)")
		}
	}
	if method, err = ssMethod(method); err != nil {
		return nil, err
	}

	outbound := Outbound{
		"type":        "shadowsocks",
		"tag":         tagOrDefault(u.Fragment, "ss", host, port),
		"server":      host,
		"server_port": port,
		"method":      method,
		"password":    password,
	}

	// queryValues, not u.Query(): net/url drops a pair with an unescaped ';',
	// and the plugin would silently vanish
	if plugin := queryValues(u.RawQuery).Get("plugin"); strings.TrimSpace(plugin) != "" {
		parts, err := splitPluginString(plugin)
		if err != nil {
			return nil, err
		}
		name, opts := parts[0].key, parts[1:]
		if parts[0].hasValue {
			return nil, errors.New("параметр plugin в ссылке повреждён")
		}
		plugin, pluginOpts, err := pluginConfig(name, opts)
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

// pluginOption is one "key=value" (or a bare "key") of a SIP003 string
type pluginOption struct {
	key, value string
	hasValue   bool
}

// splitPluginString splits a SIP003 plugin string — "name;k=v;flag", where
// a backslash escapes ';', '=' and '\' — into its parts. Errors never quote
// the string: plugin options may carry the plugin's own credential.
func splitPluginString(s string) ([]pluginOption, error) {
	var parts []pluginOption
	var current pluginOption
	var b strings.Builder
	inValue := false
	flush := func() {
		if inValue {
			current.value = b.String()
		} else {
			current.key = b.String()
		}
		parts = append(parts, current)
		current, inValue = pluginOption{}, false
		b.Reset()
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\':
			if i+1 == len(s) {
				return nil, errors.New("параметр plugin в ссылке повреждён")
			}
			i++
			b.WriteByte(s[i])
		case c == ';':
			flush()
		case c == '=' && !inValue:
			current.key, current.hasValue, inValue = b.String(), true, true
			b.Reset()
		default:
			b.WriteByte(c)
		}
	}
	flush()
	for i, p := range parts {
		p.key = strings.TrimSpace(p.key)
		if p.key == "" && (i == 0 || p.hasValue) {
			return nil, errors.New("параметр plugin в ссылке повреждён")
		}
		parts[i] = p
	}
	// "name;" or "a;;b": empty segments carry nothing
	kept := parts[:1]
	for _, p := range parts[1:] {
		if p.key != "" {
			kept = append(kept, p)
		}
	}
	return kept, nil
}

// escapePluginValue escapes a SIP003 key or value
func escapePluginValue(s string) string {
	return strings.NewReplacer(`\`, `\\`, `;`, `\;`, `=`, `\=`).Replace(s)
}

// pluginConfig maps a SIP003 plugin to sing-box's plugin + plugin_opts.
// sing-box has two plugins built in, obfs-local (simple-obfs is the same
// thing under its old name) and v2ray-plugin; the options are rebuilt from
// an allow-list, not copied: v2ray-plugin's "cert" is a file path the
// elevated sing-box would read (and quote back in its error when the file is
// no certificate). Other plugins are refused by name, their options never
// quoted — they may carry the plugin's own credential.
func pluginConfig(name string, opts []pluginOption) (plugin, pluginOpts string, err error) {
	var out []string
	add := func(key, value string) {
		out = append(out, escapePluginValue(key)+"="+escapePluginValue(value))
	}
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "obfs-local", "simple-obfs":
		plugin = "obfs-local"
		for _, o := range opts {
			switch o.key {
			case "obfs":
				mode := strings.ToLower(strings.TrimSpace(o.value))
				if mode != "http" && mode != "tls" {
					return "", "", errors.New("режим obfs плагина obfs-local не поддерживается sing-box (только http и tls)")
				}
				add("obfs", mode)
			case "obfs-host":
				add("obfs-host", o.value)
			case "obfs-uri":
				// simple-obfs's request path for http mode: sing-box has no
				// such option, and the server does not check it
			default:
				return "", "", errors.New("параметр плагина obfs-local не поддерживается sing-box")
			}
		}
	case "v2ray-plugin":
		plugin = "v2ray-plugin"
		for _, o := range opts {
			switch o.key {
			case "mode":
				switch strings.ToLower(strings.TrimSpace(o.value)) {
				case "", "websocket", "ws":
					add("mode", "websocket")
				case "quic":
					return "", "", errors.New("режим QUIC плагина v2ray-plugin не совместим с sing-box")
				default:
					return "", "", errors.New("режим плагина v2ray-plugin не поддерживается sing-box (только websocket)")
				}
			case "tls":
				// A flag: sing-box turns TLS on when the key is present at all
				switch strings.ToLower(strings.TrimSpace(o.value)) {
				case "", "1", "true":
					out = append(out, "tls")
				}
			case "host", "path", "certRaw":
				add(o.key, o.value)
			case "mux":
				if _, err := strconv.Atoi(strings.TrimSpace(o.value)); err != nil {
					return "", "", errors.New("неверный параметр mux плагина v2ray-plugin")
				}
				add("mux", strings.TrimSpace(o.value))
			case "cert":
				return "", "", errors.New("параметр cert плагина v2ray-plugin (файл на диске) через приложение не добавить")
			case "loglevel":
				// the plugin's own logging: sing-box has none to set
			default:
				return "", "", errors.New("параметр плагина v2ray-plugin не поддерживается sing-box")
			}
		}
	default:
		return "", "", fmt.Errorf("плагин «%s» не поддерживается sing-box (только obfs-local и v2ray-plugin)", token(name))
	}
	return plugin, strings.Join(out, ";"), nil
}
