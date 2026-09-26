package sharelink

import (
	"errors"
	"net/url"
	"strings"
	"unicode/utf8"
)

// parseSOCKS reads a SOCKS proxy link: socks5://user:pass@host:port (NekoBox,
// mihomo), socks://base64(user:pass)@host:port (v2rayN) or the legacy
// socks://base64(user:pass@host:port); socks4:// and socks4a:// set the
// version. The credentials travel unencrypted — SOCKS has no TLS.
func parseSOCKS(link string) (Outbound, error) {
	scheme, rest, _ := strings.Cut(link, "://")
	version := ""
	switch scheme {
	case "socks4":
		version = "4"
	case "socks4a":
		version = "4a"
	}

	// Legacy: the whole authority is base64
	legacy := false
	if beforeName, _, _ := strings.Cut(rest, "#"); !strings.Contains(beforeName, "@") && !strings.Contains(beforeName, ":") {
		legacy = true
		body, fragment, _ := strings.Cut(rest, "#")
		decoded, err := decodeBase64(strings.TrimSuffix(body, "/"))
		if err != nil || !utf8.Valid(decoded) {
			return nil, errors.New("ссылка повреждена")
		}
		// Re-escaped before the URL parse, like a legacy ss link: the
		// generators base64-encode the password as it is, and a '/', '?' or
		// '#' in it would end the authority — its head taken for the
		// server, its rest for the name. The credentials end at the last
		// '@', the user name at the first ':' (v2rayN reads the body without
		// any URL parsing)
		rest = string(decoded)
		if at := strings.LastIndex(rest, "@"); at >= 0 {
			userinfo := url.User(rest[:at])
			if user, pass, ok := strings.Cut(rest[:at], ":"); ok {
				userinfo = url.UserPassword(user, pass)
			}
			rest = userinfo.String() + rest[at:]
		}
		if fragment != "" {
			rest += "#" + fragment
		}
	}

	// The credentials are optional: a password with an unescaped '/', '?'
	// or '#' leaves no userinfo, and one starting with digits reads as the
	// port of the user name taken for the server (any other head fails the
	// parse — the reason is the same)
	u, err := parseURL(scheme + "://" + rest)
	if (err != nil || u.User == nil) && !legacy && authorityInTail(rest) {
		return nil, errUnescapedPassword
	}
	if err != nil {
		return nil, err
	}
	host, err := serverHost(u)
	if err != nil {
		return nil, err
	}
	port, err := parsePort(u.Port())
	if err != nil {
		return nil, err
	}

	outbound := Outbound{
		"type":        "socks",
		"tag":         tagOrDefault(u.Fragment, "socks", host, port),
		"server":      host,
		"server_port": port,
	}
	if version != "" {
		outbound["version"] = version
	}

	if u.User != nil {
		username := u.User.Username()
		password, hasPassword := u.User.Password()
		if !hasPassword {
			// v2rayN: base64(user:pass) as the userinfo
			if decoded, err := decodeBase64(username); err == nil && utf8.Valid(decoded) {
				if user, pass, ok := strings.Cut(string(decoded), ":"); ok {
					username, password = user, pass
				}
			}
		}
		if username != "" {
			outbound["username"] = username
		}
		if password != "" {
			outbound["password"] = password
		}
	}
	return outbound, nil
}
