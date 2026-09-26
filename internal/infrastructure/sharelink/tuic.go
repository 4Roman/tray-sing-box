package sharelink

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// uuidPattern: a UUID as sing-box's TUIC wants it (canonical or bare hex)
var uuidPattern = regexp.MustCompile(`^(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{32})$`)

// parseTUIC reads the de-facto TUIC link (dae discussion #182, as NekoBox,
// v2rayN and mihomo write it):
// tuic://uuid:password@host:port?congestion_control=&udp_relay_mode=&alpn=&sni=&allow_insecure=&disable_sni=
func parseTUIC(link string) (Outbound, error) {
	u, err := parseURL(link)
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
	if u.User == nil || u.User.Username() == "" {
		return nil, errors.New("в ссылке нет uuid")
	}
	password, hasPassword := u.User.Password()
	if !hasPassword {
		// A token alone is TUIC v4; sing-box speaks only v5
		return nil, errors.New("TUIC v4 (токен вместо uuid и пароля) не поддерживается sing-box")
	}
	if !uuidPattern.MatchString(u.User.Username()) {
		return nil, errors.New("uuid в ссылке TUIC неверный")
	}
	if password == "" {
		return nil, errors.New("в ссылке нет пароля")
	}

	q := queryValues(u.RawQuery)
	outbound := Outbound{
		"type":        "tuic",
		"tag":         tagOrDefault(u.Fragment, "tuic", host, port),
		"server":      host,
		"server_port": port,
		"uuid":        u.User.Username(),
		"password":    password,
	}

	switch cc := strings.ToLower(firstValue(q, "congestion_control", "congestion-control")); cc {
	case "":
	case "cubic", "bbr":
		outbound["congestion_control"] = cc
	case "new_reno", "new-reno", "newreno":
		outbound["congestion_control"] = "new_reno"
	default:
		return nil, fmt.Errorf("алгоритм управления перегрузкой «%s» не поддерживается sing-box", token(cc))
	}
	// Anything else sing-box would silently treat as native: left out
	switch mode := strings.ToLower(firstValue(q, "udp_relay_mode", "udp-relay-mode")); mode {
	case "native", "quic":
		outbound["udp_relay_mode"] = mode
	}

	// No uTLS: this is QUIC
	tls := map[string]any{"enabled": true}
	if sni := q.Get("sni"); sni != "" {
		tls["server_name"] = sni
	} else {
		tls["server_name"] = host
	}
	if flagSet(q, "disable_sni", "disable-sni") {
		tls["disable_sni"] = true
	}
	if flagSet(q, insecureKeys...) {
		tls["insecure"] = true
	}
	// sing-box's TUIC sets no ALPN of its own (hysteria2 does: h3), and a
	// TUIC server usually requires one — h3 unless the link says otherwise
	if alpn := splitList(q.Get("alpn")); len(alpn) > 0 {
		tls["alpn"] = alpn
	} else {
		tls["alpn"] = []string{"h3"}
	}
	outbound["tls"] = tls
	return outbound, nil
}

// parseAnyTLS reads an AnyTLS link (the official URI, modelled on Hysteria 2):
// anytls://password@host[:port]/?sni=&insecure=1 — the port defaults to 443
func parseAnyTLS(link string) (Outbound, error) {
	u, err := parseURL(link)
	if err != nil {
		return nil, err
	}
	host, err := serverHost(u)
	if err != nil {
		return nil, err
	}
	port, err := portOrDefault(u.Port(), 443)
	if err != nil {
		return nil, err
	}
	if u.User == nil || u.User.Username() == "" {
		return nil, errors.New("в ссылке нет пароля")
	}
	password := u.User.Username()
	if pw, ok := u.User.Password(); ok {
		password = password + ":" + pw
	}

	q := queryValues(u.RawQuery)
	tls := map[string]any{"enabled": true}
	// An IP as sni: sing-box verifies against it and sends no SNI, which is
	// what the URI scheme asks for
	if sni := q.Get("sni"); sni != "" {
		tls["server_name"] = sni
	} else {
		tls["server_name"] = host
	}
	if flagSet(q, insecureKeys...) {
		tls["insecure"] = true
	}
	if alpn := splitList(q.Get("alpn")); len(alpn) > 0 {
		tls["alpn"] = alpn
	}
	// The URI has no fingerprint; v2rayN adds fp= from its common query
	if q.Get("fp") != "" {
		if fp, ok := utlsFingerprint(q.Get("fp"), false); ok {
			tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
		}
	}

	return Outbound{
		"type":        "anytls",
		"tag":         tagOrDefault(u.Fragment, "anytls", host, port),
		"server":      host,
		"server_port": port,
		"password":    password,
		"tls":         tls,
	}, nil
}
