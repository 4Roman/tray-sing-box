package sharelink

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// The Xray/v2ray link family: vless://, vmess:// (the v2rayN base64 JSON and
// the Xray URL form), trojan:// — XTLS/Xray-core discussion #716 plus what
// v2rayN, v2rayNG, NekoBox and mihomo write and read.

// utlsNames are the fingerprints sing-box knows (tls.utls.fingerprint)
var utlsNames = map[string]bool{
	"chrome": true, "firefox": true, "edge": true, "safari": true, "360": true,
	"qq": true, "ios": true, "android": true, "random": true, "randomized": true,
}

// utlsFingerprint maps a link's fp to the sing-box uTLS fingerprint, and
// whether to use uTLS at all. A link without fp means chrome (#716, Xray's
// default); REALITY always needs uTLS ("uTLS is required by reality
// client"). Xray's own names become their sing-box equivalents
// (randomizednoalpn -> randomized, hellochrome_auto -> chrome); "unsafe",
// "none" and "hellogolang" mean Go's own TLS stack, i.e. no uTLS; anything
// else unknown becomes chrome — sing-box refuses an unknown fingerprint, and
// chrome is its default. Never for QUIC-based outbounds (hysteria, hysteria2,
// tuic): sing-box does not do uTLS over QUIC.
func utlsFingerprint(fp string, reality bool) (string, bool) {
	f := strings.ToLower(strings.TrimSpace(fp))
	switch f {
	case "":
		return "chrome", true
	case "none", "unsafe", "hellogolang":
		if reality {
			return "chrome", true
		}
		return "", false
	}
	name := strings.TrimPrefix(f, "hello")
	if strings.HasPrefix(name, "randomized") {
		return "randomized", true
	}
	if base, _, _ := strings.Cut(name, "_"); utlsNames[base] {
		return base, true
	}
	return "chrome", true
}

// shortIDPattern: a REALITY short_id is up to 8 bytes in hex. sing-box 1.14
// panics on a longer one (hex.Decode into an [8]byte) instead of refusing it
var shortIDPattern = regexp.MustCompile(`^(?:[0-9a-fA-F]{2}){1,8}$`)

// realityConfig builds tls.reality from the link's pbk and sid, refusing
// values sing-box would reject (or crash on). The values are never quoted:
// the short_id counts as a credential.
func realityConfig(pbk, sid string) (map[string]any, error) {
	// A '+' of standard base64 left unescaped in the link reads as a space
	pbk = strings.ReplaceAll(strings.TrimSpace(pbk), " ", "+")
	if pbk == "" {
		return nil, errors.New("не указан публичный ключ REALITY (pbk)")
	}
	key, err := decodeBase64(pbk)
	if err != nil || len(key) != 32 {
		return nil, errors.New("неверный публичный ключ REALITY (pbk)")
	}
	// sing-box accepts only unpadded base64url
	reality := map[string]any{"enabled": true, "public_key": base64.RawURLEncoding.EncodeToString(key)}
	if sid = strings.TrimSpace(sid); sid != "" {
		if !shortIDPattern.MatchString(sid) {
			return nil, errors.New("неверный short_id REALITY (sid): нужно чётное число шестнадцатеричных символов, не больше 16")
		}
		reality["short_id"] = sid
	}
	return reality, nil
}

// tlsConfig builds the sing-box tls object from the query of a vless,
// trojan or vmess-URL link; nil when the link asks for no TLS
func tlsConfig(q url.Values, host string) (map[string]any, error) {
	security := strings.ToLower(strings.TrimSpace(q.Get("security")))
	switch security {
	case "", "none":
		return nil, nil
	case "tls", "xtls", "reality":
	default:
		return nil, fmt.Errorf("режим защиты «%s» не поддерживается", token(security))
	}

	tls := map[string]any{"enabled": true}

	serverName := strings.TrimSpace(q.Get("sni"))
	if serverName == "" {
		serverName = firstOf(q.Get("host"))
	}
	if serverName == "" {
		serverName = host
	}
	tls["server_name"] = serverName

	insecure, err := certificateCheck(q, serverName)
	if err != nil {
		return nil, err
	}
	if insecure {
		tls["insecure"] = true
	}
	if alpn := splitList(q.Get("alpn")); len(alpn) > 0 {
		tls["alpn"] = alpn
	}

	reality := security == "reality"
	if fp, ok := utlsFingerprint(q.Get("fp"), reality); ok {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
	}
	if reality {
		r, err := realityConfig(q.Get("pbk"), q.Get("sid"))
		if err != nil {
			return nil, err
		}
		tls["reality"] = r
	}
	return tls, nil
}

// transportConfig builds the sing-box transport object from common query
// params ("type" follows the v2ray share-link convention); nil for a plain
// TCP stream. A transport sing-box cannot speak is refused: imported as
// plain TCP it would pass `sing-box check` and never connect. tlsOn tells
// whether the link has TLS or REALITY.
func transportConfig(q url.Values, tlsOn bool) (map[string]any, error) {
	network := strings.ToLower(strings.TrimSpace(q.Get("type")))
	switch network {
	case "", "tcp", "raw", "original":
		// Xray calls TCP "raw", trojan-go "original"
		switch header := strings.ToLower(strings.TrimSpace(q.Get("headerType"))); header {
		case "", "none":
			return nil, nil
		case "http":
			// v2ray's TCP "http" header is sing-box's http transport over
			// plain HTTP/1.1 — with TLS that transport speaks HTTP/2
			if tlsOn {
				return nil, errors.New("TCP с HTTP-маскировкой поверх TLS или REALITY не поддерживается sing-box")
			}
			transport := map[string]any{"type": "http", "method": "GET"}
			if path := firstOf(q.Get("path")); path != "" {
				transport["path"] = path
			}
			if hosts := splitList(q.Get("host")); len(hosts) > 0 {
				transport["host"] = hosts
			}
			return transport, nil
		default:
			return nil, fmt.Errorf("маскировка TCP «%s» не поддерживается sing-box", token(header))
		}
	case "ws", "websocket":
		path, ed, eh := splitEarlyData(q.Get("path"))
		// NekoBox writes the early data as parameters of the link itself
		if n, err := strconv.ParseUint(q.Get("ed"), 10, 32); err == nil && n > 0 {
			ed = n
		}
		if h := strings.TrimSpace(q.Get("eh")); h != "" {
			eh = h
		}
		transport := map[string]any{"type": "ws"}
		if path != "" {
			transport["path"] = path
		}
		if host := q.Get("host"); host != "" {
			transport["headers"] = map[string]any{"Host": host}
		}
		if ed > 0 {
			// Xray's early data travels in the Sec-WebSocket-Protocol header
			// (sing-box would otherwise append it to the path)
			if eh == "" {
				eh = "Sec-WebSocket-Protocol"
			}
			transport["max_early_data"] = int(ed)
			transport["early_data_header_name"] = eh
		}
		return transport, nil
	case "grpc":
		transport := map[string]any{"type": "grpc"}
		svc, err := grpcServiceName(q.Get("serviceName"))
		if err != nil {
			return nil, err
		}
		if svc != "" {
			transport["service_name"] = svc
		}
		return transport, nil
	case "http", "h2":
		transport := map[string]any{"type": "http"}
		if path := q.Get("path"); path != "" {
			transport["path"] = path
		}
		if hosts := splitList(q.Get("host")); len(hosts) > 0 {
			transport["host"] = hosts
		}
		return transport, nil
	case "httpupgrade":
		// sing-box's httpupgrade has no early data; Xray strips ?ed= from
		// the path on its side, so the path without it is what the server
		// compares
		path, _, _ := splitEarlyData(q.Get("path"))
		transport := map[string]any{"type": "httpupgrade"}
		if path != "" {
			transport["path"] = path
		}
		if host := q.Get("host"); host != "" {
			transport["host"] = host
		}
		return transport, nil
	case "xhttp", "splithttp":
		return nil, errors.New("транспорт XHTTP не поддерживается sing-box")
	case "kcp", "mkcp":
		return nil, errors.New("транспорт mKCP не поддерживается sing-box")
	case "quic":
		// Xray has removed its QUIC transport: a type=quic link today comes
		// from a sing-box server (s-ui writes the transport's type as it
		// is), and sing-box runs that transport. What only v2ray's QUIC had
		// — its own encryption over TLS, a packet header — sing-box has not.
		if !tlsOn {
			return nil, errors.New("транспорт QUIC работает только с TLS, а в ссылке TLS не включён")
		}
		if security := strings.ToLower(strings.TrimSpace(q.Get("quicSecurity"))); security != "" && security != "none" {
			return nil, fmt.Errorf("шифрование QUIC «%s» (из v2ray) не поддерживается sing-box", token(security))
		}
		if header := strings.ToLower(strings.TrimSpace(q.Get("headerType"))); header != "" && header != "none" {
			return nil, fmt.Errorf("маскировка QUIC «%s» не поддерживается sing-box", token(header))
		}
		return map[string]any{"type": "quic"}, nil
	case "domainsocket":
		return nil, errors.New("транспорт DomainSocket не поддерживается sing-box")
	default:
		return nil, fmt.Errorf("транспорт «%s» не поддерживается sing-box", token(network))
	}
}

// grpcServiceName maps a link's gRPC serviceName to sing-box's service_name.
// Xray reads a name starting with '/' as a custom path: "/a/b/Name|Multi" is
// served at "/a/b/Name" (the part up to the last '/' is the service, the
// rest up to '|' the stream name). sing-box always requests
// "/<service_name>/Tun", the name escaped as one path segment, so only
// "/<segment>/Tun" can be carried over — as service_name "<segment>"; any
// other custom path would pass `sing-box check` and never connect.
func grpcServiceName(svc string) (string, error) {
	if !strings.HasPrefix(svc, "/") {
		return svc, nil
	}
	last := strings.LastIndex(svc, "/")
	service := svc[1:max(last, 1)]
	stream, _, _ := strings.Cut(svc[last+1:], "|")
	if service == "" || strings.Contains(service, "/") || stream != "Tun" {
		return "", errors.New("собственный путь gRPC (serviceName с «/» в начале) не поддерживается sing-box")
	}
	return service, nil
}

// splitEarlyData takes Xray's early-data setting out of a ws/httpupgrade
// path ("/ws?ed=2048"): sing-box sends the path as it is, the '?' escaped
// ("GET /ws%3Fed=2048"), and an Xray server compares it with its bare "/ws"
// — 404. The rest of such a query is dropped too: sing-box cannot send a
// query at all, and the server matches the bare path. The path is cut as a
// string, not parsed as a URL: sing-box decodes its escapes once more.
func splitEarlyData(p string) (path string, ed uint64, eh string) {
	base, rawQuery, ok := strings.Cut(p, "?")
	if !ok {
		return p, 0, ""
	}
	values := queryValues(rawQuery)
	if n, err := strconv.ParseUint(values.Get("ed"), 10, 32); err == nil && n > 0 {
		ed = n
	}
	eh = strings.TrimSpace(values.Get("eh")) // v2rayN's header-name convention
	values.Del("ed")
	values.Del("eh")
	if len(values) > 0 {
		// Only the count: the query of a path may carry a token
		log.Printf("Share link: %d query parameter(s) dropped from a transport path (sing-box cannot send them)", len(values))
	}
	return base, ed, eh
}

// vlessFlow maps a link's flow to what sing-box accepts ("" or
// xtls-rprx-vision). Xray's -udp443 variant only lifts Xray's own client-side
// block of UDP/443 and sends plain vision to the server; sing-box never
// blocks it.
func vlessFlow(raw string) (string, error) {
	flow := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), "-udp443")
	switch flow {
	case "", "none":
		return "", nil
	case "xtls-rprx-vision":
		return flow, nil
	}
	return "", fmt.Errorf("flow «%s» не поддерживается sing-box", token(flow))
}

// vlessEncryption refuses Xray's VLESS Encryption: sing-box has no such
// option, and the server rejects a plain VLESS handshake. Only the method's
// name is named — the rest of the value is key material.
func vlessEncryption(raw string) error {
	enc := strings.TrimSpace(raw)
	if enc == "" || strings.EqualFold(enc, "none") {
		return nil
	}
	method := "неизвестный метод"
	if strings.HasPrefix(strings.ToLower(enc), "mlkem768x25519plus") {
		method = "mlkem768x25519plus"
	}
	return fmt.Errorf("VLESS Encryption (%s) не поддерживается sing-box", method)
}

func parseVLESS(link string) (Outbound, error) {
	u, err := parseURL(link)
	if err != nil {
		return nil, err
	}
	if u.User == nil || u.User.Username() == "" {
		return nil, errors.New("в ссылке нет uuid")
	}
	host, err := serverHost(u)
	if err != nil {
		return nil, err
	}
	port, err := parsePort(u.Port())
	if err != nil {
		return nil, err
	}

	q := queryValues(u.RawQuery)
	if err := vlessEncryption(q.Get("encryption")); err != nil {
		return nil, err
	}
	outbound := Outbound{
		"type":        "vless",
		"tag":         tagOrDefault(u.Fragment, "vless", host, port),
		"server":      host,
		"server_port": port,
		"uuid":        u.User.Username(),
	}
	flow, err := vlessFlow(q.Get("flow"))
	if err != nil {
		return nil, err
	}
	if flow != "" {
		outbound["flow"] = flow
	}
	if err := addTLSAndTransport(outbound, q, host); err != nil {
		return nil, err
	}
	return outbound, nil
}

// addTLSAndTransport sets tls and transport of a vless, trojan or vmess-URL
// outbound from the link's query
func addTLSAndTransport(outbound Outbound, q url.Values, host string) error {
	if err := finalMask(q.Get("fm")); err != nil {
		return err
	}
	tls, err := tlsConfig(q, host)
	if err != nil {
		return err
	}
	transport, err := transportConfig(q, tls != nil)
	if err != nil {
		return err
	}
	if err := fitTLSToTransport(tls, transport); err != nil {
		return err
	}
	if tls != nil {
		outbound["tls"] = tls
	}
	if transport != nil {
		outbound["transport"] = transport
	}
	return nil
}

// finalMask checks Xray's finalmask, which 3x-ui and v2rayN put into a link
// as fm= (the stream's "finalmask" JSON: mask lists per layer, "tcp" and
// "udp"). Its masks — header-custom, sudoku, xmc, the UDP headers and
// obfuscations — transform the stream on both ends: a server with one drops
// a client that does not apply it, and sing-box has none of them. Only
// "fragment" is the client's own business (it splits the TLS ClientHello)
// and is dropped. Just the mask's type is named: its settings carry
// passwords.
func finalMask(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var layers map[string]json.RawMessage
	if json.Unmarshal([]byte(raw), &layers) != nil {
		return errors.New("параметр fm (finalmask) в ссылке повреждён")
	}
	for _, layer := range slices.Sorted(maps.Keys(layers)) {
		var masks []struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(layers[layer], &masks) != nil {
			continue // a setting of the layer, not a list of masks
		}
		for _, mask := range masks {
			if kind := strings.ToLower(strings.TrimSpace(mask.Type)); kind != "fragment" {
				return fmt.Errorf("маскировка finalmask «%s» не поддерживается sing-box", token(kind))
			}
		}
	}
	return nil
}

// fitTLSToTransport adjusts the tls object to the transport it carries.
// ws and httpupgrade are HTTP/1.1 upgrades: sing-box offers http/1.1 when
// tls.alpn is empty, but sends a configured list as it is — and with the
// "h2,http/1.1" of 3x-ui's default TLS settings the server picks h2 and
// drops the upgrade request. Xray clients always offered http/1.1 there, so
// such links work in them; the alpn is left out. The QUIC transport runs
// its own TLS: no uTLS (sing-box does none over QUIC), no REALITY.
func fitTLSToTransport(tls, transport map[string]any) error {
	if tls == nil || transport == nil {
		return nil
	}
	switch transport["type"] {
	case "ws", "httpupgrade":
		delete(tls, "alpn")
	case "quic":
		if _, reality := tls["reality"]; reality {
			return errors.New("REALITY поверх транспорта QUIC не поддерживается sing-box")
		}
		delete(tls, "utls")
	}
	return nil
}

// vmessLink is the v2rayN-style base64 JSON payload of a vmess:// link
type vmessLink struct {
	Ps       string          `json:"ps"`
	Add      string          `json:"add"`
	Port     json.RawMessage `json:"port"`
	ID       string          `json:"id"`
	Aid      json.RawMessage `json:"aid"`
	Scy      string          `json:"scy"`
	Net      string          `json:"net"`
	Type     string          `json:"type"` // the header type of tcp; grpc/xhttp mode
	Host     string          `json:"host"`
	Path     string          `json:"path"` // grpc: the service name; kcp: the seed
	TLS      string          `json:"tls"`
	SNI      string          `json:"sni"`
	Alpn     string          `json:"alpn"`
	Fp       string          `json:"fp"`
	Insecure json.RawMessage `json:"insecure"`
	Fm       json.RawMessage `json:"fm"` // Xray's finalmask, as a JSON text or an object
}

// rawInt parses a JSON value that may be a number or a quoted number
func rawInt(raw json.RawMessage) (int, error) {
	s := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	if s == "" || s == "null" {
		return 0, nil
	}
	return strconv.Atoi(s)
}

// rawFlag reports whether a JSON value is 1 or true, quoted or not
func rawFlag(raw json.RawMessage) bool {
	switch strings.ToLower(strings.Trim(strings.TrimSpace(string(raw)), `"`)) {
	case "1", "true":
		return true
	}
	return false
}

// vmessSecurity checks the VMess cipher against the ones sing-box knows
func vmessSecurity(raw string) (string, error) {
	security := strings.ToLower(strings.TrimSpace(raw))
	switch security {
	case "":
		return "auto", nil
	case "auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305", "aes-128-cfb":
		return security, nil
	}
	return "", fmt.Errorf("шифрование VMess «%s» не поддерживается sing-box", token(security))
}

func parseVMess(link string) (Outbound, error) {
	body := strings.TrimPrefix(link, "vmess://")
	if beforeName, _, _ := strings.Cut(body, "#"); strings.Contains(beforeName, "@") {
		// The Xray URL form (vmess://uuid@host:port?...): base64 has no '@'
		return parseVMessURL(link)
	}

	payload, err := decodeBase64(body)
	if err != nil {
		return nil, errors.New("ссылка vmess повреждена (не base64)")
	}
	var v vmessLink
	if err := json.Unmarshal(payload, &v); err != nil {
		return nil, errors.New("ссылка vmess повреждена (неверный JSON)")
	}

	if strings.TrimSpace(v.Add) == "" {
		return nil, errors.New("в ссылке не указан адрес сервера")
	}
	if strings.TrimSpace(v.ID) == "" {
		return nil, errors.New("в ссылке нет uuid")
	}
	port, err := rawInt(v.Port)
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("неверный порт")
	}
	alterID, err := rawInt(v.Aid)
	if err != nil {
		return nil, errors.New("неверный alterId (aid)")
	}
	security, err := vmessSecurity(v.Scy)
	if err != nil {
		return nil, err
	}
	var fm string
	if json.Unmarshal(v.Fm, &fm) != nil {
		fm = string(v.Fm) // an object, not a string holding one
	}
	if err := finalMask(fm); err != nil {
		return nil, err
	}

	tag := strings.TrimSpace(v.Ps)
	if tag == "" {
		tag = fmt.Sprintf("vmess-%s-%d", v.Add, port)
	}

	outbound := Outbound{
		"type":        "vmess",
		"tag":         tag,
		"server":      v.Add,
		"server_port": port,
		"uuid":        v.ID,
		"security":    security,
		"alter_id":    alterID,
	}

	var tls map[string]any
	switch mode := strings.ToLower(strings.TrimSpace(v.TLS)); {
	case mode == "" || mode == "none" || mode == "0" || mode == "false":
	case strings.HasSuffix(mode, "tls"):
		// "tls", and the legacy "xtls" (as mihomo reads it)
		tls = map[string]any{"enabled": true}
		serverName := strings.TrimSpace(v.SNI)
		if serverName == "" {
			serverName = firstOf(v.Host)
		}
		if serverName == "" {
			serverName = v.Add
		}
		tls["server_name"] = serverName
		if rawFlag(v.Insecure) {
			tls["insecure"] = true
		}
		if alpn := splitList(v.Alpn); len(alpn) > 0 {
			tls["alpn"] = alpn
		}
		if fp, ok := utlsFingerprint(v.Fp, false); ok {
			tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
		}
		outbound["tls"] = tls
	default:
		return nil, fmt.Errorf("режим защиты «%s» для VMess не поддерживается", token(v.TLS))
	}

	// The transport through the query-param builder via equivalent values.
	// In the v2rayN JSON "type" is the header type of tcp and quic, "path"
	// the service name of grpc, "host" the encryption of quic
	q := url.Values{}
	q.Set("type", v.Net)
	q.Set("headerType", v.Type)
	q.Set("path", v.Path)
	q.Set("host", v.Host)
	switch strings.ToLower(strings.TrimSpace(v.Net)) {
	case "grpc":
		q.Set("serviceName", v.Path)
	case "quic":
		q.Set("quicSecurity", v.Host)
	}
	transport, err := transportConfig(q, tls != nil)
	if err != nil {
		return nil, err
	}
	if err := fitTLSToTransport(tls, transport); err != nil {
		return nil, err
	}
	if transport != nil {
		outbound["transport"] = transport
	}
	return outbound, nil
}

// parseVMessURL reads the Xray #716 form of a vmess link: like vless, with
// the cipher in "encryption"
func parseVMessURL(link string) (Outbound, error) {
	u, err := parseURL(link)
	if err != nil {
		return nil, err
	}
	if u.User == nil || u.User.Username() == "" {
		return nil, errors.New("в ссылке нет uuid")
	}
	host, err := serverHost(u)
	if err != nil {
		return nil, err
	}
	port, err := parsePort(u.Port())
	if err != nil {
		return nil, err
	}
	q := queryValues(u.RawQuery)
	security, err := vmessSecurity(q.Get("encryption"))
	if err != nil {
		return nil, err
	}
	outbound := Outbound{
		"type":        "vmess",
		"tag":         tagOrDefault(u.Fragment, "vmess", host, port),
		"server":      host,
		"server_port": port,
		"uuid":        u.User.Username(),
		"security":    security,
		"alter_id":    0,
	}
	if err := addTLSAndTransport(outbound, q, host); err != nil {
		return nil, err
	}
	return outbound, nil
}

func parseTrojan(link string) (Outbound, error) {
	u, err := parseURL(link)
	if err != nil {
		return nil, err
	}
	if u.User == nil || u.User.Username() == "" {
		return nil, errors.New("в ссылке нет пароля")
	}
	host, err := serverHost(u)
	if err != nil {
		return nil, err
	}
	port, err := parsePort(u.Port())
	if err != nil {
		return nil, err
	}

	password := u.User.Username()
	if pw, ok := u.User.Password(); ok {
		password = password + ":" + pw
	}

	q := queryValues(u.RawQuery)
	// Trojan means TLS when the link names no security (trojan-gfw and
	// trojan-go links carry none, Shadowrocket neither); security=none is
	// plain trojan, which sing-box runs (3x-ui exports it for a non-TLS
	// inbound). Shadowrocket carries the SNI as peer=.
	if strings.TrimSpace(q.Get("security")) == "" {
		q.Set("security", "tls")
	}
	if q.Get("sni") == "" && q.Get("peer") != "" {
		q.Set("sni", q.Get("peer"))
	}

	outbound := Outbound{
		"type":        "trojan",
		"tag":         tagOrDefault(u.Fragment, "trojan", host, port),
		"server":      host,
		"server_port": port,
		"password":    password,
	}
	if err := addTLSAndTransport(outbound, q, host); err != nil {
		return nil, err
	}
	return outbound, nil
}
