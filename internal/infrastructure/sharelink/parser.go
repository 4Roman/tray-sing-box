// Package sharelink converts proxy share links (vless://, vmess://, trojan://,
// ss://, hysteria2://) into sing-box outbound JSON objects. sing-box core has
// no native share-link import, so the conversion is implemented here.
package sharelink

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Outbound is a sing-box outbound object ready to be embedded into config.json
type Outbound map[string]any

// Parser adapts this package to the domain.OutboundParser interface
type Parser struct{}

// Parse extracts and converts every share link found in text
func (Parser) Parse(text string) ([]map[string]any, error) {
	outbounds, err := ParseAll(text)
	if err != nil {
		return nil, err
	}
	result := make([]map[string]any, len(outbounds))
	for i, o := range outbounds {
		result[i] = o
	}
	return result, nil
}

// Tag returns the outbound tag
func (o Outbound) Tag() string {
	tag, _ := o["tag"].(string)
	return tag
}

// Parse converts a single share link into a sing-box outbound
func Parse(link string) (Outbound, error) {
	link = strings.TrimSpace(link)

	switch {
	case strings.HasPrefix(link, "vless://"):
		return parseVLESS(link)
	case strings.HasPrefix(link, "vmess://"):
		return parseVMess(link)
	case strings.HasPrefix(link, "trojan://"):
		return parseTrojan(link)
	case strings.HasPrefix(link, "ss://"):
		return parseShadowsocks(link)
	case strings.HasPrefix(link, "hysteria2://"), strings.HasPrefix(link, "hy2://"):
		return parseHysteria2(link)
	default:
		return nil, fmt.Errorf("unsupported link format (expected vless://, vmess://, trojan://, ss:// or hysteria2://)")
	}
}

var schemes = []string{"vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://"}

// extractLinks returns every supported share link found in arbitrary text
func extractLinks(text string) []string {
	var links []string
	for _, field := range strings.Fields(text) {
		for _, scheme := range schemes {
			if idx := strings.Index(field, scheme); idx >= 0 {
				links = append(links, field[idx:])
				break
			}
		}
	}
	return links
}

// ParseAny extracts the first supported share link from arbitrary text
// (e.g. clipboard content with surrounding noise) and parses it.
func ParseAny(text string) (Outbound, error) {
	links := extractLinks(text)
	if len(links) == 0 {
		return nil, fmt.Errorf("no supported share link found in text")
	}
	return Parse(links[0])
}

// ParseAll extracts and parses every supported share link in text. If the
// text contains no links directly, it is treated as a base64 subscription
// blob (a base64-encoded list of links, the common subscription format).
// Links that fail to parse are skipped as long as at least one succeeds.
// Duplicate tags get a numeric suffix so each outbound stays addressable.
func ParseAll(text string) ([]Outbound, error) {
	links := extractLinks(text)
	if len(links) == 0 {
		compact := strings.Join(strings.Fields(text), "")
		if decoded, err := decodeBase64(compact); err == nil {
			links = extractLinks(string(decoded))
		}
	}
	if len(links) == 0 {
		return nil, fmt.Errorf("no supported share link found in text")
	}

	var outbounds []Outbound
	var firstErr error
	seen := map[string]int{}
	for _, link := range links {
		outbound, err := Parse(link)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		tag := outbound.Tag()
		seen[tag]++
		if seen[tag] > 1 {
			tag = fmt.Sprintf("%s (%d)", tag, seen[tag])
			outbound["tag"] = tag
			seen[tag]++
		}
		outbounds = append(outbounds, outbound)
	}

	if len(outbounds) == 0 {
		return nil, fmt.Errorf("no link could be parsed: %w", firstErr)
	}
	return outbounds, nil
}

// decodeBase64 decodes standard or URL-safe base64, padded or not
func decodeBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if data, err := enc.DecodeString(s); err == nil {
			return data, nil
		}
	}
	return nil, fmt.Errorf("invalid base64 data")
}

// tagOrDefault returns the URL fragment as tag, or a generated fallback
func tagOrDefault(fragment, proto, host string, port int) string {
	if tag, err := url.QueryUnescape(fragment); err == nil && strings.TrimSpace(tag) != "" {
		return strings.TrimSpace(tag)
	}
	if strings.TrimSpace(fragment) != "" {
		return strings.TrimSpace(fragment)
	}
	return fmt.Sprintf("%s-%s-%d", proto, host, port)
}

func parsePort(s string) (int, error) {
	port, err := strconv.Atoi(s)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("invalid port: %q", s)
	}
	return port, nil
}

// tlsConfig builds the sing-box tls object from common query params
func tlsConfig(q url.Values, host string) map[string]any {
	security := q.Get("security")
	if security == "" || security == "none" {
		return nil
	}

	tls := map[string]any{"enabled": true}

	serverName := q.Get("sni")
	if serverName == "" {
		serverName = q.Get("host")
	}
	if serverName == "" {
		serverName = host
	}
	tls["server_name"] = serverName

	if q.Get("allowInsecure") == "1" || q.Get("insecure") == "1" {
		tls["insecure"] = true
	}

	if alpn := q.Get("alpn"); alpn != "" {
		tls["alpn"] = strings.Split(alpn, ",")
	}

	if fp := q.Get("fp"); fp != "" {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
	}

	if security == "reality" {
		reality := map[string]any{"enabled": true, "public_key": q.Get("pbk")}
		if sid := q.Get("sid"); sid != "" {
			reality["short_id"] = sid
		}
		tls["reality"] = reality
	}

	return tls
}

// transportConfig builds the sing-box transport object from common query params.
// network values follow the v2ray share-link convention ("type" param).
func transportConfig(q url.Values) map[string]any {
	switch q.Get("type") {
	case "", "tcp":
		return nil
	case "ws":
		transport := map[string]any{"type": "ws"}
		if path := q.Get("path"); path != "" {
			transport["path"] = path
		}
		if host := q.Get("host"); host != "" {
			transport["headers"] = map[string]any{"Host": host}
		}
		return transport
	case "grpc":
		transport := map[string]any{"type": "grpc"}
		if svc := q.Get("serviceName"); svc != "" {
			transport["service_name"] = svc
		}
		return transport
	case "http", "h2":
		transport := map[string]any{"type": "http"}
		if path := q.Get("path"); path != "" {
			transport["path"] = path
		}
		if host := q.Get("host"); host != "" {
			transport["host"] = strings.Split(host, ",")
		}
		return transport
	case "httpupgrade":
		transport := map[string]any{"type": "httpupgrade"}
		if path := q.Get("path"); path != "" {
			transport["path"] = path
		}
		if host := q.Get("host"); host != "" {
			transport["host"] = host
		}
		return transport
	default:
		return nil
	}
}

func parseVLESS(link string) (Outbound, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("invalid vless link: %w", err)
	}
	if u.User == nil || u.User.Username() == "" {
		return nil, fmt.Errorf("vless link is missing uuid")
	}
	port, err := parsePort(u.Port())
	if err != nil {
		return nil, fmt.Errorf("vless link: %w", err)
	}

	q := u.Query()
	outbound := Outbound{
		"type":        "vless",
		"tag":         tagOrDefault(u.Fragment, "vless", u.Hostname(), port),
		"server":      u.Hostname(),
		"server_port": port,
		"uuid":        u.User.Username(),
	}
	if flow := q.Get("flow"); flow != "" {
		outbound["flow"] = flow
	}
	if tls := tlsConfig(q, u.Hostname()); tls != nil {
		outbound["tls"] = tls
	}
	if transport := transportConfig(q); transport != nil {
		outbound["transport"] = transport
	}
	return outbound, nil
}

// vmessLink is the v2rayN-style base64 JSON payload of a vmess:// link
type vmessLink struct {
	Ps   string          `json:"ps"`
	Add  string          `json:"add"`
	Port json.RawMessage `json:"port"`
	ID   string          `json:"id"`
	Aid  json.RawMessage `json:"aid"`
	Scy  string          `json:"scy"`
	Net  string          `json:"net"`
	Host string          `json:"host"`
	Path string          `json:"path"`
	TLS  string          `json:"tls"`
	SNI  string          `json:"sni"`
	Alpn string          `json:"alpn"`
	Fp   string          `json:"fp"`
}

// rawInt parses a JSON value that may be a number or a quoted number
func rawInt(raw json.RawMessage) (int, error) {
	s := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	if s == "" || s == "null" {
		return 0, nil
	}
	return strconv.Atoi(s)
}

func parseVMess(link string) (Outbound, error) {
	payload, err := decodeBase64(strings.TrimPrefix(link, "vmess://"))
	if err != nil {
		return nil, fmt.Errorf("invalid vmess link: %w", err)
	}

	var v vmessLink
	if err := json.Unmarshal(payload, &v); err != nil {
		return nil, fmt.Errorf("invalid vmess link payload: %w", err)
	}

	port, err := rawInt(v.Port)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("vmess link: invalid port %q", string(v.Port))
	}
	alterID, err := rawInt(v.Aid)
	if err != nil {
		return nil, fmt.Errorf("vmess link: invalid aid %q", string(v.Aid))
	}

	security := v.Scy
	if security == "" {
		security = "auto"
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

	if v.TLS == "tls" {
		tls := map[string]any{"enabled": true}
		serverName := v.SNI
		if serverName == "" {
			serverName = v.Host
		}
		if serverName == "" {
			serverName = v.Add
		}
		tls["server_name"] = serverName
		if v.Alpn != "" {
			tls["alpn"] = strings.Split(v.Alpn, ",")
		}
		if v.Fp != "" {
			tls["utls"] = map[string]any{"enabled": true, "fingerprint": v.Fp}
		}
		outbound["tls"] = tls
	}

	// Reuse the query-param transport builder via equivalent values
	q := url.Values{}
	q.Set("type", v.Net)
	q.Set("path", v.Path)
	q.Set("host", v.Host)
	if v.Net == "h2" {
		q.Set("type", "http")
	}
	if transport := transportConfig(q); transport != nil {
		outbound["transport"] = transport
	}

	return outbound, nil
}

func parseTrojan(link string) (Outbound, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("invalid trojan link: %w", err)
	}
	if u.User == nil || u.User.Username() == "" {
		return nil, fmt.Errorf("trojan link is missing password")
	}
	port, err := parsePort(u.Port())
	if err != nil {
		return nil, fmt.Errorf("trojan link: %w", err)
	}

	password := u.User.Username()
	if pw, ok := u.User.Password(); ok {
		password = password + ":" + pw
	}

	q := u.Query()
	outbound := Outbound{
		"type":        "trojan",
		"tag":         tagOrDefault(u.Fragment, "trojan", u.Hostname(), port),
		"server":      u.Hostname(),
		"server_port": port,
		"password":    password,
	}

	// Trojan implies TLS; honor explicit params but default to enabled
	if tls := tlsConfig(q, u.Hostname()); tls != nil {
		outbound["tls"] = tls
	} else {
		serverName := q.Get("sni")
		if serverName == "" {
			serverName = u.Hostname()
		}
		outbound["tls"] = map[string]any{"enabled": true, "server_name": serverName}
	}

	if transport := transportConfig(q); transport != nil {
		outbound["transport"] = transport
	}
	return outbound, nil
}

func parseShadowsocks(link string) (Outbound, error) {
	raw := strings.TrimPrefix(link, "ss://")

	// Legacy format: the whole authority is base64(method:password@host:port)
	if !strings.Contains(raw, "@") {
		body := raw
		var fragment string
		if idx := strings.Index(body, "#"); idx >= 0 {
			fragment = body[idx+1:]
			body = body[:idx]
		}
		decoded, err := decodeBase64(body)
		if err != nil {
			return nil, fmt.Errorf("invalid ss link: %w", err)
		}
		raw = string(decoded)
		if fragment != "" {
			raw += "#" + fragment
		}
	}

	u, err := url.Parse("ss://" + raw)
	if err != nil {
		return nil, fmt.Errorf("invalid ss link: %w", err)
	}
	if u.User == nil {
		return nil, fmt.Errorf("ss link is missing credentials")
	}
	port, err := parsePort(u.Port())
	if err != nil {
		return nil, fmt.Errorf("ss link: %w", err)
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
			return nil, fmt.Errorf("invalid ss link userinfo: %w", err)
		}
		method, password, ok = strings.Cut(string(decoded), ":")
		if !ok {
			return nil, fmt.Errorf("invalid ss link userinfo: expected method:password")
		}
	}

	if plugin := u.Query().Get("plugin"); plugin != "" {
		return nil, fmt.Errorf("ss link uses plugin %q which is not supported", plugin)
	}

	return Outbound{
		"type":        "shadowsocks",
		"tag":         tagOrDefault(u.Fragment, "ss", u.Hostname(), port),
		"server":      u.Hostname(),
		"server_port": port,
		"method":      method,
		"password":    password,
	}, nil
}

func parseHysteria2(link string) (Outbound, error) {
	link = strings.Replace(link, "hy2://", "hysteria2://", 1)
	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("invalid hysteria2 link: %w", err)
	}
	port, err := parsePort(u.Port())
	if err != nil {
		return nil, fmt.Errorf("hysteria2 link: %w", err)
	}

	var password string
	if u.User != nil {
		password = u.User.Username()
		if pw, ok := u.User.Password(); ok {
			password = password + ":" + pw
		}
	}

	q := u.Query()
	serverName := q.Get("sni")
	if serverName == "" {
		serverName = u.Hostname()
	}
	tls := map[string]any{"enabled": true, "server_name": serverName}
	if q.Get("insecure") == "1" || q.Get("allowInsecure") == "1" {
		tls["insecure"] = true
	}

	outbound := Outbound{
		"type":        "hysteria2",
		"tag":         tagOrDefault(u.Fragment, "hysteria2", u.Hostname(), port),
		"server":      u.Hostname(),
		"server_port": port,
		"password":    password,
		"tls":         tls,
	}

	if obfs := q.Get("obfs"); obfs != "" {
		outbound["obfs"] = map[string]any{
			"type":     obfs,
			"password": q.Get("obfs-password"),
		}
	}

	return outbound, nil
}
