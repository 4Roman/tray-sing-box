package sharelink

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// portListPattern: what a port list may be quoted as in a refusal
var portListPattern = regexp.MustCompile(`^[0-9,:\- ]{1,64}$`)

// parsePortList converts a port-hopping list — "443,20000-30000" in the
// Hysteria URI, v2rayN's mport with '-' or ':' — into sing-box's
// server_ports, where every entry is "start:end" (a single port "p:p");
// first is the first port of the list
func parsePortList(s string) (ranges []string, first int, err error) {
	bad := func() error {
		if portListPattern.MatchString(s) {
			return fmt.Errorf("список портов «%s» не распознан", s)
		}
		return errors.New("список портов не распознан")
	}
	for _, entry := range strings.Split(s, ",") {
		entry = strings.TrimSpace(entry)
		lo, hi, isRange := strings.Cut(entry, "-")
		if !isRange {
			lo, hi, isRange = strings.Cut(entry, ":")
		}
		a, errA := strconv.Atoi(strings.TrimSpace(lo))
		b := a
		var errB error
		if isRange {
			b, errB = strconv.Atoi(strings.TrimSpace(hi))
		}
		if errA != nil || errB != nil || a < 1 || b > 65535 || a > b {
			return nil, 0, bad()
		}
		ranges = append(ranges, fmt.Sprintf("%d:%d", a, b))
		if first == 0 {
			first = a
		}
	}
	return ranges, first, nil
}

// splitPortList takes a multi-port list out of a hysteria link's authority
// ("pw@host:443,20000-30000" is no valid URL): the link comes back with the
// first port only, the list as server_ports. A link without a list comes
// back unchanged, ranges nil.
func splitPortList(link, scheme string) (string, []string, error) {
	rest := strings.TrimPrefix(link, scheme)
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}
	authority, tail := rest[:end], rest[end:]
	// The userinfo ends at the last '@', as net/url has it: a password may
	// contain ':' or ','
	userinfo, hostPort := "", authority
	if at := strings.LastIndex(authority, "@"); at >= 0 {
		userinfo, hostPort = authority[:at+1], authority[at+1:]
	}
	host, portPart := hostPort, ""
	if strings.HasPrefix(hostPort, "[") {
		i := strings.Index(hostPort, "]")
		if i < 0 {
			return link, nil, nil
		}
		host = hostPort[:i+1]
		after := hostPort[i+1:]
		if !strings.HasPrefix(after, ":") {
			return link, nil, nil
		}
		portPart = after[1:]
	} else if i := strings.LastIndex(hostPort, ":"); i >= 0 {
		host, portPart = hostPort[:i], hostPort[i+1:]
	}
	if !strings.ContainsAny(portPart, ",-") {
		return link, nil, nil
	}
	ranges, first, err := parsePortList(portPart)
	if err != nil {
		return "", nil, err
	}
	return scheme + userinfo + host + ":" + strconv.Itoa(first) + tail, ranges, nil
}

// hopping sets server_ports (from the authority's list, or else the mport
// parameter of v2rayN and the like) and hop_interval (mportHopInt, in
// seconds; sing-box refuses less than 5 s when it connects, and without it
// uses 30 s)
func hopping(outbound Outbound, ranges []string, mport, hopInt string) error {
	if ranges == nil && strings.TrimSpace(mport) != "" {
		var err error
		if ranges, _, err = parsePortList(mport); err != nil {
			return err
		}
	}
	if ranges == nil {
		return nil
	}
	outbound["server_ports"] = ranges
	hopInt = strings.TrimSpace(hopInt)
	if n, err := strconv.Atoi(hopInt); err == nil && n >= 5 {
		outbound["hop_interval"] = fmt.Sprintf("%ds", n)
	} else if d, err := time.ParseDuration(hopInt); err == nil && d >= 5*time.Second {
		outbound["hop_interval"] = d.String()
	}
	return nil
}

func parseHysteria2(link string) (Outbound, error) {
	if rest, short := strings.CutPrefix(link, "hy2://"); short {
		link = "hysteria2://" + rest
	}
	link, ranges, err := splitPortList(link, "hysteria2://")
	if err != nil {
		return nil, err
	}
	u, err := parseURL(link)
	if err != nil {
		return nil, err
	}
	// A password with an unescaped '/', '?' or '#' ends the authority inside
	// it: the head of the password would become the server (and the SNI),
	// the rest the path, the query or the name — and with the optional
	// password and the default port nothing else would refuse the link
	if u.User == nil && strings.Contains(link, "@") {
		return nil, errors.New("ссылка повреждена: символы «/», «?» и «#» в пароле должны быть закодированы (%2F, %3F, %23)")
	}
	host, err := serverHost(u)
	if err != nil {
		return nil, err
	}
	// The official URI: no port means 443
	port, err := portOrDefault(u.Port(), 443)
	if err != nil {
		return nil, err
	}

	var password string
	if u.User != nil {
		password = u.User.Username()
		if pw, ok := u.User.Password(); ok {
			password = password + ":" + pw
		}
	}

	q := queryValues(u.RawQuery)
	serverName := q.Get("sni")
	if serverName == "" {
		serverName = host
	}
	// No uTLS: this is QUIC
	tls := map[string]any{"enabled": true, "server_name": serverName}
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

	outbound := Outbound{
		"type":        "hysteria2",
		"tag":         tagOrDefault(u.Fragment, "hysteria2", host, port),
		"server":      host,
		"server_port": port,
		"password":    password,
		"tls":         tls,
	}

	switch obfs := strings.ToLower(strings.TrimSpace(q.Get("obfs"))); obfs {
	case "", "none":
	case "salamander", "gecko":
		if q.Get("obfs-password") == "" {
			return nil, errors.New("не указан пароль обфускации (obfs-password)")
		}
		outbound["obfs"] = map[string]any{
			"type":     obfs,
			"password": q.Get("obfs-password"),
		}
	default:
		return nil, fmt.Errorf("обфускация «%s» не поддерживается sing-box", token(obfs))
	}

	if err := hopping(outbound, ranges, q.Get("mport"), q.Get("mportHopInt")); err != nil {
		return nil, err
	}
	return outbound, nil
}

// parseHysteria reads a Hysteria (v1) link:
// hysteria://host:port?protocol=udp&auth=&peer=&insecure=1&upmbps=&downmbps=&alpn=&obfs=xplus&obfsParam=
func parseHysteria(link string) (Outbound, error) {
	link, ranges, err := splitPortList(link, "hysteria://")
	if err != nil {
		return nil, err
	}
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
	q := queryValues(u.RawQuery)

	switch protocol := strings.ToLower(strings.TrimSpace(q.Get("protocol"))); protocol {
	case "", "udp":
	default:
		return nil, fmt.Errorf("режим Hysteria «%s» не поддерживается sing-box (только udp)", token(protocol))
	}

	// Both speeds are required: without them sing-box does not start it
	up, errUp := strconv.Atoi(firstValue(q, "upmbps", "up"))
	down, errDown := strconv.Atoi(firstValue(q, "downmbps", "down"))
	if errUp != nil || errDown != nil || up <= 0 || down <= 0 {
		return nil, errors.New("не указана скорость канала (upmbps и downmbps), без неё sing-box не запускает Hysteria")
	}

	serverName := firstValue(q, "peer", "sni")
	if serverName == "" {
		serverName = host
	}
	// No uTLS: this is QUIC. Without alpn sing-box uses "hysteria"
	tls := map[string]any{"enabled": true, "server_name": serverName}
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

	outbound := Outbound{
		"type":        "hysteria",
		"tag":         tagOrDefault(u.Fragment, "hysteria", host, port),
		"server":      host,
		"server_port": port,
		"up_mbps":     up,
		"down_mbps":   down,
		"tls":         tls,
	}
	auth := q.Get("auth")
	if auth == "" && u.User != nil {
		auth = u.User.Username()
	}
	if auth != "" {
		outbound["auth_str"] = auth
	}

	// obfs is the mode (only xplus exists), obfsParam its password — which
	// is what sing-box's obfs takes
	switch mode := strings.ToLower(strings.TrimSpace(q.Get("obfs"))); mode {
	case "", "xplus":
		if param := q.Get("obfsParam"); param != "" {
			outbound["obfs"] = param
		}
	default:
		return nil, fmt.Errorf("обфускация «%s» не поддерживается sing-box", token(mode))
	}

	if err := hopping(outbound, ranges, q.Get("mport"), q.Get("mportHopInt")); err != nil {
		return nil, err
	}
	return outbound, nil
}

// firstValue is the value of the first of the keys that is set
func firstValue(q map[string][]string, keys ...string) string {
	for _, k := range keys {
		if v := q[k]; len(v) > 0 && strings.TrimSpace(v[0]) != "" {
			return strings.TrimSpace(v[0])
		}
	}
	return ""
}
