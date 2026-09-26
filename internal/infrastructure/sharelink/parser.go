// Package sharelink converts proxy share links (vless://, vmess://, trojan://,
// ss://, hysteria2://, hysteria://, tuic://, anytls://, socks://) and
// subscription bodies (lists of such links, base64 blobs, sing-box and SIP008
// JSON profiles) into sing-box outbound JSON objects. sing-box core has no
// native share-link import, so the conversion is implemented here.
//
// A link sing-box cannot run as it is meant (an Xray-only transport, VLESS
// Encryption, a plugin sing-box does not have, ...) is refused, not imported
// in a form that passes `sing-box check` and then never connects. The reason
// is in Russian (it reaches the tray popups and the settings page) and never
// quotes the link: it carries the server's credentials.
package sharelink

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"tray-sing-box/internal/domain"
)

// Outbound is a sing-box outbound object ready to be embedded into config.json
type Outbound map[string]any

// Parser adapts this package to the domain.OutboundParser interface
type Parser struct{}

// Parse extracts and converts every share link found in text (or the nodes
// of a subscription profile); the links that could not be converted are
// listed in skipped
func (Parser) Parse(text string) ([]map[string]any, []domain.SkippedNode, error) {
	outbounds, skipped, err := ParseAllReport(text)
	if err != nil {
		return nil, skipped, err
	}
	result := make([]map[string]any, len(outbounds))
	for i, o := range outbounds {
		result[i] = o
	}
	return result, skipped, nil
}

// Tag returns the outbound tag
func (o Outbound) Tag() string {
	tag, _ := o["tag"].(string)
	return tag
}

// linkParsers are the supported schemes and their converters
var linkParsers = []struct {
	scheme string
	parse  func(string) (Outbound, error)
}{
	{"vless://", parseVLESS},
	{"vmess://", parseVMess},
	{"trojan://", parseTrojan},
	{"ss://", parseShadowsocks},
	{"hysteria2://", parseHysteria2},
	{"hy2://", parseHysteria2},
	{"hysteria://", parseHysteria},
	{"tuic://", parseTUIC},
	{"anytls://", parseAnyTLS},
	{"socks://", parseSOCKS},
	{"socks5://", parseSOCKS},
	{"socks5h://", parseSOCKS},
	{"socks4://", parseSOCKS},
	{"socks4a://", parseSOCKS},
}

// unsupportedSchemes are proxy links the app recognizes but cannot import:
// found in a text they are reported with the reason instead of being
// silently ignored
var unsupportedSchemes = []struct {
	scheme, reason string
}{
	{"ssr://", "ShadowsocksR не поддерживается sing-box"},
	{"wireguard://", "ссылки WireGuard приложение не импортирует (в sing-box это endpoint, а не outbound)"},
	{"wg://", "ссылки WireGuard приложение не импортирует (в sing-box это endpoint, а не outbound)"},
	{"awg://", "AmneziaWG не поддерживается sing-box"},
	{"hysteria2+realm://", "режим realm Hysteria 2 приложение не импортирует"},
	{"hysteria2+realm+http://", "режим realm Hysteria 2 приложение не импортирует"},
	{"naive+https://", "ссылки NaiveProxy приложение не импортирует"},
	{"naive+quic://", "ссылки NaiveProxy приложение не импортирует"},
	{"naive://", "ссылки NaiveProxy приложение не импортирует"},
}

// allSchemes is every scheme extractLinks looks for
var allSchemes = func() []string {
	var all []string
	for _, p := range linkParsers {
		all = append(all, p.scheme)
	}
	for _, u := range unsupportedSchemes {
		all = append(all, u.scheme)
	}
	return all
}()

// errNoLinks: the text holds nothing the app can read
var errNoLinks = errors.New("в тексте нет ссылок на серверы (приложение понимает vless://, vmess://, trojan://, ss://, " +
	"hysteria2://, hysteria://, tuic://, anytls://, socks://, их списки и подписки в base64, профили sing-box и SIP008)")

// nodeError is the refusal of one link: the reason, for the user in Russian,
// and the node's name when the link has one
type nodeError struct {
	name   string
	reason string
}

func (e *nodeError) Error() string {
	if e.name == "" {
		return e.reason
	}
	return fmt.Sprintf("узел «%s»: %s", e.name, e.reason)
}

// Parse converts a single share link into a sing-box outbound. The error
// names the node (the link's name) and says in Russian why it was refused.
func Parse(link string) (Outbound, error) {
	link = strings.TrimSpace(link)
	outbound, err := parseLink(link)
	if err != nil {
		return nil, &nodeError{name: linkTitle(link), reason: err.Error()}
	}
	return outbound, nil
}

// parseLink converts a link; its error is the bare reason
func parseLink(link string) (Outbound, error) {
	for _, p := range linkParsers {
		if strings.HasPrefix(link, p.scheme) {
			return p.parse(link)
		}
	}
	for _, u := range unsupportedSchemes {
		if strings.HasPrefix(link, u.scheme) {
			return nil, errors.New(u.reason)
		}
	}
	return nil, errors.New("неизвестный формат ссылки (приложение понимает vless://, vmess://, trojan://, ss://, " +
		"hysteria2://, hysteria://, tuic://, anytls:// и socks://)")
}

// extractLinks returns every proxy link (supported or recognized as
// unsupported) found in arbitrary text. A scheme counts only at the start of
// a word: "wss://" is no "ss://" link, "vmess://" no "ss://" either.
func extractLinks(text string) []string {
	var links []string
	for _, field := range strings.Fields(text) {
		best, bestLen := -1, 0
		for _, scheme := range allSchemes {
			for from := 0; from < len(field); {
				i := strings.Index(field[from:], scheme)
				if i < 0 {
					break
				}
				i += from
				if i == 0 || !schemeChar(field[i-1]) {
					if best < 0 || i < best || (i == best && len(scheme) > bestLen) {
						best, bestLen = i, len(scheme)
					}
					break
				}
				from = i + 1
			}
		}
		if best >= 0 {
			links = append(links, field[best:])
		}
	}
	return links
}

// schemeChar: a character a URL scheme may contain
func schemeChar(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '+' || c == '-' || c == '.'
}

// ParseAny extracts the first supported share link from arbitrary text
// (e.g. clipboard content with surrounding noise) and parses it.
func ParseAny(text string) (Outbound, error) {
	links := extractLinks(text)
	if len(links) == 0 {
		return nil, errNoLinks
	}
	return Parse(links[0])
}

// ParseAll extracts and parses every supported share link in text. If the
// text contains no links directly, it is treated as a base64 subscription
// blob (a base64-encoded list of links, the common subscription format) or
// a JSON profile (sing-box, SIP008). Links that fail to parse are skipped as
// long as at least one succeeds. Duplicate tags get a numeric suffix so each
// outbound stays addressable.
func ParseAll(text string) ([]Outbound, error) {
	outbounds, _, err := ParseAllReport(text)
	return outbounds, err
}

// ParseAllReport is ParseAll that also names the links it left out, with
// the reason (never the link: it carries credentials). When nothing could be
// converted the error lists the reasons.
func ParseAllReport(text string) ([]Outbound, []domain.SkippedNode, error) {
	var c collector
	if ok, err := c.profile(text); ok {
		return c.result(err)
	}

	links := extractLinks(text)
	var decoded string
	if len(links) == 0 {
		compact := strings.Join(strings.Fields(text), "")
		if data, err := decodeBase64(compact); err == nil {
			decoded = string(data)
			links = extractLinks(decoded)
			if len(links) == 0 {
				if ok, err := c.profile(decoded); ok {
					return c.result(err)
				}
			}
		}
	}
	if len(links) == 0 {
		if err := foreignProfile(text); err != nil {
			return nil, nil, err
		}
		if err := foreignProfile(decoded); err != nil {
			return nil, nil, err
		}
		return nil, nil, errNoLinks
	}

	for i, link := range links {
		outbound, err := parseLink(link)
		if err != nil {
			c.skip(linkName(link, i), err.Error())
			continue
		}
		c.add(outbound)
	}
	return c.result(nil)
}

// collector gathers the converted outbounds (tags made unique) and the
// nodes left out
type collector struct {
	outbounds []Outbound
	skipped   []domain.SkippedNode
	seen      map[string]int
}

func (c *collector) add(outbound Outbound) {
	if c.seen == nil {
		c.seen = map[string]int{}
	}
	tag := outbound.Tag()
	c.seen[tag]++
	if c.seen[tag] > 1 {
		tag = fmt.Sprintf("%s (%d)", tag, c.seen[tag])
		outbound["tag"] = tag
		c.seen[tag]++
	}
	c.outbounds = append(c.outbounds, outbound)
}

func (c *collector) skip(name, reason string) {
	c.skipped = append(c.skipped, domain.SkippedNode{Name: name, Reason: reason})
}

// result: the outbounds, or — nothing converted — an error: err when the
// source itself was refused, otherwise the list of the reasons
func (c *collector) result(err error) ([]Outbound, []domain.SkippedNode, error) {
	if len(c.outbounds) > 0 {
		return c.outbounds, c.skipped, nil
	}
	if err == nil {
		err = nothingImported(c.skipped)
	}
	return nil, c.skipped, err
}

// nothingImported is the error of a text none of whose nodes could be
// converted: every reason (the first few), each with its node
func nothingImported(skipped []domain.SkippedNode) error {
	if len(skipped) == 0 {
		return errNoLinks
	}
	const limit = 5
	var parts []string
	for i, sk := range skipped {
		if i == limit {
			parts = append(parts, fmt.Sprintf("и ещё %d", len(skipped)-limit))
			break
		}
		parts = append(parts, fmt.Sprintf("«%s» — %s", sk.Name, sk.Reason))
	}
	if len(skipped) == 1 {
		return fmt.Errorf("сервер не импортирован: %s", parts[0])
	}
	return fmt.Errorf("ни один сервер не импортирован: %s", strings.Join(parts, "; "))
}

// linkName is what a skipped link is called in the report: its name (the
// URL fragment, or the vmess "ps"), never anything else of the link
func linkName(link string, index int) string {
	if name := linkTitle(link); name != "" {
		return name
	}
	return fmt.Sprintf("ссылка %d", index+1)
}

// linkTitle is the link's own name, "" when it has none. Only a fragment on
// one line qualifies: Parse is given whatever text its caller has, and after
// the last '#' of a text with line breaks there could be anything
func linkTitle(link string) string {
	if i := strings.LastIndex(link, "#"); i >= 0 {
		if name, err := url.QueryUnescape(link[i+1:]); err == nil && plainName(name) {
			return shortName(name)
		}
	}
	if strings.HasPrefix(link, "vmess://") {
		if payload, err := decodeBase64(strings.TrimPrefix(link, "vmess://")); err == nil {
			var v struct {
				Ps string `json:"ps"`
			}
			if json.Unmarshal(payload, &v) == nil && plainName(v.Ps) {
				return shortName(v.Ps)
			}
		}
	}
	return ""
}

// plainName: a non-empty name on one line
func plainName(s string) bool {
	return strings.TrimSpace(s) != "" && !strings.ContainsFunc(s, func(r rune) bool { return r < ' ' || r == 0x7f })
}

// shortName trims a name for the report (the node's tag keeps it whole)
func shortName(s string) string {
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > 100 {
		return string(r[:100]) + "…"
	}
	return s
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

// parseURL is url.Parse without the link in its error: net/url quotes the
// whole input (and its inner errors quote pieces of it, e.g. an "invalid
// port" made of password characters), and a share link carries the
// server's credentials — the error text reaches the log, the tray popups and
// the settings page, which any program of the user can drive
func parseURL(link string) (*url.URL, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, errors.New("ссылка повреждена")
	}
	return u, nil
}

// serverHost is the link's server address; a link without one is refused
func serverHost(u *url.URL) (string, error) {
	host := u.Hostname()
	if host == "" {
		return "", errors.New("в ссылке не указан адрес сервера")
	}
	return host, nil
}

func parsePort(s string) (int, error) {
	if s == "" {
		return 0, errors.New("в ссылке не указан порт")
	}
	port, err := strconv.Atoi(s)
	if err != nil || port < 1 || port > 65535 {
		return 0, errors.New("неверный порт")
	}
	return port, nil
}

// portOrDefault is parsePort with a default for a link without a port (the
// hysteria2 and anytls URI schemes say 443)
func portOrDefault(s string, def int) (int, error) {
	if s == "" {
		return def, nil
	}
	return parsePort(s)
}

// queryValues parses a link's query like url.ParseQuery, except that a ';'
// belongs to the value: net/url drops a whole pair that contains one, and a
// SIP002 plugin value ("obfs-local;obfs=http") is often left unescaped. A
// value that is not valid percent-encoding is kept as it is.
func queryValues(raw string) url.Values {
	values := url.Values{}
	for _, pair := range strings.Split(raw, "&") {
		if pair == "" {
			continue
		}
		key, value, _ := strings.Cut(pair, "=")
		if k, err := url.QueryUnescape(key); err == nil {
			key = k
		}
		if v, err := url.QueryUnescape(value); err == nil {
			value = v
		}
		values.Add(key, value)
	}
	return values
}

// flagSet reports whether any of the keys is set to 1 or true
func flagSet(q url.Values, keys ...string) bool {
	for _, k := range keys {
		switch strings.ToLower(strings.TrimSpace(q.Get(k))) {
		case "1", "true":
			return true
		}
	}
	return false
}

// insecureKeys are the spellings of "skip certificate verification" in the
// links of the various clients
var insecureKeys = []string{"allowInsecure", "insecure", "allow_insecure", "allowinsecure"}

// splitList splits a comma-separated value, dropping empty items
func splitList(s string) []string {
	var items []string
	for _, item := range strings.Split(s, ",") {
		if item = strings.TrimSpace(item); item != "" {
			items = append(items, item)
		}
	}
	return items
}

// firstOf is the first item of a comma-separated value
func firstOf(s string) string {
	if items := splitList(s); len(items) > 0 {
		return items[0]
	}
	return ""
}

// tokenPattern: a value short and plain enough to be named in a reason — a
// transport, flow or plugin name, never a credential-like blob
var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,31}$`)

// token returns s when it can be quoted in a reason, "…" otherwise
func token(s string) string {
	if tokenPattern.MatchString(s) {
		return s
	}
	return "…"
}
