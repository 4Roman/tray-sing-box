package configfile

import (
	"reflect"
	"testing"
)

// groupMembers returns the members of a group of the saved config
func groupMembers(t *testing.T, path, group string) []any {
	t.Helper()
	o := outboundByTag(t, load(t, path), group)
	if o == nil {
		t.Fatalf("no group %q", group)
	}
	members, _ := o["outbounds"].([]any)
	return members
}

// A server the user dials through a group it is not a member of keeps that
// chain when it is imported again or refreshed — and is not added to the
// group it dials through: the group would depend on it and it on the group,
// a ring sing-box does not start with. Registered there, the update was
// refused as a ring the user never made, and the server stayed at its old
// credentials for good.
func TestReimportThroughAGroupIsNoRing(t *testing.T) {
	const config = `{"outbounds": [
    {"type": "selector", "tag": "proxy", "outbounds": ["A", "direct"]},
    {"type": "selector", "tag": "final-sel", "outbounds": ["U", "proxy"]},
    {"type": "vless", "tag": "A", "server": "192.0.2.10", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555555"},
    {"type": "vless", "tag": "U", "server": "192.0.2.11", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555555", "detour": "proxy"},
    {"type": "direct", "tag": "direct"}
  ], "route": {"final": "final-sel"}}`
	updated := func() map[string]any {
		u := vlessNode("U", "192.0.2.11")
		u["uuid"] = "99999999-2222-4333-8444-555555555555"
		return u
	}
	check := func(t *testing.T, path string) {
		t.Helper()
		u := outboundByTag(t, load(t, path), "U")
		if u["uuid"] != "99999999-2222-4333-8444-555555555555" || u["detour"] != "proxy" {
			t.Fatalf("U = %v", u)
		}
		if members := groupMembers(t, path, "proxy"); !reflect.DeepEqual(members, []any{"A", "direct"}) {
			t.Fatalf("proxy = %v", members)
		}
	}

	path := writeConfig(t, config)
	result, err := New(path).AddOutbounds([]map[string]any{updated()}, nil)
	if err != nil {
		t.Fatalf("AddOutbounds: %v", err)
	}
	if !reflect.DeepEqual(result.Tags, []string{"U"}) || len(result.Skipped) != 0 || !result.Changed {
		t.Fatalf("result = %+v", result)
	}
	check(t, path)

	path = writeConfig(t, config)
	sync, err := New(path).SyncOutbounds([]string{"U"}, []map[string]any{updated()})
	if err != nil {
		t.Fatalf("SyncOutbounds: %v", err)
	}
	if !reflect.DeepEqual(sync.Tags, []string{"U"}) || len(sync.Skipped) != 0 || !sync.Changed {
		t.Fatalf("sync = %+v", sync)
	}
	check(t, path)
}

// The group may be further up the chain: behind a relay, or behind another
// group the node dials through (a member of which dials through the first)
func TestImportNotRegisteredInAGroupUpTheChain(t *testing.T) {
	path := writeConfig(t, `{"outbounds": [
    {"type": "selector", "tag": "proxy", "outbounds": ["A", "direct"]},
    {"type": "selector", "tag": "relays", "outbounds": ["R2"]},
    {"type": "vless", "tag": "A", "server": "192.0.2.10", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555555"},
    {"type": "vless", "tag": "R1", "server": "192.0.2.20", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555555", "detour": "proxy"},
    {"type": "vless", "tag": "R2", "server": "192.0.2.21", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555555", "detour": "proxy"},
    {"type": "vless", "tag": "U1", "server": "192.0.2.11", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555555", "detour": "R1"},
    {"type": "vless", "tag": "U2", "server": "192.0.2.12", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555555", "detour": "relays"},
    {"type": "direct", "tag": "direct"}
  ], "route": {"final": "proxy"}}`)
	result, err := New(path).AddOutbounds([]map[string]any{vlessNode("U1", "192.0.2.31"), vlessNode("U2", "192.0.2.32"), vlessNode("B", "192.0.2.33")}, nil)
	if err != nil {
		t.Fatalf("AddOutbounds: %v", err)
	}
	if !reflect.DeepEqual(result.Tags, []string{"U1", "U2", "B"}) || len(result.Skipped) != 0 {
		t.Fatalf("result = %+v", result)
	}
	if members := groupMembers(t, path, "proxy"); !reflect.DeepEqual(members, []any{"A", "direct", "B"}) {
		t.Fatalf("proxy = %v", members)
	}
	// relays is a group U1 does not depend on: it becomes selectable there
	if members := groupMembers(t, path, "relays"); !reflect.DeepEqual(members, []any{"R2", "U1", "B"}) {
		t.Fatalf("relays = %v", members)
	}
}

// A node registered in a group is a dependency of that group from then on:
// a later node of the same batch that reaches the node's own chain through
// that group is not registered where it would close a ring. Here A dials
// through Q and B through P; A goes into P, so B now reaches Q through P
// and A — in Q, B would close Q -> B -> P -> A -> Q.
func TestRegistrationFollowsEarlierRegistrations(t *testing.T) {
	path := writeConfig(t, `{"outbounds": [
    {"type": "selector", "tag": "P", "outbounds": ["direct"]},
    {"type": "selector", "tag": "Q", "outbounds": ["direct"]},
    {"type": "vless", "tag": "A", "server": "192.0.2.10", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555555", "detour": "Q"},
    {"type": "vless", "tag": "B", "server": "192.0.2.11", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555555", "detour": "P"},
    {"type": "direct", "tag": "direct"}
  ], "route": {"final": "P"}}`)
	result, err := New(path).AddOutbounds([]map[string]any{vlessNode("A", "192.0.2.20"), vlessNode("B", "192.0.2.21")}, nil)
	if err != nil {
		t.Fatalf("AddOutbounds: %v", err)
	}
	if !reflect.DeepEqual(result.Tags, []string{"A", "B"}) || len(result.Skipped) != 0 {
		t.Fatalf("result = %+v", result)
	}
	if p, q := groupMembers(t, path, "P"), groupMembers(t, path, "Q"); !reflect.DeepEqual(p, []any{"direct", "A"}) || !reflect.DeepEqual(q, []any{"direct"}) {
		t.Fatalf("P = %v, Q = %v", p, q)
	}
}

// shadowTLSProfile is the ShadowTLS pattern of sing-box profiles (hiddify,
// the sing-box documentation): a shadowsocks node dialing through a
// shadowtls outbound, which ignores the destination and works only so
func shadowTLSProfile(helperFirst bool) []map[string]any {
	ss := map[string]any{
		"type": "shadowsocks", "tag": "st-ss", "server": "192.0.2.40", "server_port": 443,
		"method": "2022-blake3-aes-128-gcm", "password": "8JCsPssfgS8tiRwiMlhARg==", "detour": "st-ss_shadowtls-out",
	}
	helper := map[string]any{
		"type": "shadowtls", "tag": "st-ss_shadowtls-out", "server": "192.0.2.40", "server_port": 443,
		"version": 3, "password": "shadowtls-password",
		"tls": map[string]any{"enabled": true, "server_name": "www.example.com"},
	}
	if helperFirst {
		return []map[string]any{helper, ss}
	}
	return []map[string]any{ss, helper}
}

// The helper of a profile's node is not offered as a server: it is not
// added to the user's groups, by an import or a refresh — also when the
// node it serves was refused by the check
func TestRelayOfTheBatchNotRegistered(t *testing.T) {
	path := writeSample(t)
	result, err := New(path).AddOutbounds(append(shadowTLSProfile(false), vlessNode("DE", "192.0.2.10")), nil)
	if err != nil {
		t.Fatalf("AddOutbounds: %v", err)
	}
	if len(result.Tags) != 3 || len(result.Skipped) != 0 {
		t.Fatalf("result = %+v", result)
	}
	if members := groupMembers(t, path, "proxy"); !reflect.DeepEqual(members, []any{"old-node", "direct", "st-ss", "DE"}) {
		t.Fatalf("proxy = %v", members)
	}

	path = writeSample(t)
	sync, err := New(path).SyncOutbounds(nil, append(shadowTLSProfile(true), vlessNode("DE", "192.0.2.10")))
	if err != nil {
		t.Fatalf("SyncOutbounds: %v", err)
	}
	if len(sync.Tags) != 3 || len(sync.Skipped) != 0 {
		t.Fatalf("sync = %+v", sync)
	}
	if members := groupMembers(t, path, "proxy"); !reflect.DeepEqual(members, []any{"old-node", "direct", "st-ss", "DE"}) {
		t.Fatalf("proxy = %v", members)
	}

	// The shadowsocks node refused: the helper is saved (nothing it needs is
	// missing) but still no server
	editor, path, _ := checkedEditor(t, sampleConfig)
	batch := shadowTLSProfile(false)
	batch[0]["flow"] = "from-a-newer-sing-box"
	result, err = editor.AddOutbounds(append(batch, vlessNode("DE", "192.0.2.10")), nil)
	if err != nil {
		t.Fatalf("AddOutbounds with a refused node: %v", err)
	}
	if !reflect.DeepEqual(result.Tags, []string{"st-ss_shadowtls-out", "DE"}) || len(result.Skipped) != 1 {
		t.Fatalf("result = %+v", result)
	}
	if members := groupMembers(t, path, "proxy"); !reflect.DeepEqual(members, []any{"old-node", "direct", "DE"}) {
		t.Fatalf("proxy = %v", members)
	}
}

// The references to a node a refresh removes go to a server the traffic can
// use: not a relay of another node (the provider listing the ShadowTLS
// helper first), not a node whose server is this machine (a provider's
// placeholder on 127.0.0.1, the DPI bypass's local proxy) — among the new
// nodes and among the surviving ones
func TestRemovedNodeReplacementIsAServer(t *testing.T) {
	const config = `{"outbounds": [
    {"type": "selector", "tag": "proxy", "outbounds": ["DE", "direct"], "default": "DE"},
    {"type": "vless", "tag": "DE", "server": "192.0.2.10", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555555"},
    {"type": "http", "tag": "dpi-bypass", "server": "127.0.0.1", "server_port": 3128},
    {"type": "vless", "tag": "user-node", "server": "192.0.2.30", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555555"},
    {"type": "direct", "tag": "direct"}
  ], "route": {"rules": [{"domain_suffix": [".example.org"], "outbound": "DE"}], "final": "DE"}}`
	placeholder := func(server string) map[string]any {
		return map[string]any{"type": "socks", "tag": "info " + server, "server": server, "server_port": 1080}
	}
	for name, tc := range map[string]struct {
		fresh []map[string]any
		want  string
	}{
		"relay first":         {shadowTLSProfile(true), "st-ss"},
		"placeholder first":   {[]map[string]any{placeholder("127.0.0.1"), vlessNode("NL", "192.0.2.11")}, "NL"},
		"unspecified first":   {[]map[string]any{placeholder("0.0.0.0"), vlessNode("NL", "192.0.2.11")}, "NL"},
		"localhost first":     {[]map[string]any{placeholder("localhost"), vlessNode("NL", "192.0.2.11")}, "NL"},
		"IPv6 loopback first": {[]map[string]any{placeholder("::1"), vlessNode("NL", "192.0.2.11")}, "NL"},
		"only a placeholder":  {[]map[string]any{placeholder("127.0.0.1")}, "user-node"},
	} {
		t.Run(name, func(t *testing.T) {
			path := writeConfig(t, config)
			result, err := New(path).SyncOutbounds([]string{"DE"}, tc.fresh)
			if err != nil {
				t.Fatalf("SyncOutbounds: %v", err)
			}
			if !reflect.DeepEqual(result.Removed, []string{"DE"}) || len(result.Skipped) != 0 {
				t.Fatalf("result = %+v", result)
			}
			route := load(t, path)["route"].(map[string]any)
			if route["final"] != tc.want {
				t.Fatalf("final = %v, want %s", route["final"], tc.want)
			}
			if rule := route["rules"].([]any)[0].(map[string]any); rule["outbound"] != tc.want {
				t.Fatalf("rule = %v", rule)
			}
		})
	}
}

// The node a relay serves refused, the relay alone saved: the references of
// a node the refresh removes still do not go to that relay — it is one
// whether or not its node made it — but to a direct outbound
func TestRefusedNodesRelayIsNoReplacement(t *testing.T) {
	const config = `{"outbounds": [
    {"type": "selector", "tag": "proxy", "outbounds": ["DE", "direct"], "default": "DE"},
    {"type": "vless", "tag": "DE", "server": "192.0.2.10", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555555"},
    {"type": "direct", "tag": "direct"}
  ], "route": {"rules": [{"domain_suffix": [".example.org"], "outbound": "DE"}], "final": "DE"}}`
	for _, helperFirst := range []bool{true, false} {
		editor, path, _ := checkedEditor(t, config)
		fresh := shadowTLSProfile(helperFirst)
		for _, o := range fresh {
			if o["type"] == "shadowsocks" {
				o["flow"] = "bogus" // refused by the fake check
			}
		}
		result, err := editor.SyncOutbounds([]string{"DE"}, fresh)
		if err != nil {
			t.Fatalf("SyncOutbounds: %v", err)
		}
		if !reflect.DeepEqual(result.Tags, []string{"st-ss_shadowtls-out"}) || len(result.Skipped) != 1 {
			t.Fatalf("helper first %v: result = %+v", helperFirst, result)
		}
		route := load(t, path)["route"].(map[string]any)
		if route["final"] != "direct" {
			t.Fatalf("helper first %v: final = %v", helperFirst, route["final"])
		}
	}
}

// A config whose sections are spelled otherwise ({"Route": {"Final": …}},
// read so by sing-box): the merge repoints those references too — the
// dependency check reads them, and would otherwise refuse the refresh that
// removed the node they name, at every refresh
func TestRefreshRepointsReferencesInAnySpelling(t *testing.T) {
	path := writeConfig(t, `{"outbounds": [
    {"type": "selector", "tag": "proxy", "outbounds": ["DE", "direct"]},
    {"type": "vless", "tag": "DE", "server": "192.0.2.10", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555555"},
    {"type": "direct", "tag": "direct"}
  ], "DNS": {"Servers": [{"type": "https", "tag": "remote", "server": "1.1.1.1", "Detour": "DE"}]},
  "Route": {"Rules": [{"domain_suffix": [".example.org"], "outbound": "DE"}], "Final": "DE"}}`)
	result, err := New(path).SyncOutbounds([]string{"DE"}, []map[string]any{vlessNode("NL", "192.0.2.11")})
	if err != nil {
		t.Fatalf("SyncOutbounds: %v", err)
	}
	if !reflect.DeepEqual(result.Removed, []string{"DE"}) || !result.Changed {
		t.Fatalf("result = %+v", result)
	}
	cfg := load(t, path)
	route := cfg["Route"].(map[string]any)
	if route["Final"] != "NL" || route["Rules"].([]any)[0].(map[string]any)["outbound"] != "NL" {
		t.Fatalf("route = %v", route)
	}
	server := cfg["DNS"].(map[string]any)["Servers"].([]any)[0].(map[string]any)
	if server["Detour"] != "NL" {
		t.Fatalf("dns server = %v", server)
	}
}
