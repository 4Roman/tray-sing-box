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
