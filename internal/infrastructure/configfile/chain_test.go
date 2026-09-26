package configfile

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"tray-sing-box/internal/domain"
)

// Detour chains and group members: sing-box check passes a config whose
// outbounds depend on a tag that is not there or on each other in a ring,
// and sing-box then does not start. Every save refuses what it would add.
func TestDependencyProblemsRefused(t *testing.T) {
	for name, tc := range map[string]struct {
		outbounds string
		want      []string
	}{
		"missing detour": {
			`[{"type": "vless", "tag": "A", "server": "a.example.com", "server_port": 443, "detour": "gone"}, {"type": "direct", "tag": "direct"}]`,
			[]string{"outbound «A» работает через «gone»"},
		},
		"detour spelled otherwise": {
			`[{"type": "vless", "tag": "A", "server": "a.example.com", "server_port": 443, "Detour": "gone"}, {"type": "direct", "tag": "direct"}]`,
			[]string{"outbound «A» работает через «gone»"},
		},
		"missing member": {
			`[{"type": "selector", "tag": "proxy", "outbounds": ["direct", "gone"]}, {"type": "direct", "tag": "direct"}]`,
			[]string{"в группе «proxy» есть «gone»"},
		},
		"ring": {
			`[{"type": "vless", "tag": "A", "server": "a.example.com", "server_port": 443, "detour": "B"},
			  {"type": "vless", "tag": "B", "server": "b.example.com", "server_port": 443, "detour": "A"}, {"type": "direct", "tag": "direct"}]`,
			[]string{"«A», «B» подключаются друг через друга по кругу"},
		},
		"ring through a group": {
			`[{"type": "selector", "tag": "proxy", "outbounds": ["A", "direct"]},
			  {"type": "vless", "tag": "A", "server": "a.example.com", "server_port": 443, "detour": "proxy"}, {"type": "direct", "tag": "direct"}]`,
			[]string{"«A», «proxy»"},
		},
		"itself": {
			`[{"type": "vless", "tag": "A", "server": "a.example.com", "server_port": 443, "detour": "A"}, {"type": "direct", "tag": "direct"}]`,
			[]string{"«A» подключается через самого себя"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			path := writeSample(t)
			err := New(path).WriteSection("outbounds", []byte(tc.outbounds))
			if err == nil {
				t.Fatal("saved")
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "sing-box не запустится") {
					t.Fatalf("error = %q, want it to say %q", err, want)
				}
			}
			if !refusal(err) {
				t.Fatal("not a refusal")
			}

			// One the config already has does not block other saves
			path = writeConfig(t, `{"outbounds": `+tc.outbounds+`, "route": {"final": "direct"}}`)
			if err := New(path).AddOutbound(node("new", "")); err != nil {
				t.Fatalf("an existing problem blocked an import: %v", err)
			}
		})
	}

	// The first config too
	err := New(filepath.Join(t.TempDir(), "config.json")).CreateConfig([]byte(`{"outbounds": [{"type": "vless", "tag": "A", "server": "a.example.com", "server_port": 443, "detour": "gone"}]}`))
	if err == nil || !strings.Contains(err.Error(), "«gone»") {
		t.Fatalf("CreateConfig: %v", err)
	}
}

// A node chained through one the checks refused goes with it — saved, it
// would name an outbound the config does not have. The others are saved.
func TestRefusedNodeTakesItsChain(t *testing.T) {
	editor, path, _ := checkedEditor(t, sampleConfig)

	exit := node("exit", "")
	exit["detour"] = "relay"
	further := node("further", "")
	further["detour"] = "exit"
	result, err := editor.AddOutbounds([]map[string]any{further, exit, node("relay", "bad-flow"), node("good", "")}, nil)
	if err != nil {
		t.Fatalf("AddOutbounds: %v", err)
	}
	if !reflect.DeepEqual(result.Tags, []string{"good"}) {
		t.Fatalf("saved %v", result.Tags)
	}
	want := []domain.SkippedNode{
		{Name: "further", Reason: "узел работает через «exit», а тот пропущен"},
		{Name: "exit", Reason: "узел работает через «relay», а тот пропущен"},
		{Name: "relay", Reason: "sing-box не принимает: unsupported flow: bad-flow"},
	}
	if !reflect.DeepEqual(result.Skipped, want) {
		t.Fatalf("skipped = %+v", result.Skipped)
	}
	cfg := load(t, path)
	if outboundByTag(t, cfg, "exit") != nil || outboundByTag(t, cfg, "further") != nil {
		t.Fatalf("a chained node was saved: %v", cfg["outbounds"])
	}
}

// What the dependency check refuses in an incoming node costs only that node
func TestDependencyRefusalLeavesOutOne(t *testing.T) {
	path := writeSample(t)
	dangling := node("dangling", "")
	dangling["Detour"] = "nowhere"
	result, err := New(path).AddOutbounds([]map[string]any{node("good", ""), dangling}, nil)
	if err != nil {
		t.Fatalf("AddOutbounds: %v", err)
	}
	if !reflect.DeepEqual(result.Tags, []string{"good"}) || len(result.Skipped) != 1 || result.Skipped[0].Name != "dangling" ||
		!strings.Contains(result.Skipped[0].Reason, "«nowhere»") {
		t.Fatalf("result = %+v", result)
	}
}

// A detour spelled otherwise is a detour to sing-box: a node the refresh
// removes is taken out of it like out of any other
func TestSyncPrunesDetourSpelledOtherwise(t *testing.T) {
	path := writeConfig(t, strings.Replace(syncBaseConfig, `"detour": "sub-a"`, `"Detour": "sub-a"`, 1))
	result, err := New(path).SyncOutbounds([]string{"sub-a", "sub-b"}, []map[string]any{{"type": "vless", "tag": "sub-b", "server": "b.example.com"}})
	if err != nil {
		t.Fatalf("SyncOutbounds: %v", err)
	}
	if !reflect.DeepEqual(result.Removed, []string{"sub-a"}) {
		t.Fatalf("result = %+v", result)
	}
	for k := range outboundByTag(t, load(t, path), "user-node") {
		if strings.EqualFold(k, "detour") {
			t.Fatal("the detour to the removed node stayed")
		}
	}
}

// A profile node named like one of the user's outbounds is saved under
// another name; the node chained through it follows it there — not to the
// user's outbound of that name (here the selector it is added to: a ring)
func TestSuffixFollowsDetours(t *testing.T) {
	profile := func() []map[string]any {
		chained := node("F", "")
		chained["detour"] = "proxy"
		return []map[string]any{node("proxy", ""), chained}
	}

	path := writeSample(t)
	result, err := New(path).AddOutbounds(profile(), nil)
	if err != nil {
		t.Fatalf("AddOutbounds: %v", err)
	}
	if !reflect.DeepEqual(result.Tags, []string{"proxy (2)", "F"}) || len(result.Skipped) != 0 {
		t.Fatalf("result = %+v", result)
	}
	if detour := outboundByTag(t, load(t, path), "F")["detour"]; detour != "proxy (2)" {
		t.Fatalf("F dials through %v", detour)
	}

	// A subscription the same way
	path = writeSample(t)
	sync, err := New(path).SyncOutbounds(nil, profile())
	if err != nil {
		t.Fatalf("SyncOutbounds: %v", err)
	}
	if !reflect.DeepEqual(sync.Tags, []string{"proxy (2)", "F"}) || len(sync.Skipped) != 0 {
		t.Fatalf("sync = %+v", sync)
	}
	if detour := outboundByTag(t, load(t, path), "F")["detour"]; detour != "proxy (2)" {
		t.Fatalf("F dials through %v", detour)
	}
}

// A subscription's name is reserved also while the config lacks the node
// (deleted by hand, a rollback): its next refresh would take the import over
func TestImportAvoidsReservedNameMissingFromConfig(t *testing.T) {
	path := writeSample(t)
	result, err := New(path).AddOutbounds([]map[string]any{node("srv", "")}, []string{"srv"})
	if err != nil {
		t.Fatalf("AddOutbounds: %v", err)
	}
	if !reflect.DeepEqual(result.Tags, []string{"srv (2)"}) ||
		!reflect.DeepEqual(result.Renamed, []domain.TagRename{{From: "srv", To: "srv (2)"}}) {
		t.Fatalf("result = %+v", result)
	}
}

const heldConfig = `{
  "outbounds": [
    {"type": "selector", "tag": "proxy", "outbounds": ["DE", "NL|12GB", "direct"], "default": "NL|12GB"},
    {"type": "vless", "tag": "DE", "server": "192.0.2.10", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555555"},
    {"type": "vless", "tag": "NL|12GB", "server": "192.0.2.11", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555555"},
    {"type": "direct", "tag": "direct"}
  ],
  "route": {"rules": [{"domain_suffix": [".example.org"], "outbound": "NL|12GB"}], "final": "proxy"}
}`

// A refused update of a subscription's node keeps the copy the config has —
// the user's choice and rules stay on it — and the subscription keeps it.
// The same when the provider renamed the node meanwhile (live counters).
func TestRefusedUpdateKeepsOwnedCopy(t *testing.T) {
	for name, nl := range map[string]string{"same name": "NL|12GB", "renamed": "NL|11GB"} {
		t.Run(name, func(t *testing.T) {
			editor, path, _ := checkedEditor(t, heldConfig)
			refused := vlessNode(nl, "192.0.2.11")
			refused["flow"] = "from-a-newer-sing-box"
			changed := vlessNode("DE", "192.0.2.12")

			result, err := editor.SyncOutbounds([]string{"DE", "NL|12GB"}, []map[string]any{changed, refused})
			if err != nil {
				t.Fatalf("SyncOutbounds: %v", err)
			}
			if !reflect.DeepEqual(result.Tags, []string{"DE", "NL|12GB"}) || len(result.Removed) != 0 ||
				len(result.Skipped) != 1 || result.Skipped[0].Name != nl || !result.NeedsRestart {
				t.Fatalf("result = %+v", result)
			}
			cfg := load(t, path)
			if n := outboundByTag(t, cfg, "NL|12GB"); n == nil || n["server"] != "192.0.2.11" {
				t.Fatalf("the working copy is gone: %v", cfg["outbounds"])
			}
			if outboundByTag(t, cfg, "DE")["server"] != "192.0.2.12" {
				t.Fatal("the other node was not updated")
			}
			if def := outboundByTag(t, cfg, "proxy")["default"]; def != "NL|12GB" {
				t.Fatalf("selector default moved to %v", def)
			}
			rule := cfg["route"].(map[string]any)["rules"].([]any)[0].(map[string]any)
			if rule["outbound"] != "NL|12GB" {
				t.Fatalf("rule moved to %v", rule["outbound"])
			}
		})
	}
}

// A refused relay keeps its copy, and the node chained through it keeps its
// own and the chain — not deleted with it, not dialing directly past it
func TestRefusedRelayKeepsTheChain(t *testing.T) {
	config := `{"outbounds": [
    {"type": "selector", "tag": "proxy", "outbounds": ["relay", "exit", "other", "direct"]},
    {"type": "vless", "tag": "relay", "server": "192.0.2.10", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555555"},
    {"type": "vless", "tag": "exit", "server": "192.0.2.11", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555555", "detour": "relay"},
    {"type": "vless", "tag": "other", "server": "192.0.2.12", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555555"},
    {"type": "direct", "tag": "direct"}
  ], "route": {"final": "proxy"}}`
	editor, path, _ := checkedEditor(t, config)

	relay := vlessNode("relay", "192.0.2.10")
	relay["flow"] = "from-a-newer-sing-box"
	exit := vlessNode("exit", "192.0.2.21")
	exit["detour"] = "relay"
	result, err := editor.SyncOutbounds([]string{"relay", "exit", "other"}, []map[string]any{relay, exit, vlessNode("other", "192.0.2.22")})
	if err != nil {
		t.Fatalf("SyncOutbounds: %v", err)
	}
	if !reflect.DeepEqual(result.Tags, []string{"other", "exit", "relay"}) || len(result.Removed) != 0 || len(result.Skipped) != 2 {
		t.Fatalf("result = %+v", result)
	}
	cfg := load(t, path)
	if n := outboundByTag(t, cfg, "exit"); n == nil || n["detour"] != "relay" || n["server"] != "192.0.2.11" {
		t.Fatalf("exit = %v", n)
	}
	if outboundByTag(t, cfg, "relay") == nil || outboundByTag(t, cfg, "other")["server"] != "192.0.2.22" {
		t.Fatalf("outbounds = %v", cfg["outbounds"])
	}
}

// A held node keeps the relays its copy dials through, also when the
// provider no longer serves them: the new relay was refused, and the node
// chained through it with it. Removed, the old relays would take the held
// node's detour along, and it would dial its server directly — past the
// relay — while reported as not updated.
func TestHeldNodeKeepsItsRelays(t *testing.T) {
	config := `{"outbounds": [
    {"type": "selector", "tag": "proxy", "outbounds": ["relay0", "relay", "exit", "other", "direct"]},
    {"type": "vless", "tag": "relay0", "server": "192.0.2.9", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555555"},
    {"type": "vless", "tag": "relay", "server": "192.0.2.10", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555555", "detour": "relay0"},
    {"type": "vless", "tag": "exit", "server": "192.0.2.11", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555555", "Detour": "relay"},
    {"type": "vless", "tag": "other", "server": "192.0.2.12", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555555"},
    {"type": "direct", "tag": "direct"}
  ], "route": {"final": "proxy"}}`
	editor, path, _ := checkedEditor(t, config)

	relay2 := vlessNode("relay2", "192.0.2.30")
	relay2["flow"] = "from-a-newer-sing-box"
	exit := vlessNode("exit", "192.0.2.21")
	exit["detour"] = "relay2"
	result, err := editor.SyncOutbounds([]string{"relay0", "relay", "exit", "other"},
		[]map[string]any{relay2, exit, vlessNode("other", "192.0.2.22")})
	if err != nil {
		t.Fatalf("SyncOutbounds: %v", err)
	}
	if !reflect.DeepEqual(result.Tags, []string{"other", "exit", "relay", "relay0"}) || len(result.Removed) != 0 || len(result.Skipped) != 2 {
		t.Fatalf("result = %+v", result)
	}
	cfg := load(t, path)
	if n := outboundByTag(t, cfg, "exit"); n == nil || n["Detour"] != "relay" || n["server"] != "192.0.2.11" {
		t.Fatalf("exit = %v", n)
	}
	if n := outboundByTag(t, cfg, "relay"); n == nil || n["detour"] != "relay0" {
		t.Fatalf("relay = %v", n)
	}
	if outboundByTag(t, cfg, "relay0") == nil || outboundByTag(t, cfg, "other")["server"] != "192.0.2.22" {
		t.Fatalf("outbounds = %v", cfg["outbounds"])
	}

	// Once the provider's update of the node passes, the relays it no longer
	// needs go
	result, err = editor.SyncOutbounds(result.Tags, []map[string]any{vlessNode("exit", "192.0.2.21"), vlessNode("other", "192.0.2.22")})
	if err != nil {
		t.Fatalf("SyncOutbounds 2: %v", err)
	}
	if !reflect.DeepEqual(result.Removed, []string{"relay", "relay0"}) || len(result.Skipped) != 0 {
		t.Fatalf("result 2 = %+v", result)
	}
}

// A re-import decides a detour between two of its nodes the same whether the
// check refused the relay or not: E1 chained through R is the batch's chain
// (R is re-imported), and the batch now serves E1 without it; E2 chained
// through the DPI bypass is the user's, although the batch has a node named
// like it too (saved under another name, or refused)
func TestReimportChainNotDecidedByRefusal(t *testing.T) {
	config := `{"outbounds": [
    {"type": "selector", "tag": "proxy", "outbounds": ["R", "E1", "E2", "direct"]},
    {"type": "vless", "tag": "R", "server": "192.0.2.10", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555555"},
    {"type": "vless", "tag": "E1", "server": "192.0.2.11", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555555", "detour": "R"},
    {"type": "vless", "tag": "E2", "server": "192.0.2.12", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555555", "detour": "dpi-bypass"},
    {"type": "http", "tag": "dpi-bypass", "server": "127.0.0.1", "server_port": 3128},
    {"type": "direct", "tag": "direct"}
  ], "route": {"final": "proxy"}}`
	for name, flow := range map[string]string{"relays accepted": "", "relays refused": "from-a-newer-sing-box"} {
		t.Run(name, func(t *testing.T) {
			editor, path, _ := checkedEditor(t, config)
			relay := vlessNode("R", "192.0.2.20")
			namesake := vlessNode("dpi-bypass", "192.0.2.23")
			if flow != "" {
				relay["flow"] = flow
				namesake["flow"] = flow
			}
			result, err := editor.AddOutbounds([]map[string]any{relay, namesake, vlessNode("E1", "192.0.2.21"), vlessNode("E2", "192.0.2.22")}, nil)
			if err != nil {
				t.Fatalf("AddOutbounds: %v", err)
			}
			if flow != "" && (!reflect.DeepEqual(result.Tags, []string{"E1", "E2"}) || len(result.Skipped) != 2 || len(result.Renamed) != 0) {
				t.Fatalf("result = %+v", result)
			}
			cfg := load(t, path)
			if n := outboundByTag(t, cfg, "E1"); n["server"] != "192.0.2.21" || n["detour"] != nil {
				t.Fatalf("E1 = %v", n)
			}
			if n := outboundByTag(t, cfg, "E2"); n["server"] != "192.0.2.22" || n["detour"] != "dpi-bypass" {
				t.Fatalf("E2 = %v", n)
			}
		})
	}
}

// A chain between two nodes of a subscription is the provider's: when the
// provider takes it out (or turns it around), the node dials as served. A
// chain of the user's (the DPI bypass) stays.
func TestProviderChainFollowsTheProvider(t *testing.T) {
	path := writeConfig(t, `{"outbounds": [
    {"type": "selector", "tag": "proxy", "outbounds": ["direct"]},
    {"type": "http", "tag": "dpi-bypass", "server": "127.0.0.1", "server_port": 3128},
    {"type": "direct", "tag": "direct"}
  ], "route": {"final": "proxy"}}`)
	editor := New(path)
	chained := func(tag, detour string) map[string]any {
		o := vlessNode(tag, "192.0.2.10")
		o["server"] = tag + ".example.com"
		if detour != "" {
			o["detour"] = detour
		}
		return o
	}

	result, err := editor.SyncOutbounds(nil, []map[string]any{chained("A", "B"), chained("B", ""), chained("C", "")})
	if err != nil {
		t.Fatalf("sync 1: %v", err)
	}
	if err := editor.SetDetour("C", "dpi-bypass"); err != nil {
		t.Fatal(err)
	}

	// The provider turns the chain around: A direct, B through A
	result, err = editor.SyncOutbounds(result.Tags, []map[string]any{chained("A", ""), chained("B", "A"), chained("C", "")})
	if err != nil {
		t.Fatalf("sync 2: %v", err)
	}
	if !result.Changed || len(result.Skipped) != 0 {
		t.Fatalf("sync 2 = %+v", result)
	}
	cfg := load(t, path)
	if detour, has := outboundByTag(t, cfg, "A")["detour"]; has {
		t.Fatalf("A kept the chain the provider removed: %v", detour)
	}
	if outboundByTag(t, cfg, "B")["detour"] != "A" {
		t.Fatal("B lost the provider's chain")
	}
	if outboundByTag(t, cfg, "C")["detour"] != "dpi-bypass" {
		t.Fatal("the DPI chain was lost")
	}
}

// A node and its twin chained through another node of the provider are
// different nodes: renamed together (live counters) and served in another
// order, each keeps the user's choices that were its own
func TestRenamedTwinsPairByChain(t *testing.T) {
	path := writeConfig(t, `{"outbounds": [
    {"type": "selector", "tag": "proxy", "outbounds": ["X | 10GB", "X relay | 10GB", "relay", "direct"], "default": "X | 10GB"},
    {"type": "vless", "tag": "X | 10GB", "server": "192.0.2.10", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555555"},
    {"type": "vless", "tag": "X relay | 10GB", "server": "192.0.2.10", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555555", "detour": "relay"},
    {"type": "vless", "tag": "relay", "server": "192.0.2.20", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555555"},
    {"type": "direct", "tag": "direct"}
  ], "route": {"rules": [{"domain_suffix": [".example.org"], "outbound": "X | 10GB"}], "final": "proxy"}}`)

	viaRelay := vlessNode("X relay | 9GB", "192.0.2.10")
	viaRelay["detour"] = "relay"
	result, err := New(path).SyncOutbounds([]string{"X | 10GB", "X relay | 10GB", "relay"},
		[]map[string]any{viaRelay, vlessNode("X | 9GB", "192.0.2.10"), vlessNode("relay", "192.0.2.20")})
	if err != nil {
		t.Fatalf("SyncOutbounds: %v", err)
	}
	want := []domain.TagRename{{From: "X | 10GB", To: "X | 9GB"}, {From: "X relay | 10GB", To: "X relay | 9GB"}}
	if !reflect.DeepEqual(result.Renamed, want) {
		t.Fatalf("renamed = %+v", result.Renamed)
	}
	cfg := load(t, path)
	if def := outboundByTag(t, cfg, "proxy")["default"]; def != "X | 9GB" {
		t.Fatalf("default = %v", def)
	}
	if _, has := outboundByTag(t, cfg, "X | 9GB")["detour"]; has {
		t.Fatal("the direct twin got the chain")
	}
}
