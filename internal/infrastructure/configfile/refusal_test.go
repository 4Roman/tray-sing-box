package configfile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"tray-sing-box/internal/domain"
)

// fakeCheck imitates sing-box check the way it answers: an outbound with a
// flow other than "" or "xtls-rprx-vision" is refused with its position in
// the whole file; a uuid "bad-uuid-…" is refused while decoding, quoting the
// value and the path of the file under check, and so is a key "zz_…" (an
// option of a newer sing-box); the flow "crash" crashes it (a Go panic: no
// position, a stack trace).
type fakeCheck struct {
	calls int
}

func (f *fakeCheck) validate(raw []byte) error {
	f.calls++
	var cfg struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return err
	}
	for i, o := range cfg.Outbounds {
		flow, _ := o["flow"].(string)
		uuid, _ := o["uuid"].(string)
		switch {
		case flow == "crash":
			return fmt.Errorf("sing-box check: panic: runtime error: index out of range [8] with length 8\n\ngoroutine 1 [running]:\nencoding/hex.Decode({0x3e3d240d7c8?})\n\tencoding/hex/hex.go:101 +0x105")
		case flow != "" && flow != "xtls-rprx-vision":
			return fmt.Errorf("sing-box check: FATAL[0000] initialize outbound[%d]: unsupported flow: %s", i, flow)
		case strings.HasPrefix(uuid, "bad-uuid-"):
			return fmt.Errorf("sing-box check: FATAL[0000] decode config at C:\\data\\.singbox-check-4242.json: outbounds[%d].uuid: invalid uuid: %s", i, uuid)
		}
		for k := range o {
			if strings.HasPrefix(k, "zz_") {
				return fmt.Errorf("sing-box check: FATAL[0000] decode config at C:\\data\\.singbox-check-4242.json: outbounds[%d].%s: json: unknown field %q", i, k, k)
			}
		}
	}
	return nil
}

func node(tag, flow string) map[string]any {
	o := map[string]any{"type": "vless", "tag": tag, "server": tag + ".example.com", "server_port": 443,
		"uuid": "11111111-2222-4333-8444-555555555555"}
	if flow != "" {
		o["flow"] = flow
	}
	return o
}

func checkedEditor(t *testing.T, config string) (*Editor, string, *fakeCheck) {
	t.Helper()
	path := writeConfig(t, config)
	check := &fakeCheck{}
	editor := New(path)
	editor.SetValidator(check.validate)
	return editor, path, check
}

// One node sing-box refuses costs only that node: the others are saved, the
// refused one is named with sing-box's reason (not its position in the file)
func TestAddOutboundsLeavesOutRefused(t *testing.T) {
	editor, path, check := checkedEditor(t, sampleConfig)

	result, err := editor.AddOutbounds([]map[string]any{
		node("good-1", "xtls-rprx-vision"), node("bad", "xtls-rprx-vision-udp443"), node("good-2", ""), node("good-3", ""),
	}, nil)
	if err != nil {
		t.Fatalf("AddOutbounds: %v", err)
	}
	if !reflect.DeepEqual(result.Tags, []string{"good-1", "good-2", "good-3"}) || !result.Changed {
		t.Fatalf("result = %+v", result)
	}
	want := []domain.SkippedNode{{Name: "bad", Reason: "sing-box не принимает: unsupported flow: xtls-rprx-vision-udp443"}}
	if !reflect.DeepEqual(result.Skipped, want) {
		t.Fatalf("skipped = %+v", result.Skipped)
	}
	// The whole config, the new nodes together, then (without "bad") together
	// again and the whole config: four sing-box runs, not one per node
	if check.calls != 4 {
		t.Fatalf("validator ran %d times, want 4", check.calls)
	}

	cfg := load(t, path)
	if outboundByTag(t, cfg, "bad") != nil || outboundByTag(t, cfg, "good-3") == nil {
		t.Fatalf("outbounds = %v", cfg["outbounds"])
	}
	for _, m := range outboundByTag(t, cfg, "proxy")["outbounds"].([]any) {
		if m == "bad" {
			t.Fatal("the refused node was registered in the selector")
		}
	}
}

// When every node is refused nothing is saved
func TestAddOutboundsAllRefused(t *testing.T) {
	editor, path, _ := checkedEditor(t, sampleConfig)

	result, err := editor.AddOutbounds([]map[string]any{node("bad-1", "x"), node("bad-2", "y")}, nil)
	if err != nil {
		t.Fatalf("AddOutbounds: %v", err)
	}
	if len(result.Tags) != 0 || len(result.Skipped) != 2 || result.Changed {
		t.Fatalf("result = %+v", result)
	}
	raw, _ := os.ReadFile(path)
	if !bytes.Equal(raw, []byte(sampleConfig)) {
		t.Fatal("config changed although every node was refused")
	}
	if _, err := os.Stat(path + ".bak"); !os.IsNotExist(err) {
		t.Fatal("backup written although nothing was saved")
	}
}

// A refusal that is not about the new nodes is returned, naming the
// outbound by tag instead of its position among all outbounds of the file
func TestCheckErrorNamesTheOutbound(t *testing.T) {
	broken := strings.Replace(sampleConfig, `"tag": "old-node",`, `"tag": "old-node", "flow": "weird",`, 1)
	editor, _, _ := checkedEditor(t, broken)

	_, err := editor.AddOutbounds([]map[string]any{node("good", "")}, nil)
	if err == nil {
		t.Fatal("a config sing-box refuses was saved")
	}
	msg := err.Error()
	if !strings.Contains(msg, "outbound «old-node»: unsupported flow: weird") ||
		strings.Contains(msg, "outbound[") || strings.Contains(msg, "FATAL") {
		t.Fatalf("error = %q", msg)
	}
}

// sing-box's reasons may quote a value: a credential never passes, nor the
// path of the file under check
func TestRefusalReasonHidesSecrets(t *testing.T) {
	editor, _, _ := checkedEditor(t, sampleConfig)

	bad := node("bad", "")
	bad["uuid"] = "bad-uuid-secretvalue"
	result, err := editor.AddOutbounds([]map[string]any{node("good", ""), bad}, nil)
	if err != nil {
		t.Fatalf("AddOutbounds: %v", err)
	}
	if len(result.Skipped) != 1 {
		t.Fatalf("skipped = %+v", result.Skipped)
	}
	reason := result.Skipped[0].Reason
	if strings.Contains(reason, "secretvalue") || strings.Contains(reason, "singbox-check") ||
		!strings.Contains(reason, "uuid: invalid uuid: "+SecretPlaceholder) {
		t.Fatalf("reason = %q", reason)
	}

	// The same in an error about the whole config
	existing := strings.Replace(sampleConfig, `"tag": "old-node",`, `"tag": "old-node", "uuid": "bad-uuid-othersecret",`, 1)
	editor, _, _ = checkedEditor(t, existing)
	_, err = editor.AddOutbounds([]map[string]any{node("good", "")}, nil)
	if err == nil || strings.Contains(err.Error(), "othersecret") || !strings.Contains(err.Error(), "outbound «old-node».uuid") {
		t.Fatalf("error = %v", err)
	}
}

// A crash names no outbound: the nodes are then checked in halves, and the
// reason is the first line of the crash, not its stack
func TestCrashIsCheckedOneByOne(t *testing.T) {
	editor, _, _ := checkedEditor(t, sampleConfig)

	result, err := editor.AddOutbounds([]map[string]any{node("good-1", ""), node("crashing", "crash"), node("good-2", "")}, nil)
	if err != nil {
		t.Fatalf("AddOutbounds: %v", err)
	}
	want := []domain.SkippedNode{{Name: "crashing", Reason: "sing-box не принимает: panic: runtime error: index out of range [8] with length 8"}}
	if !reflect.DeepEqual(result.Skipped, want) || !reflect.DeepEqual(result.Tags, []string{"good-1", "good-2"}) {
		t.Fatalf("result = %+v", result)
	}
}

// A crashing node among many costs a few checks, not one per node: a
// subscription of hundreds would hold the app's lock for minutes
func TestCrashAmongManyIsBisected(t *testing.T) {
	editor, _, check := checkedEditor(t, sampleConfig)

	var nodes []map[string]any
	for i := 0; i < 64; i++ {
		nodes = append(nodes, node(fmt.Sprintf("good-%d", i), ""))
	}
	nodes = append(nodes[:40:40], append([]map[string]any{node("crashing", "crash")}, nodes[40:]...)...)
	result, err := editor.AddOutbounds(nodes, nil)
	if err != nil {
		t.Fatalf("AddOutbounds: %v", err)
	}
	if len(result.Tags) != 64 || len(result.Skipped) != 1 || result.Skipped[0].Name != "crashing" {
		t.Fatalf("result: %d saved, skipped %+v", len(result.Tags), result.Skipped)
	}
	// The merge, the batch, two halves per level down to the node, the retry
	if check.calls > 20 {
		t.Fatalf("validator ran %d times for one crashing node among 65", check.calls)
	}
}

// Halving pays off for a few crashing nodes; with most nodes crashing it
// would cost two checks per node (each a sing-box start under the app's
// lock). The rounds that narrow nothing down are bounded: at most one check
// per node plus a few rounds.
func TestManyCrashesCostAboutOneCheckEach(t *testing.T) {
	for _, crashing := range []int{64, 20, 3} {
		t.Run(fmt.Sprint(crashing), func(t *testing.T) {
			editor, _, check := checkedEditor(t, sampleConfig)

			var nodes []map[string]any
			for i := 0; i < 64; i++ {
				flow := ""
				if i*crashing/64 != (i+1)*crashing/64 {
					flow = "crash"
				}
				nodes = append(nodes, node(fmt.Sprintf("node-%d", i), flow))
			}
			nodes = append(nodes, node("good", ""))
			result, err := editor.AddOutbounds(nodes, nil)
			if err != nil {
				t.Fatalf("AddOutbounds: %v", err)
			}
			if len(result.Skipped) != crashing || len(result.Tags) != 65-crashing {
				t.Fatalf("result: %d saved, %d skipped", len(result.Tags), len(result.Skipped))
			}
			for _, sk := range result.Skipped {
				if !strings.HasPrefix(sk.Reason, "sing-box не принимает: panic:") {
					t.Fatalf("skipped %+v", sk)
				}
			}
			// The merge and its retry, the first check of all of them, one
			// check per node checked alone, and two checks for each of the
			// halving rounds that narrowed nothing down: 2 × log2(65) + 2
			if limit := 3 + 65 + 2*(2*7+2); check.calls > limit {
				t.Fatalf("validator ran %d times for %d crashing nodes among 65, want at most %d", check.calls, crashing, limit)
			}
		})
	}
}

// A few crashing nodes among many, in a run (one template with a broken
// option) or scattered: halving finds them in a few rounds each, as long as
// a round narrows something down. Only rounds with crashes in both halves
// use up the budget — spending it on the first few crashes made a run of 16
// among 201 cost 221 checks instead of 43.
func TestFewCrashesAmongManyStayCheap(t *testing.T) {
	for _, tc := range []struct {
		name  string
		crash []int // the crashing nodes among 200
		limit int
	}{
		{"run of 16", []int{90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105}, 50},
		{"3 scattered", []int{17, 118, 181}, 45},
		{"5 scattered", []int{3, 61, 99, 142, 197}, 70},
		{"8 spread", []int{12, 37, 62, 87, 112, 137, 162, 187}, 105},
	} {
		t.Run(tc.name, func(t *testing.T) {
			editor, _, check := checkedEditor(t, sampleConfig)
			crash := map[int]bool{}
			for _, i := range tc.crash {
				crash[i] = true
			}
			var nodes []map[string]any
			for i := 0; i < 200; i++ {
				flow := ""
				if crash[i] {
					flow = "crash"
				}
				nodes = append(nodes, node(fmt.Sprintf("node-%d", i), flow))
			}
			nodes = append(nodes, node("good", ""))
			result, err := editor.AddOutbounds(nodes, nil)
			if err != nil {
				t.Fatalf("AddOutbounds: %v", err)
			}
			if len(result.Skipped) != len(tc.crash) || len(result.Tags) != 201-len(tc.crash) {
				t.Fatalf("result: %d saved, %d skipped", len(result.Tags), len(result.Skipped))
			}
			if check.calls > tc.limit {
				t.Fatalf("validator ran %d times, want at most %d", check.calls, tc.limit)
			}
		})
	}
}

// A provider serving an option of a newer sing-box in every node: the nodes
// of one type with the same unknown key are refused together, with the same
// reason — one round, not one check per node
func TestUnknownFieldRefusedTogether(t *testing.T) {
	editor, path, check := checkedEditor(t, sampleConfig)

	var nodes []map[string]any
	for i := 0; i < 30; i++ {
		n := node(fmt.Sprintf("newer-%d", i), "")
		n["zz_newer"] = true
		nodes = append(nodes, n)
	}
	nodes = append(nodes, node("good", ""))
	result, err := editor.AddOutbounds(nodes, nil)
	if err != nil {
		t.Fatalf("AddOutbounds: %v", err)
	}
	if !reflect.DeepEqual(result.Tags, []string{"good"}) || len(result.Skipped) != 30 {
		t.Fatalf("result: %v, skipped %d", result.Tags, len(result.Skipped))
	}
	for _, sk := range result.Skipped {
		if sk.Reason != `sing-box не принимает: zz_newer: json: unknown field "zz_newer"` {
			t.Fatalf("skipped %+v", sk)
		}
	}
	if check.calls > 5 {
		t.Fatalf("validator ran %d times for 30 nodes with one unknown field", check.calls)
	}
	if outboundByTag(t, load(t, path), "good") == nil {
		t.Fatal("the good node was not saved")
	}

	// Only the same type: another type may know the key
	if sameUnknownField(map[string]any{"type": "trojan", "zz_newer": true}, nodes[0], "zz_newer") ||
		!sameUnknownField(nodes[1], nodes[0], "zz_newer") || sameUnknownField(nodes[30], nodes[0], "zz_newer") {
		t.Fatal("sameUnknownField")
	}
}

// What the guard refuses in one node costs only that node too
func TestGuardRefusalLeavesOutOne(t *testing.T) {
	path := writeSample(t)
	risky := node("risky", "")
	risky["tls"] = map[string]any{"enabled": true, "certificate_path": "ca.pem"}

	result, err := New(path).AddOutbounds([]map[string]any{node("good", ""), risky}, nil)
	if err != nil {
		t.Fatalf("AddOutbounds: %v", err)
	}
	if !reflect.DeepEqual(result.Tags, []string{"good"}) || len(result.Skipped) != 1 ||
		result.Skipped[0].Name != "risky" || !strings.HasPrefix(result.Skipped[0].Reason, "приложение не добавляет") {
		t.Fatalf("result = %+v", result)
	}
	if outboundByTag(t, load(t, path), "risky") != nil {
		t.Fatal("the refused node was saved")
	}
}

// A selector default outside the members passes sing-box check, and sing-box
// then does not start: refused when a save brings it, kept when it was there
func TestSelectorDefaultOutsideMembers(t *testing.T) {
	path := writeSample(t)
	editor := New(path)

	err := editor.WriteSection("outbounds", []byte(`[
    {"type": "selector", "tag": "proxy", "outbounds": ["old-node", "direct"], "default": "gone"},
    {"type": "vless", "tag": "old-node", "server": "old.example.com", "server_port": 443},
    {"type": "direct", "tag": "direct"}
  ]`))
	if err == nil || !strings.Contains(err.Error(), "«proxy»") || !strings.Contains(err.Error(), "«gone»") {
		t.Fatalf("dangling default saved: %v", err)
	}
	if err := editor.WriteSection("outbounds", []byte(`[
    {"type": "selector", "tag": "proxy", "outbounds": ["old-node", "direct"], "default": "old-node"},
    {"type": "vless", "tag": "old-node", "server": "old.example.com", "server_port": 443},
    {"type": "direct", "tag": "direct"}
  ]`)); err != nil {
		t.Fatalf("a valid default refused: %v", err)
	}

	// One the config already has does not block other saves
	dangling := strings.Replace(sampleConfig, `"outbounds": ["old-node", "direct"]}`, `"outbounds": ["old-node", "direct"], "default": "gone"}`, 1)
	if err := New(writeConfig(t, dangling)).AddOutbound(node("new", "")); err != nil {
		t.Fatalf("an existing dangling default blocked an import: %v", err)
	}
}

func TestCheckMessage(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"sing-box check: FATAL[0000] initialize outbound[2]: unsupported flow: x", "initialize outbound[2]: unsupported flow: x"},
		{"sing-box check: WARN[0000] something is deprecated\nFATAL[0000] initialize outbound[0]: nope", "initialize outbound[0]: nope"},
		{`sing-box check: FATAL[0000] decode config at C:\d\.singbox-check-1.json: outbounds[1].encryption: json: unknown field "encryption"`,
			`outbounds[1].encryption: json: unknown field "encryption"`},
		{"sing-box check: panic: boom\n\ngoroutine 1 [running]:\nmain.main()", "panic: boom"},
		{"exit status 1", "exit status 1"},
	} {
		if got := checkMessage(tc.in); got != tc.want {
			t.Errorf("checkMessage(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
