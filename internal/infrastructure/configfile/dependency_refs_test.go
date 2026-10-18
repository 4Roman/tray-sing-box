package configfile

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// startRefsConfig names an outbound, a rule set or a shared HTTP client from
// every place sing-box looks one up only when it starts
const startRefsConfig = `{
  "http_clients": [{"tag": "shared", "detour": "A"}],
  "outbounds": [
    {"type": "selector", "tag": "proxy", "outbounds": ["A", "direct"]},
    {"type": "vless", "tag": "A", "server": "192.0.2.10", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555555"},
    {"type": "direct", "tag": "direct"}
  ],
  "endpoints": [{"type": "wireguard", "tag": "wg"}],
  "route": {
    "rules": [
      {"rule_set": "ads", "action": "reject"},
      {"type": "logical", "mode": "or", "rules": [{"rule_set": ["geoip-ru", "geosite-ru"]}, {"preferred_by": "wg"}], "outbound": "direct"}
    ],
    "rule_set": [
      {"type": "remote", "tag": "ads", "format": "binary", "url": "https://rules.example.com/ads.srs", "download_detour": "A"},
      {"type": "remote", "tag": ["geoip-ru", "geosite-ru"], "format": "binary", "url": "https://rules.example.com/{tag}.srs", "http_client": {"detour": "A"}},
      {"type": "remote", "tag": "cn", "format": "binary", "url": "https://rules.example.com/cn.srs", "http_client": "shared"}
    ],
    "default_http_client": "shared",
    "final": "proxy"
  }
}`

// The references sing-box resolves only when it starts — sing-box check
// passes them all — to a rule set (a route rule's rule_set, also inside a
// logical rule), to an outbound (a route rule's preferred_by, the download
// detour of a rule set, the detour of a shared HTTP client) and to a shared
// HTTP client (a rule set's http_client given by tag, the default one). Keys
// in every spelling sing-box reads as them, lists where sing-box takes a list.
func TestStartReferenceProblems(t *testing.T) {
	const outbounds = `"outbounds": [{"type": "vless", "tag": "A", "server": "192.0.2.10", "server_port": 443}, {"type": "direct", "tag": "direct"}], "endpoints": [{"type": "wireguard", "tag": "wg"}]`
	const ads = `{"type": "remote", "tag": "ads", "format": "binary", "url": "https://rules.example.com/ads.srs"}`
	for name, tc := range map[string]struct {
		config string
		want   []string
	}{
		"everything present": {startRefsConfig, nil},
		"rule set": {
			`{` + outbounds + `, "route": {"rules": [{"rule_set": "gone", "action": "reject"}]}}`,
			[]string{"rule_set правила маршрутизации указывает на «gone», а такого rule-set нет"},
		},
		"rule set in a list": {
			`{` + outbounds + `, "route": {"rules": [{"rule_set": ["ads", "gone"], "outbound": "direct"}], "rule_set": [` + ads + `]}}`,
			[]string{"rule_set правила маршрутизации указывает на «gone», а такого rule-set нет"},
		},
		"rule set of a logical rule": {
			`{` + outbounds + `, "route": {"rules": [{"type": "logical", "mode": "and", "rules": [{"rule_set": "gone"},
			  {"type": "logical", "mode": "or", "rules": [{"rule_set": ["deeper"]}, {"network": "udp"}]}], "outbound": "direct"}]}}`,
			[]string{
				"rule_set правила маршрутизации указывает на «gone», а такого rule-set нет",
				"rule_set правила маршрутизации указывает на «deeper», а такого rule-set нет",
			},
		},
		"rule set spelled otherwise": {
			`{` + outbounds + `, "Route": {"Rules": [{"Rule_Set": "gone", "action": "reject"},
			  {"type": "logical", "mode": "and", "RULES": [{"RULE_SET": ["ads"]}, {"network": "udp"}], "outbound": "direct"}],
			  "Rule_Set": [{"type": "remote", "Tag": "ads", "format": "binary", "url": "https://rules.example.com/ads.srs"}]}}`,
			[]string{"rule_set правила маршрутизации указывает на «gone», а такого rule-set нет"},
		},
		// sing-box reads "" in a list as one more tag to look up, never found
		"empty rule set name": {
			`{` + outbounds + `, "route": {"rules": [{"rule_set": ["ads", ""], "outbound": "direct"}, {"rule_set": "", "action": "reject"}], "rule_set": [` + ads + `]}}`,
			[]string{"rule_set правила маршрутизации указывает на пустое имя, а rule-set без имени не бывает"},
		},
		"empty preferred_by name": {
			`{` + outbounds + `, "route": {"rules": [{"preferred_by": [""], "outbound": "direct"}]}}`,
			[]string{"preferred_by правила маршрутизации указывает на пустое имя, а outbound без имени не бывает"},
		},
		// Where a field holds one tag, "" is not set: no problem
		"empty single tags": {
			`{` + outbounds + `, "route": {"final": "", "default_http_client": "", "rule_set": [{"type": "remote", "tag": "ads", "format": "binary", "url": "https://rules.example.com/ads.srs", "download_detour": ""}]}}`,
			nil,
		},
		"rule set tagged by a list": {
			`{` + outbounds + `, "route": {"rules": [{"rule_set": "geosite-ru", "outbound": "direct"}],
			  "rule_set": [{"type": "remote", "tag": ["geoip-ru", "geosite-ru"], "format": "binary", "url": "https://rules.example.com/{tag}.srs"}]}}`,
			nil,
		},
		"preferred_by": {
			`{` + outbounds + `, "route": {"rules": [{"preferred_by": ["wg", "gone"], "outbound": "direct"}]}}`,
			[]string{"preferred_by правила маршрутизации указывает на «gone», а такого outbound нет"},
		},
		"preferred_by of a logical rule, spelled otherwise": {
			`{` + outbounds + `, "route": {"rules": [{"type": "logical", "mode": "or", "Rules": [{"Preferred_By": "gone"}, {"network": "udp"}], "outbound": "direct"}]}}`,
			[]string{"preferred_by правила маршрутизации указывает на «gone», а такого outbound нет"},
		},
		"download detour": {
			`{` + outbounds + `, "route": {"rule_set": [{"type": "remote", "tag": "ads", "format": "binary", "url": "https://rules.example.com/ads.srs", "Download_Detour": "gone"}]}}`,
			[]string{"download_detour rule-set «ads» указывает на «gone», а такого outbound нет"},
		},
		"the rule set's own HTTP client": {
			`{` + outbounds + `, "route": {"rule_set": [{"type": "remote", "tag": ["geoip-ru", "geosite-ru"], "format": "binary", "url": "https://rules.example.com/{tag}.srs",
			  "Http_Client": {"version": 2, "Detour": "gone"}}]}}`,
			[]string{"http_client.detour rule-set «geoip-ru», «geosite-ru» указывает на «gone», а такого outbound нет"},
		},
		"a shared HTTP client by tag": {
			`{` + outbounds + `, "http_clients": [{"tag": "shared"}], "route": {"rule_set": [{"type": "remote", "tag": "ads", "format": "binary", "url": "https://rules.example.com/ads.srs", "http_client": "gone"},
			  {"type": "remote", "tag": "cn", "format": "binary", "url": "https://rules.example.com/cn.srs", "http_client": "shared"}]}}`,
			[]string{"http_client rule-set «ads» указывает на «gone», а такого http_client нет"},
		},
		"default HTTP client": {
			`{` + outbounds + `, "HTTP_Clients": [{"Tag": "shared"}], "route": {"Default_HTTP_Client": "gone"}}`,
			[]string{"route.default_http_client указывает на «gone», а такого http_client нет"},
		},
		"default HTTP client present": {`{` + outbounds + `, "HTTP_Clients": [{"Tag": "shared"}], "route": {"default_http_client": "shared"}}`, nil},
		"shared HTTP client's detour": {
			`{` + outbounds + `, "Http_Clients": [{"tag": "fine", "detour": "A"}, {"tag": "shared", "Detour": "gone"}],
			  "route": {"rule_set": [{"type": "remote", "tag": "ads", "format": "binary", "url": "https://rules.example.com/ads.srs", "Http_Client": "shared"}]}}`,
			[]string{"detour http_client «shared» указывает на «gone», а такого outbound нет"},
		},
		// A rule set with neither an http_client nor a download_detour
		// downloads through the default client: the first one, or the one
		// route.default_http_client names
		"default HTTP client's detour": {
			`{` + outbounds + `, "http_clients": [{"tag": "first", "detour": "gone"}, {"tag": "second", "detour": "gone too"}],
			  "route": {"rule_set": [{"type": "remote", "tag": "ads", "format": "binary", "url": "https://rules.example.com/ads.srs", "http_client": ""}]}}`,
			[]string{"detour http_client «first» указывает на «gone», а такого outbound нет"},
		},
		"named default HTTP client's detour": {
			`{` + outbounds + `, "http_clients": [{"tag": "first", "detour": "gone"}, {"tag": "second", "detour": "gone too"}],
			  "route": {"rule_set": [` + ads + `], "Default_HTTP_Client": "second"}}`,
			[]string{"detour http_client «second» указывает на «gone too», а такого outbound нет"},
		},
		// sing-box looks a client's detour up at its first dial: a client no
		// rule set downloads through — none names it, none falls back to the
		// default one (it has a client or a download detour of its own, or
		// downloads nothing) — cannot fail the start
		"HTTP clients no rule set downloads through": {
			`{` + outbounds + `, "http_clients": [{"tag": "main", "detour": "gone"}, {"tag": "spare", "detour": "gone"}],
			  "route": {"rule_set": [
			    {"type": "remote", "tag": "own", "format": "binary", "url": "https://rules.example.com/own.srs", "http_client": {}},
			    {"type": "remote", "tag": "legacy", "format": "binary", "url": "https://rules.example.com/legacy.srs", "download_detour": "A"},
			    {"type": "local", "tag": "file", "format": "binary", "path": "file.srs"},
			    {"tag": "inline", "rules": [{"domain_suffix": [".example.org"]}]}]}}`,
			nil,
		},
		"DNS rule": {
			`{` + outbounds + `, "dns": {"servers": [{"type": "local", "tag": "local"}], "rules": [{"type": "logical", "mode": "and", "rules": [{"Rule_Set": "gone"}, {"network": "udp"}], "server": "local"}]}}`,
			[]string{"rule_set правила DNS указывает на «gone», а такого rule-set нет"},
		},
		// A route rule sending traffic to a missing outbound fails only the
		// connections it matches; a detour through a direct outbound depends
		// on the version and is not the check's business
		"not a start failure": {
			`{` + outbounds + `, "route": {"rules": [{"domain_suffix": [".example.org"], "outbound": "gone"}],
			  "rule_set": [{"type": "remote", "tag": "ads", "format": "binary", "url": "https://rules.example.com/ads.srs", "http_client": {"detour": "direct"}}]}}`,
			nil,
		},
	} {
		t.Run(name, func(t *testing.T) {
			var got []string
			for _, p := range referenceProblems(decode(t, tc.config)) {
				got = append(got, p.String())
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("problems = %q, want %q", got, tc.want)
			}
		})
	}
}

// A save that would add one of them is refused, naming it — from the
// outbounds section (an outbound renamed), from the route section (a rule
// set removed, a rule added) and in a first config
func TestStartReferenceProblemsRefused(t *testing.T) {
	path := writeConfig(t, startRefsConfig)
	renamed := `[
    {"type": "selector", "tag": "proxy", "outbounds": ["B", "direct"]},
    {"type": "vless", "tag": "B", "server": "192.0.2.10", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555555"},
    {"type": "direct", "tag": "direct"}
  ]`
	err := New(path).WriteSection("outbounds", []byte(renamed))
	if err == nil {
		t.Fatal("saved")
	}
	for _, want := range []string{
		"download_detour rule-set «ads» указывает на «A», а такого outbound нет",
		"http_client.detour rule-set «geoip-ru», «geosite-ru» указывает на «A», а такого outbound нет",
		"detour http_client «shared» указывает на «A», а такого outbound нет",
		"sing-box не запустится (sing-box check этого не замечает)",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %q, want it to say %q", err, want)
		}
	}
	if !refusal(err) {
		t.Fatal("not a refusal")
	}
	if outboundByTag(t, load(t, path), "A") == nil {
		t.Fatal("the config was written")
	}

	// A rule set still in use removed, a rule naming nothing added
	route := `{
    "rules": [
      {"rule_set": "ads", "action": "reject"},
      {"type": "logical", "mode": "or", "rules": [{"rule_set": ["geoip-ru", "geosite-ru"]}, {"preferred_by": ["wg", "wg2"]}], "outbound": "direct"}
    ],
    "rule_set": [
      {"type": "remote", "tag": ["geoip-ru", "geosite-ru"], "format": "binary", "url": "https://rules.example.com/{tag}.srs", "http_client": {"detour": "A"}},
      {"type": "remote", "tag": "cn", "format": "binary", "url": "https://rules.example.com/cn.srs", "http_client": "other"}
    ],
    "default_http_client": "shared",
    "final": "proxy"
  }`
	err = New(path).WriteSection("route", []byte(route))
	if err == nil {
		t.Fatal("route saved")
	}
	for _, want := range []string{
		"rule_set правила маршрутизации указывает на «ads», а такого rule-set нет",
		"preferred_by правила маршрутизации указывает на «wg2», а такого outbound нет",
		"http_client rule-set «cn» указывает на «other», а такого http_client нет",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("route: error = %q, want it to say %q", err, want)
		}
	}

	// The first config too
	err = New(filepath.Join(t.TempDir(), "config.json")).CreateConfig([]byte(`{"outbounds": [{"type": "direct", "tag": "direct"}],
	  "route": {"rules": [{"rule_set": "geosite-ru", "outbound": "direct"}]}}`))
	if err == nil || !strings.Contains(err.Error(), "rule_set правила маршрутизации указывает на «geosite-ru»") {
		t.Fatalf("CreateConfig: %v", err)
	}
}

// A shared HTTP client no rule set downloads through does not stand in the
// way of deleting the outbound it dials through on the settings page (the
// page cannot edit http_clients; sing-box starts without it). A rule set
// made to download through that client afterwards is refused.
func TestUnusedHTTPClientDetourAllowed(t *testing.T) {
	path := writeConfig(t, `{
  "http_clients": [{"tag": "main"}, {"tag": "spare", "detour": "old"}],
  "outbounds": [
    {"type": "vless", "tag": "old", "server": "192.0.2.10", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555555"},
    {"type": "direct", "tag": "direct"}
  ],
  "route": {"rule_set": [{"type": "remote", "tag": "ads", "format": "binary", "url": "https://rules.example.com/ads.srs"}], "final": "direct"}
}`)
	if err := New(path).WriteSection("outbounds", []byte(`[{"type": "direct", "tag": "direct"}]`)); err != nil {
		t.Fatalf("an outbound only an unused HTTP client dials through, deleted: %v", err)
	}
	err := New(path).WriteSection("route", []byte(`{"rule_set": [{"type": "remote", "tag": "ads", "format": "binary",
	  "url": "https://rules.example.com/ads.srs", "http_client": "spare"}], "final": "direct"}`))
	if err == nil || !strings.Contains(err.Error(), "detour http_client «spare» указывает на «old», а такого outbound нет") {
		t.Fatalf("a rule set made to download through that client: %v", err)
	}
}

// A problem the previous config had stays allowed wherever it moves — the
// rules reordered, a rule moved into a logical one — and does not block
// other saves; a new one in the same save is refused, alone
func TestStartReferenceProblemsKept(t *testing.T) {
	const had = `{
  "http_clients": [{"tag": "shared", "detour": "gone"}],
  "outbounds": [
    {"type": "selector", "tag": "proxy", "outbounds": ["A", "direct"]},
    {"type": "vless", "tag": "A", "server": "192.0.2.10", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555555"},
    {"type": "direct", "tag": "direct"}
  ],
  "route": {
    "rules": [
      {"rule_set": "missing-set", "action": "reject"},
      {"domain_suffix": [".example.org"], "outbound": "direct"},
      {"preferred_by": "missing-wg", "outbound": "direct"}
    ],
    "rule_set": [
      {"type": "remote", "tag": "ads", "format": "binary", "url": "https://rules.example.com/ads.srs", "download_detour": "gone"},
      {"type": "remote", "tag": "cn", "format": "binary", "url": "https://rules.example.com/cn.srs", "http_client": {"detour": "gone"}},
      {"type": "remote", "tag": "fb", "format": "binary", "url": "https://rules.example.com/fb.srs", "http_client": "shared"}
    ],
    "default_http_client": "missing-client",
    "final": "proxy"
  }
}`
	path := writeConfig(t, had)
	if err := New(path).AddOutbound(node("new", "")); err != nil {
		t.Fatalf("an existing problem blocked an import: %v", err)
	}

	moved := `{
    "rules": [
      {"type": "logical", "mode": "or", "rules": [{"preferred_by": ["missing-wg"]}, {"network": "udp"}], "outbound": "direct"},
      {"domain_suffix": [".example.org"], "outbound": "direct"},
      {"type": "logical", "mode": "and", "rules": [{"rule_set": ["missing-set"]}, {"network": "tcp"}], "action": "reject"}
    ],
    "rule_set": [
      {"type": "remote", "tag": "fb", "format": "binary", "url": "https://rules.example.com/fb.srs", "http_client": "shared"},
      {"type": "remote", "tag": "cn", "format": "binary", "url": "https://rules.example.com/cn.srs", "http_client": {"detour": "gone"}},
      {"type": "remote", "tag": "ads", "format": "binary", "url": "https://rules.example.com/ads.srs", "download_detour": "gone"}
    ],
    "default_http_client": "missing-client",
    "final": "proxy"
  }`
	if err := New(path).WriteSection("route", []byte(moved)); err != nil {
		t.Fatalf("the problems the config had, moved, refused: %v", err)
	}

	added := strings.Replace(moved, `{"network": "tcp"}`, `{"rule_set": "missing-too"}`, 1)
	err := New(path).WriteSection("route", []byte(added))
	if err == nil {
		t.Fatal("a new problem saved")
	}
	if !strings.Contains(err.Error(), "«missing-too»") || strings.Contains(err.Error(), "«missing-set»") ||
		strings.Contains(err.Error(), "«gone»") || strings.Contains(err.Error(), "«missing-client»") {
		t.Fatalf("error = %q, want it to name the new problem alone", err)
	}

	// The same name missing as something else is another problem
	for _, other := range []struct{ from, to, want string }{
		{`{"network": "tcp"}`, `{"preferred_by": "missing-set"}`, "preferred_by правила маршрутизации указывает на «missing-set»"},
		{`"http_client": {"detour": "gone"}`, `"http_client": "gone"`, "http_client rule-set «cn» указывает на «gone», а такого http_client нет"},
		{`"final": "proxy"`, `"final": "missing-client"`, "route.final указывает на «missing-client»"},
	} {
		err := New(path).WriteSection("route", []byte(strings.Replace(moved, other.from, other.to, 1)))
		if err == nil || !strings.Contains(err.Error(), other.want) {
			t.Fatalf("%s: %v", other.to, err)
		}
	}
}

// A DNS rule naming a missing rule set sing-box check refuses as well: the
// refusal names it without claiming check would not notice
func TestStartReferenceProblemsCheckNotices(t *testing.T) {
	dns := `"dns": {"servers": [{"type": "local", "tag": "local"}], "rules": [{"rule_set": "gone", "server": "local"}]}`
	err := checkDependencies(nil, decode(t, `{"outbounds": [{"type": "direct", "tag": "direct"}], `+dns+`}`))
	if err == nil || !strings.HasSuffix(err.Error(), "rule_set правила DNS указывает на «gone», а такого rule-set нет — с таким конфигом sing-box не запустится") {
		t.Fatalf("DNS rule: %v", err)
	}
	err = checkDependencies(nil, decode(t, `{"outbounds": [{"type": "direct", "tag": "direct"}], `+dns+`, "route": {"final": "nowhere"}}`))
	if err == nil || !strings.HasSuffix(err.Error(), "(sing-box check этого не замечает)") {
		t.Fatalf("with a problem check misses: %v", err)
	}
}

const syncDownloadConfig = `{
  "outbounds": [
    {"type": "selector", "tag": "proxy", "outbounds": ["sub-a", "sub-b", "direct"]},
    {"type": "vless", "tag": "sub-a", "server": "192.0.2.10", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555555"},
    {"type": "vless", "tag": "sub-b", "server": "192.0.2.11", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555555"},
    {"type": "direct", "tag": "direct"}
  ],
  "route": {
    "rule_set": [
      {"type": "remote", "tag": "ads", "format": "binary", "url": "https://rules.example.com/ads.srs", "Http_Client": {"version": 2, "Detour": "sub-a"}},
      {"type": "remote", "tag": "cn", "format": "binary", "url": "https://rules.example.com/cn.srs", "download_detour": "sub-a"}
    ],
    "final": "proxy"
  }
}`

// A subscription node a rule set downloads through (its own http_client's
// detour, its download_detour) that the refresh removes or the provider
// renames: the detour follows, the refresh is saved — the check would
// refuse the merge otherwise
func TestSyncFollowsRuleSetDownloadDetours(t *testing.T) {
	detours := func(t *testing.T, path string) (string, string) {
		t.Helper()
		sets := load(t, path)["route"].(map[string]any)["rule_set"].([]any)
		client, _ := sets[0].(map[string]any)["Http_Client"].(map[string]any)["Detour"].(string)
		download, _ := sets[1].(map[string]any)["download_detour"].(string)
		return client, download
	}

	t.Run("removed", func(t *testing.T) {
		path := writeConfig(t, syncDownloadConfig)
		result, err := New(path).SyncOutbounds([]string{"sub-a", "sub-b"}, []map[string]any{vlessNode("sub-b", "192.0.2.11")})
		if err != nil {
			t.Fatalf("SyncOutbounds: %v", err)
		}
		if !reflect.DeepEqual(result.Removed, []string{"sub-a"}) {
			t.Fatalf("result = %+v", result)
		}
		if client, download := detours(t, path); client != "sub-b" || download != "sub-b" {
			t.Fatalf("detours = %q, %q", client, download)
		}
	})

	t.Run("renamed", func(t *testing.T) {
		path := writeConfig(t, syncDownloadConfig)
		result, err := New(path).SyncOutbounds([]string{"sub-a", "sub-b"},
			[]map[string]any{vlessNode("sub-a | 9GB", "192.0.2.10"), vlessNode("sub-b", "192.0.2.11")})
		if err != nil {
			t.Fatalf("SyncOutbounds: %v", err)
		}
		if len(result.Renamed) != 1 || len(result.Removed) != 0 {
			t.Fatalf("result = %+v", result)
		}
		if client, download := detours(t, path); client != "sub-a | 9GB" || download != "sub-a | 9GB" {
			t.Fatalf("detours = %q, %q", client, download)
		}
	})
}

const syncSharedClientConfig = `{
  "Http_Clients": [{"tag": "shared", "Detour": "sub-a"}],
  "outbounds": [
    {"type": "selector", "tag": "proxy", "outbounds": ["sub-a", "sub-b", "direct"]},
    {"type": "vless", "tag": "sub-a", "server": "192.0.2.10", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555555"},
    {"type": "vless", "tag": "sub-b", "server": "192.0.2.11", "server_port": 443, "uuid": "11111111-2222-4333-8444-555555555555"},
    {"type": "direct", "tag": "direct"}
  ],
  "route": {
    "rule_set": [
      {"type": "remote", "tag": "ads", "format": "binary", "url": "https://rules.example.com/ads.srs", "http_client": "shared"},
      {"type": "remote", "tag": "cn", "format": "binary", "url": "https://rules.example.com/cn.srs", "http_client": {"detour": "sub-a"}}
    ],
    "default_http_client": "shared",
    "final": "proxy"
  }
}`

// The same for a shared HTTP client (http_clients) dialing through such a
// node; with no server left the detours go — sing-box refuses one to a
// direct outbound — and the clients dial directly
func TestSyncFollowsSharedHTTPClientDetour(t *testing.T) {
	detours := func(t *testing.T, path string) (string, string) {
		t.Helper()
		cfg := load(t, path)
		shared, _ := cfg["Http_Clients"].([]any)[0].(map[string]any)["Detour"].(string)
		own, _ := cfg["route"].(map[string]any)["rule_set"].([]any)[1].(map[string]any)["http_client"].(map[string]any)["detour"].(string)
		return shared, own
	}
	for name, tc := range map[string]struct {
		incoming []map[string]any
		want     string
	}{
		"removed":        {[]map[string]any{vlessNode("sub-b", "192.0.2.11")}, "sub-b"},
		"renamed":        {[]map[string]any{vlessNode("sub-a | 9GB", "192.0.2.10"), vlessNode("sub-b", "192.0.2.11")}, "sub-a | 9GB"},
		"no server left": {nil, ""},
	} {
		t.Run(name, func(t *testing.T) {
			path := writeConfig(t, syncSharedClientConfig)
			result, err := New(path).SyncOutbounds([]string{"sub-a", "sub-b"}, tc.incoming)
			if err != nil {
				t.Fatalf("SyncOutbounds: %v", err)
			}
			if !result.Changed {
				t.Fatalf("result = %+v", result)
			}
			if shared, own := detours(t, path); shared != tc.want || own != tc.want {
				t.Fatalf("detours = %q, %q, want %q", shared, own, tc.want)
			}
		})
	}
}
