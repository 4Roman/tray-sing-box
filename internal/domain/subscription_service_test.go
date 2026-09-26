package domain

import (
	"bytes"
	"errors"
	"log"
	"reflect"
	"strings"
	"testing"
	"time"
)

type fakeSubStore struct {
	subs    []Subscription
	loadErr error
	saves   int
}

func (f *fakeSubStore) Load() ([]Subscription, error) {
	if f.loadErr != nil {
		return nil, f.loadErr
	}
	// Return a copy: the service mutates the slice in place
	out := make([]Subscription, len(f.subs))
	copy(out, f.subs)
	return out, nil
}

func (f *fakeSubStore) Save(subs []Subscription) error {
	f.subs = subs
	f.saves++
	return nil
}

type fakeSyncStore struct {
	calls   []syncCall
	results map[string]*SyncResult // keyed by first new tag, "" for removal
	err     error
}

type syncCall struct {
	owned []string
	tags  []string
}

func (f *fakeSyncStore) SyncOutbounds(owned []string, outbounds []map[string]any) (*SyncResult, error) {
	if f.err != nil {
		return nil, f.err
	}
	var tags []string
	for _, o := range outbounds {
		tag, _ := o["tag"].(string)
		tags = append(tags, tag)
	}
	f.calls = append(f.calls, syncCall{owned: owned, tags: tags})

	key := ""
	if len(tags) > 0 {
		key = tags[0]
	}
	if r, ok := f.results[key]; ok {
		if r.Tags == nil {
			r.Tags = tags
		}
		return r, nil
	}
	return &SyncResult{Tags: tags, Added: tags, Changed: true, NeedsRestart: true}, nil
}

// fetcherFor maps URL -> body or error
func fetcherFor(bodies map[string]string, errs map[string]error) SubscriptionFetcher {
	return func(url string) (string, error) {
		if err, ok := errs[url]; ok {
			return "", err
		}
		body, ok := bodies[url]
		if !ok {
			return "", errors.New("unexpected url " + url)
		}
		return body, nil
	}
}

// linkParser maps each line of the body to an outbound tagged with the line;
// a line "skip:<name>:<reason>" is a link it leaves out
type linkParser struct{}

func (linkParser) Parse(text string) ([]map[string]any, []SkippedNode, error) {
	var outbounds []map[string]any
	var skipped []SkippedNode
	for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
		if line == "" {
			continue
		}
		if parts := strings.SplitN(line, ":", 3); len(parts) == 3 && parts[0] == "skip" {
			skipped = append(skipped, SkippedNode{Name: parts[1], Reason: parts[2]})
			continue
		}
		outbounds = append(outbounds, map[string]any{"tag": line, "type": "vless"})
	}
	if len(outbounds) == 0 {
		return nil, skipped, errors.New("no links")
	}
	return outbounds, skipped, nil
}

func TestIsSubscriptionURL(t *testing.T) {
	for url, want := range map[string]bool{
		"https://provider.example/sub?token=x": true,
		"http://provider.example/sub":          true,
		"  https://provider.example/s  ":       true,
		"vless://u@h:443?security=tls#x":       false,
		"https://a.example/x\nhttps://b":       false, // multiple lines
		"not a url":                            false,
		"https://":                             false, // no host
	} {
		if got := IsSubscriptionURL(url); got != want {
			t.Errorf("IsSubscriptionURL(%q) = %v, want %v", url, got, want)
		}
	}
}

func TestAddSubscription(t *testing.T) {
	store := &fakeSubStore{}
	sync := &fakeSyncStore{}
	fetch := fetcherFor(map[string]string{"https://p.example/sub": "node-a\nnode-b"}, nil)
	pm := &fakeProcessManager{running: true}
	svc := NewSubscriptionService(store, fetch, linkParser{}, sync, NewVPNService(pm, &fakeStorage{state: true}))

	result, err := svc.Add("https://p.example/sub")
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if len(result.Updates) != 1 || result.Updates[0].Err != nil {
		t.Fatalf("updates = %+v", result.Updates)
	}
	if !result.Restarted {
		t.Fatal("running VPN must be restarted after a config change")
	}
	if len(store.subs) != 1 || store.subs[0].URL != "https://p.example/sub" {
		t.Fatalf("subscription not saved: %+v", store.subs)
	}
	if got := store.subs[0].Tags; len(got) != 2 || got[0] != "node-a" || got[1] != "node-b" {
		t.Fatalf("tags = %v", got)
	}
	if store.subs[0].Updated.IsZero() {
		t.Fatal("Updated timestamp not set")
	}
	if len(sync.calls) != 1 || len(sync.calls[0].owned) != 0 {
		t.Fatalf("sync calls = %+v", sync.calls)
	}
}

func TestAddRejectsNonURL(t *testing.T) {
	svc := NewSubscriptionService(&fakeSubStore{}, nil, linkParser{}, &fakeSyncStore{}, NewVPNService(&fakeProcessManager{}, &fakeStorage{}))
	if _, err := svc.Add("vless://u@h:443#x"); err == nil {
		t.Fatal("share link must not be accepted as a subscription URL")
	}
}

func TestAddExistingURLRefreshes(t *testing.T) {
	store := &fakeSubStore{subs: []Subscription{{URL: "https://p.example/sub", Tags: []string{"old-1"}}}}
	sync := &fakeSyncStore{}
	fetch := fetcherFor(map[string]string{"https://p.example/sub": "new-1"}, nil)
	svc := NewSubscriptionService(store, fetch, linkParser{}, sync, NewVPNService(&fakeProcessManager{}, &fakeStorage{}))

	if _, err := svc.Add("https://p.example/sub"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if len(store.subs) != 1 {
		t.Fatalf("duplicate subscription created: %+v", store.subs)
	}
	if len(sync.calls) != 1 || len(sync.calls[0].owned) != 1 || sync.calls[0].owned[0] != "old-1" {
		t.Fatalf("old tags not passed as owned: %+v", sync.calls)
	}
	if store.subs[0].Tags[0] != "new-1" {
		t.Fatalf("tags not replaced: %+v", store.subs[0].Tags)
	}
}

func TestUpdateAllSurvivesOneFailure(t *testing.T) {
	store := &fakeSubStore{subs: []Subscription{
		{URL: "https://bad.example/sub", Tags: []string{"b-1"}},
		{URL: "https://good.example/sub", Tags: []string{"g-1"}},
	}}
	sync := &fakeSyncStore{}
	fetch := fetcherFor(
		map[string]string{"https://good.example/sub": "g-1\ng-2"},
		map[string]error{"https://bad.example/sub": errors.New("timeout")},
	)
	svc := NewSubscriptionService(store, fetch, linkParser{}, sync, NewVPNService(&fakeProcessManager{}, &fakeStorage{}))

	result, err := svc.UpdateAll()
	if err != nil {
		t.Fatalf("UpdateAll must not fail on a single bad subscription: %v", err)
	}
	if len(result.Updates) != 2 {
		t.Fatalf("updates = %+v", result.Updates)
	}
	if result.Updates[0].Err == nil || result.Updates[1].Err != nil {
		t.Fatalf("wrong per-subscription errors: %+v", result.Updates)
	}
	// The failed subscription keeps its previous tags
	if store.subs[0].Tags[0] != "b-1" {
		t.Fatalf("failed subscription tags must be kept: %+v", store.subs[0])
	}
	if len(store.subs[1].Tags) != 2 {
		t.Fatalf("good subscription not refreshed: %+v", store.subs[1])
	}
}

func TestUpdateUnknownURL(t *testing.T) {
	svc := NewSubscriptionService(&fakeSubStore{}, nil, linkParser{}, &fakeSyncStore{}, NewVPNService(&fakeProcessManager{}, &fakeStorage{}))
	if _, err := svc.Update("https://nope.example/sub"); err == nil {
		t.Fatal("expected error for unknown subscription")
	}
}

func TestUpdateSingleFailsLoudly(t *testing.T) {
	store := &fakeSubStore{subs: []Subscription{{URL: "https://bad.example/sub"}}}
	fetch := fetcherFor(nil, map[string]error{"https://bad.example/sub": errors.New("HTTP 502")})
	svc := NewSubscriptionService(store, fetch, linkParser{}, &fakeSyncStore{}, NewVPNService(&fakeProcessManager{}, &fakeStorage{}))

	if _, err := svc.Update("https://bad.example/sub"); err == nil {
		t.Fatal("targeted update must return the fetch error")
	}
}

func TestNoRestartWhenNothingChanged(t *testing.T) {
	store := &fakeSubStore{subs: []Subscription{{URL: "https://p.example/sub", Tags: []string{"node-a"}}}}
	sync := &fakeSyncStore{results: map[string]*SyncResult{"node-a": {Changed: false}}}
	fetch := fetcherFor(map[string]string{"https://p.example/sub": "node-a"}, nil)
	pm := &fakeProcessManager{running: true}
	svc := NewSubscriptionService(store, fetch, linkParser{}, sync, NewVPNService(pm, &fakeStorage{state: true}))

	result, err := svc.UpdateAll()
	if err != nil {
		t.Fatalf("UpdateAll: %v", err)
	}
	if result.Restarted {
		t.Fatal("VPN must not restart when the config did not change")
	}
}

func TestRemoveSubscription(t *testing.T) {
	store := &fakeSubStore{subs: []Subscription{{URL: "https://p.example/sub", Tags: []string{"node-a", "node-b"}}}}
	sync := &fakeSyncStore{results: map[string]*SyncResult{"": {Removed: []string{"node-a", "node-b"}, Changed: true, NeedsRestart: true}}}
	pm := &fakeProcessManager{running: true}
	svc := NewSubscriptionService(store, nil, linkParser{}, sync, NewVPNService(pm, &fakeStorage{state: true}))

	result, err := svc.Remove("https://p.example/sub")
	if err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if len(store.subs) != 0 {
		t.Fatalf("subscription not removed: %+v", store.subs)
	}
	if len(sync.calls) != 1 || len(sync.calls[0].tags) != 0 {
		t.Fatalf("outbounds not synced away: %+v", sync.calls)
	}
	if !result.Restarted {
		t.Fatal("running VPN must restart after its outbounds were removed")
	}
}

func TestSubscriptionID(t *testing.T) {
	id := SubscriptionID("https://p.example/sub?token=a")
	if len(id) != 16 || strings.Trim(id, "0123456789abcdef") != "" {
		t.Fatalf("SubscriptionID = %q, want 16 hex digits", id)
	}
	if SubscriptionID("https://p.example/sub?token=a") != id {
		t.Fatal("SubscriptionID is not stable")
	}
	if SubscriptionID("https://p.example/sub?token=b") == id {
		t.Fatal("two subscriptions of one host got the same ID")
	}
}

func TestRedactURL(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{"https://p.example/sub?token=secret", "https://p.example/…"},
		{"https://usersecret:secret@p.example:8443/api/v1/secret?token=secret#secret", "https://p.example:8443/…"},
		{"https://p.example/secret", "https://p.example/…"},
		{"https://p.example?token=secret", "https://p.example/…"},
		{"https://p.example#secret", "https://p.example/…"},
		{"http://p.example", "http://p.example"},
		{"https://p.example/", "https://p.example"},
		// Not an absolute URL: nothing of it is shown
		{"not a url secret", ""},
		{"p.example/secret", ""},
		{"http://[::1/secret", ""},
		{"", ""},
	} {
		short := SubscriptionID(tc.raw)[:6]
		want := "(подписка " + short + ")"
		if tc.want != "" {
			want = tc.want + " (" + short + ")"
		}
		got := RedactURL(tc.raw)
		if got != want {
			t.Errorf("RedactURL(%q) = %q, want %q", tc.raw, got, want)
		}
		if strings.Contains(got, "secret") {
			t.Errorf("RedactURL(%q) = %q reveals the secret part", tc.raw, got)
		}
	}
}

// Subscription URLs carry the provider's access token: the service names
// them only in the redacted form, in its log lines and in its errors
func TestSubscriptionMessagesRedactURL(t *testing.T) {
	const secretURL = "https://usersecret:pwsecret@p.example/pathsecret?token=querysecret"
	assertRedacted := func(what, text string) {
		t.Helper()
		for _, secret := range []string{"usersecret", "pwsecret", "pathsecret", "querysecret"} {
			if strings.Contains(text, secret) {
				t.Fatalf("%s reveals the subscription URL (%q): %s", what, secret, text)
			}
		}
	}

	var logs bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(prev)

	store := &fakeSubStore{}
	fetch := fetcherFor(map[string]string{secretURL: "node-a"}, nil)
	svc := NewSubscriptionService(store, fetch, linkParser{}, &fakeSyncStore{}, NewVPNService(&fakeProcessManager{}, &fakeStorage{}))

	if _, err := svc.Add(secretURL); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, err := svc.Remove(secretURL); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	for _, text := range []string{"Subscription refreshed: https://p.example/… (", "Subscription removed: https://p.example/… ("} {
		if !strings.Contains(logs.String(), text) {
			t.Fatalf("log lacks %q: %s", text, logs.String())
		}
	}
	assertRedacted("log", logs.String())

	// Errors naming a subscription: unknown (removed above) and not a URL
	_, errUpdate := svc.Update(secretURL)
	_, errRemove := svc.Remove(secretURL)
	_, errAdd := svc.Add("https://p.example/x pathsecret?token=querysecret")
	for _, err := range []error{errUpdate, errRemove, errAdd} {
		if err == nil {
			t.Fatal("expected an error")
		}
		assertRedacted("error", err.Error())
	}
}

// The subscription owns the tags its nodes were saved under (a node whose
// name was taken gets a suffix), and the update names the nodes left out:
// the parser's and the ones the config check refused
func TestRefreshRecordsSavedTagsAndSkipped(t *testing.T) {
	const u = "https://p.example/sub"
	store := &fakeSubStore{}
	sync := &fakeSyncStore{results: map[string]*SyncResult{"direct": {
		Tags:         []string{"node-b", "direct (2)"},
		Added:        []string{"direct (2)", "node-b"},
		Suffixed:     []TagRename{{From: "direct", To: "direct (2)"}},
		Skipped:      []SkippedNode{{Name: "bad", Reason: "sing-box не принимает: x"}},
		Changed:      true,
		NeedsRestart: true,
	}}}
	fetch := fetcherFor(map[string]string{u: "direct\nnode-b\nbad\nskip:hy2-hop:список портов"}, nil)
	svc := NewSubscriptionService(store, fetch, linkParser{}, sync, NewVPNService(&fakeProcessManager{}, &fakeStorage{}))

	result, err := svc.Add(u)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if got := store.subs[0].Tags; !reflect.DeepEqual(got, []string{"direct (2)", "node-b"}) {
		t.Fatalf("owned tags = %v", got)
	}
	update := result.Updates[0]
	want := []SkippedNode{{Name: "hy2-hop", Reason: "список портов"}, {Name: "bad", Reason: "sing-box не принимает: x"}}
	if !reflect.DeepEqual(update.Skipped, want) || len(update.Suffixed) != 1 || !update.NewProblem {
		t.Fatalf("update = %+v", update)
	}
}

// refuseAll is a config store whose check refuses every node
type refuseAll struct{ calls int }

func (r *refuseAll) SyncOutbounds(owned []string, outbounds []map[string]any) (*SyncResult, error) {
	r.calls++
	result := &SyncResult{}
	for _, o := range outbounds {
		result.Skipped = append(result.Skipped, SkippedNode{Name: o["tag"].(string), Reason: "sing-box не принимает: x"})
	}
	return result, nil
}

// Every node refused: an error naming them, and the servers of the last
// refresh stay the subscription's
func TestRefreshAllRefusedKeepsTags(t *testing.T) {
	const u = "https://p.example/sub"
	store := &fakeSubStore{subs: []Subscription{{URL: u, Tags: []string{"old-1"}}}}
	fetch := fetcherFor(map[string]string{u: "new-1"}, nil)
	pm := &fakeProcessManager{running: true}
	svc := NewSubscriptionService(store, fetch, linkParser{}, &refuseAll{}, NewVPNService(pm, &fakeStorage{state: true}))

	result, err := svc.UpdateAll()
	if err != nil {
		t.Fatalf("UpdateAll: %v", err)
	}
	if e := result.Updates[0].Err; e == nil || e.Error() != "ни один сервер подписки не подошёл:\n«new-1» — sing-box не принимает: x" {
		t.Fatalf("error = %v", e)
	}
	if !reflect.DeepEqual(store.subs[0].Tags, []string{"old-1"}) || result.Restarted {
		t.Fatalf("tags %v, restarted %v", store.subs[0].Tags, result.Restarted)
	}
	if _, err := svc.Update(u); err == nil {
		t.Fatal("a targeted update must fail loudly")
	}
}

// Nothing but renamed nodes: saved, not restarted
func TestRenamesOnlyDoNotRestart(t *testing.T) {
	const u = "https://p.example/sub"
	store := &fakeSubStore{subs: []Subscription{{URL: u, Tags: []string{"DE|12GB"}}}}
	sync := &fakeSyncStore{results: map[string]*SyncResult{"DE|11GB": {
		Renamed: []TagRename{{From: "DE|12GB", To: "DE|11GB"}},
		Changed: true,
	}}}
	pm := &fakeProcessManager{running: true}
	svc := NewSubscriptionService(store, fetcherFor(map[string]string{u: "DE|11GB"}, nil), linkParser{}, sync, NewVPNService(pm, &fakeStorage{state: true}))

	result, err := svc.UpdateAll()
	if err != nil {
		t.Fatalf("UpdateAll: %v", err)
	}
	if result.Restarted || pm.startCount() != 0 {
		t.Fatal("VPN restarted for renamed nodes")
	}
	if !reflect.DeepEqual(store.subs[0].Tags, []string{"DE|11GB"}) || len(result.Updates[0].Renamed) != 1 {
		t.Fatalf("tags %v, update %+v", store.subs[0].Tags, result.Updates[0])
	}
}

// An unattended refresh reports a problem once: the same problem at the
// next refresh is not new — also when the node names carry live counters —,
// a different one is, and one that went away and came back is again
func TestNewProblemOncePerProblem(t *testing.T) {
	const u = "https://p.example/sub"
	body := "node-a\nskip:info|12.4GB:тип ссылки не поддерживается"
	fetch := func(string) (string, error) { return body, nil }
	store := &fakeSubStore{subs: []Subscription{{URL: u}}}
	svc := NewSubscriptionService(store, fetch, linkParser{}, &fakeSyncStore{}, NewVPNService(&fakeProcessManager{}, &fakeStorage{}))
	newProblem := func() bool {
		t.Helper()
		result, err := svc.UpdateAll()
		if err != nil {
			t.Fatalf("UpdateAll: %v", err)
		}
		return result.Updates[0].NewProblem
	}

	if !newProblem() {
		t.Fatal("first problem not new")
	}
	body = "node-a\nskip:info|11.9GB:тип ссылки не поддерживается"
	if newProblem() {
		t.Fatal("the same problem reported again")
	}
	body = "node-a\nskip:x:другая причина"
	if !newProblem() {
		t.Fatal("a different problem not reported")
	}
	body = "node-a"
	if newProblem() || store.subs[0].Problem != "" {
		t.Fatalf("no problem, but NewProblem or a recorded one (%q)", store.subs[0].Problem)
	}
	body = "node-a\nskip:x:другая причина"
	if !newProblem() {
		t.Fatal("a problem that came back not reported")
	}

	// An error naming nodes: their live counters do not make it new
	refusing := NewSubscriptionService(store, fetch, linkParser{}, &refuseAll{}, NewVPNService(&fakeProcessManager{}, &fakeStorage{}))
	body = "DE|12.4GB"
	if r, _ := refusing.UpdateAll(); !r.Updates[0].NewProblem {
		t.Fatal("refusal not reported")
	}
	body = "DE|11.9GB"
	if r, _ := refusing.UpdateAll(); r.Updates[0].NewProblem {
		t.Fatal("the same refusal reported again under another counter")
	}
}

// When the VPN restart after a refresh fails, the refresh has happened and
// its new problem is recorded as reported: the result travels with the
// error (RestartErr), so it can still be shown — otherwise the user would
// never hear of the problem, the next refresh no longer finds it new
func TestRestartFailureKeepsTheResult(t *testing.T) {
	const u = "https://p.example/sub"
	store := &fakeSubStore{subs: []Subscription{{URL: u, Tags: []string{"old"}}}}
	pm := &fakeProcessManager{running: true, startErr: errors.New("TUN setup failed")}
	fetch := fetcherFor(map[string]string{u: "node-a\nskip:bad:тип «tor» не поддерживается"}, nil)
	svc := NewSubscriptionService(store, fetch, linkParser{}, &fakeSyncStore{}, NewVPNService(pm, &fakeStorage{state: true}))

	result, err := svc.UpdateAll()
	if err == nil || !strings.Contains(err.Error(), "TUN setup failed") {
		t.Fatalf("err = %v", err)
	}
	if result == nil || result.RestartErr != err || !result.Applied(err) {
		t.Fatalf("result = %+v", result)
	}
	if !result.Updates[0].NewProblem || store.subs[0].Problem == "" {
		t.Fatalf("update %+v, recorded problem %q", result.Updates[0], store.subs[0].Problem)
	}

	// Removal too: the servers are gone from the config, only the restart failed
	pm.setRunning(true)
	result, err = svc.Remove(u)
	if err == nil || result == nil || result.RestartErr != err || len(store.subs) != 0 {
		t.Fatalf("remove: result %+v, err %v", result, err)
	}

	// A failure of the operation itself is not applied
	failed := &fakeSubStore{loadErr: errors.New("broken file")}
	svc = NewSubscriptionService(failed, fetch, linkParser{}, &fakeSyncStore{}, NewVPNService(pm, &fakeStorage{state: true}))
	result, err = svc.UpdateAll()
	if err == nil || result.Applied(err) {
		t.Fatalf("a failed load counts as applied: %+v, %v", result, err)
	}
}

// A failed download is a problem only once the servers are getting old (at
// logon the network is often not up yet), and it does not wipe out what an
// earlier refresh recorded
func TestFetchFailureReportedWhenStale(t *testing.T) {
	const u = "https://p.example/sub"
	store := &fakeSubStore{subs: []Subscription{{URL: u, Tags: []string{"a"}, Updated: time.Now(), Problem: "earlier"}}}
	svc := NewSubscriptionService(store, fetcherFor(nil, map[string]error{u: errors.New("timeout")}), linkParser{}, &fakeSyncStore{}, NewVPNService(&fakeProcessManager{}, &fakeStorage{}))

	result, _ := svc.UpdateAll()
	if result.Updates[0].NewProblem || store.subs[0].Problem != "earlier" {
		t.Fatalf("a fresh subscription's failed download: %+v, problem %q", result.Updates[0], store.subs[0].Problem)
	}
	store.subs[0].Updated = time.Now().Add(-48 * time.Hour)
	if result, _ = svc.UpdateAll(); !result.Updates[0].NewProblem {
		t.Fatal("a stale subscription's failed download not reported")
	}
	if result, _ = svc.UpdateAll(); result.Updates[0].NewProblem {
		t.Fatal("the same failure reported again")
	}
}
