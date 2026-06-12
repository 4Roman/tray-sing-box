package domain

import (
	"errors"
	"strings"
	"testing"
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
		return r, nil
	}
	return &SyncResult{Added: tags, Changed: true}, nil
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

// linkParser maps each line of the body to an outbound tagged with the line
type linkParser struct{}

func (linkParser) Parse(text string) ([]map[string]any, error) {
	var outbounds []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
		if line == "" {
			continue
		}
		outbounds = append(outbounds, map[string]any{"tag": line, "type": "vless"})
	}
	if len(outbounds) == 0 {
		return nil, errors.New("no links")
	}
	return outbounds, nil
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
	sync := &fakeSyncStore{results: map[string]*SyncResult{"": {Removed: []string{"node-a", "node-b"}, Changed: true}}}
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
