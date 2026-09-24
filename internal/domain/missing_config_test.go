package domain

import (
	"fmt"
	"strings"
	"testing"
)

// A fresh install has no config.json: whatever needs one says how to get it
// in, and nothing half-works

func missingConfig() error {
	return fmt.Errorf("%w at: C:\\data\\config.json", ErrConfigMissing)
}

func TestImportWithoutAConfigCarriesTheHint(t *testing.T) {
	vpn := NewVPNService(&fakeProcessManager{}, &fakeStorage{})
	imp := NewImportService(&fakeParser{tags: []string{"node-1"}}, &fakeEditor{err: missingConfig()}, vpn)
	_, err := imp.ImportFromText("vless://...")
	if err == nil || !strings.Contains(err.Error(), "«Первоначальная настройка»") {
		t.Fatalf("import error lacks the hint: %v", err)
	}
}

// A subscription added before the config exists is not kept without servers
func TestSubscriptionAddedWithoutAConfigIsNotKept(t *testing.T) {
	store := &fakeSubStore{}
	fetch := fetcherFor(map[string]string{"https://s.example/sub": "node-a"}, nil)
	svc := NewSubscriptionService(store, fetch, linkParser{}, &fakeSyncStore{err: missingConfig()}, NewVPNService(&fakeProcessManager{}, &fakeStorage{}))

	_, err := svc.Add("https://s.example/sub")
	if err == nil || !strings.Contains(err.Error(), "«Первоначальная настройка»") {
		t.Fatalf("add error lacks the hint: %v", err)
	}
	if len(store.subs) != 0 {
		t.Fatalf("subscription kept without servers: %+v", store.subs)
	}
}

// No privileged container for a config that is not there; the status still
// tells the Docker state
func TestDPIWithoutAConfig(t *testing.T) {
	manager := &fakeDPIManager{}
	store := newBypassStore("p1", map[string]string{"p1": "vless"})
	store.missing = true
	svc := NewDPIBypassService(manager, store, NewVPNService(&fakeProcessManager{}, &fakeStorage{}))

	if _, err := svc.EnableDirect(); err == nil || !strings.Contains(err.Error(), "«Первоначальная настройка»") {
		t.Fatalf("EnableDirect without a config: %v", err)
	}
	if _, err := svc.EnableChain(); err == nil {
		t.Fatal("EnableChain without a config succeeded")
	}
	if manager.started {
		t.Fatal("the container was started for a missing config")
	}
	st, err := svc.Status()
	if err != nil || !st.DockerOK || st.ChainActive {
		t.Fatalf("Status without a config: %+v, %v", st, err)
	}
}
