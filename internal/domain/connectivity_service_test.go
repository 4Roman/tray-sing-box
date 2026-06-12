package domain

import (
	"errors"
	"testing"
)

type fakeProxySource struct {
	url string
	err error
}

func (f *fakeProxySource) LocalProxyURL() (string, error) { return f.url, f.err }

func TestConnectivityNotRunningResets(t *testing.T) {
	svc := NewConnectivityService(
		func(string) error { t.Fatal("must not probe when VPN is stopped"); return nil },
		&fakeProxySource{},
		NewVPNService(&fakeProcessManager{}, &fakeStorage{}),
	)

	status := svc.Check()
	if status.Checked {
		t.Fatalf("stopped VPN must yield an unchecked verdict: %+v", status)
	}
}

func TestConnectivityOK(t *testing.T) {
	var gotProxy string
	svc := NewConnectivityService(
		func(p string) error { gotProxy = p; return nil },
		&fakeProxySource{url: "http://127.0.0.1:2080"},
		NewVPNService(&fakeProcessManager{running: true}, &fakeStorage{state: true}),
	)

	status := svc.Check()
	if !status.Checked || !status.OK {
		t.Fatalf("status = %+v", status)
	}
	if gotProxy != "http://127.0.0.1:2080" {
		t.Fatalf("probe must go through the local inbound, got %q", gotProxy)
	}
}

func TestConnectivityDebouncesSingleFailure(t *testing.T) {
	failures := 0
	probe := func(string) error {
		failures++
		if failures <= 1 {
			return errors.New("blip")
		}
		return nil
	}
	svc := NewConnectivityService(probe, &fakeProxySource{},
		NewVPNService(&fakeProcessManager{running: true}, &fakeStorage{state: true}))

	// One lost probe: no verdict yet (and an existing OK verdict would stand)
	if status := svc.Check(); status.Checked {
		t.Fatalf("single failure must not produce a verdict: %+v", status)
	}
	// Next probe succeeds: OK
	if status := svc.Check(); !status.OK {
		t.Fatalf("recovery not reflected: %+v", status)
	}
}

func TestConnectivityFlipsAfterThreshold(t *testing.T) {
	svc := NewConnectivityService(
		func(string) error { return errors.New("down") },
		&fakeProxySource{},
		NewVPNService(&fakeProcessManager{running: true}, &fakeStorage{state: true}),
	)

	svc.Check()
	status := svc.Check() // second consecutive failure crosses the threshold
	if !status.Checked || status.OK {
		t.Fatalf("two failures must flip the verdict: %+v", status)
	}
}

func TestConnectivityProxyLookupErrorFallsBackToDirect(t *testing.T) {
	var gotProxy string
	svc := NewConnectivityService(
		func(p string) error { gotProxy = p; return nil },
		&fakeProxySource{err: errors.New("config unreadable")},
		NewVPNService(&fakeProcessManager{running: true}, &fakeStorage{state: true}),
	)

	if status := svc.Check(); !status.OK {
		t.Fatalf("status = %+v", status)
	}
	if gotProxy != "" {
		t.Fatalf("must fall back to a direct probe, got %q", gotProxy)
	}
}
