package domain

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

type fakeDPIManager struct {
	availErr error
	state    ContainerState
	started  bool
	stopped  bool
}

func (f *fakeDPIManager) Available() error { return f.availErr }
func (f *fakeDPIManager) State() (ContainerState, error) {
	if f.state == "" {
		return ContainerAbsent, nil
	}
	return f.state, nil
}
func (f *fakeDPIManager) Start() error             { f.started = true; f.state = ContainerRunning; return nil }
func (f *fakeDPIManager) Stop() error              { f.stopped = true; f.state = ContainerStopped; return nil }
func (f *fakeDPIManager) ProxyAddr() (string, int) { return "127.0.0.1", 3128 }

type fakeBypassStore struct {
	active      string
	types       map[string]string
	detours     map[string]string
	routeRefs   map[string]bool
	bypassAdded bool
	missing     bool // no config.json yet
}

func newBypassStore(active string, types map[string]string) *fakeBypassStore {
	return &fakeBypassStore{
		active:    active,
		types:     types,
		detours:   map[string]string{},
		routeRefs: map[string]bool{},
	}
}

func (f *fakeBypassStore) EnsureBypassOutbound(tag, server string, port int) error {
	f.bypassAdded = true
	if f.types == nil {
		f.types = map[string]string{}
	}
	f.types[tag] = "http"
	return nil
}
func (f *fakeBypassStore) SetDetour(target, detour string) error {
	f.detours[target] = detour
	return nil
}
func (f *fakeBypassStore) ClearDetour(detour string) error {
	for k, v := range f.detours {
		if v == detour {
			delete(f.detours, k)
		}
	}
	return nil
}
func (f *fakeBypassStore) DetourTargets(detour string) ([]string, error) {
	if f.missing {
		return nil, fmt.Errorf("%w at: C:\\data\\config.json", ErrConfigMissing)
	}
	var out []string
	for k, v := range f.detours {
		if v == detour {
			out = append(out, k)
		}
	}
	return out, nil
}
func (f *fakeBypassStore) RouteReferences(tag string) (bool, error) { return f.routeRefs[tag], nil }
func (f *fakeBypassStore) ActiveOutbound() (string, error) {
	if f.missing {
		return "", fmt.Errorf("%w at: C:\\data\\config.json", ErrConfigMissing)
	}
	return f.active, nil
}
func (f *fakeBypassStore) OutboundType(tag string) (string, error) {
	if t, ok := f.types[tag]; ok {
		return t, nil
	}
	return "", errors.New("not found")
}

func newRunningVPN() *VPNService {
	return NewVPNService(&fakeProcessManager{running: true}, &fakeStorage{state: true})
}

func TestEnableChainSuccess(t *testing.T) {
	mgr := &fakeDPIManager{}
	store := newBypassStore("proxy_vless", map[string]string{"proxy_vless": "vless"})
	svc := NewDPIBypassService(mgr, store, newRunningVPN())

	st, err := svc.EnableChain()
	if err != nil {
		t.Fatalf("EnableChain: %v", err)
	}
	if !mgr.started {
		t.Fatal("container not started")
	}
	if !store.bypassAdded {
		t.Fatal("bypass outbound not ensured")
	}
	if store.detours["proxy_vless"] != "dpi-bypass" {
		t.Fatalf("detour not set: %v", store.detours)
	}
	if !st.ChainActive || st.ChainTarget != "proxy_vless" {
		t.Fatalf("status wrong: %+v", st)
	}
	if !st.Restarted {
		t.Fatal("VPN should have restarted")
	}
}

func TestEnableChainDockerUnavailableTouchesNothing(t *testing.T) {
	mgr := &fakeDPIManager{availErr: errors.New("Docker не запущен")}
	store := newBypassStore("proxy_vless", map[string]string{"proxy_vless": "vless"})
	svc := NewDPIBypassService(mgr, store, newRunningVPN())

	if _, err := svc.EnableChain(); err == nil {
		t.Fatal("expected error when Docker is unavailable")
	}
	if mgr.started || store.bypassAdded || len(store.detours) != 0 {
		t.Fatal("config/container must be untouched when Docker is unavailable")
	}
}

func TestEnableChainRejectsUDPActive(t *testing.T) {
	mgr := &fakeDPIManager{}
	store := newBypassStore("proxy_hy2", map[string]string{"proxy_hy2": "hysteria2"})
	svc := NewDPIBypassService(mgr, store, newRunningVPN())

	if _, err := svc.EnableChain(); err == nil {
		t.Fatal("hysteria2 (UDP) active server must be rejected")
	}
	if mgr.started || store.bypassAdded {
		t.Fatal("nothing should change when the active server is UDP")
	}

	// The active server may be a subscription's node: its name, the
	// provider's text, stays on one line of the error popup
	evil := "hy2\n\nПодписка истекла"
	store = newBypassStore(evil, map[string]string{evil: "hysteria2"})
	_, err := NewDPIBypassService(mgr, store, newRunningVPN()).EnableChain()
	if err == nil || strings.Contains(err.Error(), "\n") || !strings.Contains(err.Error(), "«hy2  Подписка истекла»") {
		t.Fatalf("error = %q", err)
	}
}

func TestEnableChainRejectsEmptyOrBypassActive(t *testing.T) {
	for _, active := range []string{"", "dpi-bypass"} {
		mgr := &fakeDPIManager{}
		store := newBypassStore(active, map[string]string{"dpi-bypass": "http"})
		svc := NewDPIBypassService(mgr, store, newRunningVPN())
		if _, err := svc.EnableChain(); err == nil {
			t.Fatalf("active=%q must be rejected", active)
		}
	}
}

func TestDisableChainStopsContainerWhenNoDirect(t *testing.T) {
	mgr := &fakeDPIManager{state: ContainerRunning}
	store := newBypassStore("proxy_vless", map[string]string{"proxy_vless": "vless", "dpi-bypass": "http"})
	store.detours["proxy_vless"] = "dpi-bypass"
	svc := NewDPIBypassService(mgr, store, newRunningVPN())

	st, err := svc.DisableChain()
	if err != nil {
		t.Fatalf("DisableChain: %v", err)
	}
	if len(store.detours) != 0 {
		t.Fatalf("detour not cleared: %v", store.detours)
	}
	if !mgr.stopped {
		t.Fatal("container should stop when nothing else uses it")
	}
	if st.ChainActive {
		t.Fatal("chain should be inactive after disable")
	}
}

func TestDisableChainKeepsContainerWhenDirectInUse(t *testing.T) {
	mgr := &fakeDPIManager{state: ContainerRunning}
	store := newBypassStore("proxy_vless", map[string]string{"proxy_vless": "vless", "dpi-bypass": "http"})
	store.detours["proxy_vless"] = "dpi-bypass"
	store.routeRefs["dpi-bypass"] = true // mode B still routes through it
	svc := NewDPIBypassService(mgr, store, newRunningVPN())

	if _, err := svc.DisableChain(); err != nil {
		t.Fatalf("DisableChain: %v", err)
	}
	if mgr.stopped {
		t.Fatal("container must stay up while direct mode uses it")
	}
}

func TestToggleChainFlips(t *testing.T) {
	mgr := &fakeDPIManager{}
	store := newBypassStore("proxy_vless", map[string]string{"proxy_vless": "vless"})
	svc := NewDPIBypassService(mgr, store, newRunningVPN())

	st, err := svc.ToggleChain() // off -> on
	if err != nil || !st.ChainActive {
		t.Fatalf("toggle on failed: %+v / %v", st, err)
	}
	st, err = svc.ToggleChain() // on -> off
	if err != nil || st.ChainActive {
		t.Fatalf("toggle off failed: %+v / %v", st, err)
	}
}
