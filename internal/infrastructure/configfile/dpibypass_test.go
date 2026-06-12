package configfile

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestEnsureBypassOutboundAddsHTTPNotInSelector(t *testing.T) {
	path := writeSample(t) // has a "proxy" selector group
	e := New(path)

	if err := e.EnsureBypassOutbound("dpi-bypass", "127.0.0.1", 3128); err != nil {
		t.Fatalf("EnsureBypassOutbound: %v", err)
	}

	cfg := load(t, path)
	ob := outboundByTag(t, cfg, "dpi-bypass")
	if ob == nil {
		t.Fatal("dpi-bypass outbound not added")
	}
	if ob["type"] != "http" || ob["server"] != "127.0.0.1" {
		t.Fatalf("unexpected bypass outbound: %v", ob)
	}

	// Must NOT be registered in the selector group (it is plumbing, not a server)
	selector := outboundByTag(t, cfg, "proxy")
	for _, m := range selector["outbounds"].([]any) {
		if m == "dpi-bypass" {
			t.Fatal("dpi-bypass must not be added to the selector group")
		}
	}
}

func TestEnsureBypassOutboundIdempotent(t *testing.T) {
	path := writeSample(t)
	e := New(path)

	if err := e.EnsureBypassOutbound("dpi-bypass", "127.0.0.1", 3128); err != nil {
		t.Fatalf("first EnsureBypassOutbound: %v", err)
	}
	before, _ := os.ReadFile(path)

	if err := e.EnsureBypassOutbound("dpi-bypass", "127.0.0.1", 3128); err != nil {
		t.Fatalf("second EnsureBypassOutbound: %v", err)
	}
	after, _ := os.ReadFile(path)

	if string(before) != string(after) {
		t.Fatal("identical EnsureBypassOutbound must not rewrite the file")
	}
}

func TestSetAndClearDetour(t *testing.T) {
	path := writeRouted(t)
	e := New(path)

	if err := e.EnsureBypassOutbound("dpi-bypass", "127.0.0.1", 3128); err != nil {
		t.Fatalf("EnsureBypassOutbound: %v", err)
	}
	if err := e.SetDetour("proxy_vless", "dpi-bypass"); err != nil {
		t.Fatalf("SetDetour: %v", err)
	}

	cfg := load(t, path)
	if outboundByTag(t, cfg, "proxy_vless")["detour"] != "dpi-bypass" {
		t.Fatal("detour not set on proxy_vless")
	}
	// Other outbounds untouched
	if _, ok := outboundByTag(t, cfg, "proxy_hy2")["detour"]; ok {
		t.Fatal("detour leaked onto proxy_hy2")
	}

	targets, err := e.DetourTargets("dpi-bypass")
	if err != nil || len(targets) != 1 || targets[0] != "proxy_vless" {
		t.Fatalf("DetourTargets = %v, %v", targets, err)
	}

	if err := e.ClearDetour("dpi-bypass"); err != nil {
		t.Fatalf("ClearDetour: %v", err)
	}
	cfg = load(t, path)
	if _, ok := outboundByTag(t, cfg, "proxy_vless")["detour"]; ok {
		t.Fatal("detour not cleared")
	}
	// proxy_vless itself still present
	if outboundByTag(t, cfg, "proxy_vless") == nil {
		t.Fatal("proxy_vless damaged by ClearDetour")
	}
}

func TestSetDetourRejectsInvalid(t *testing.T) {
	path := writeRouted(t)
	e := New(path)
	if err := e.EnsureBypassOutbound("dpi-bypass", "127.0.0.1", 3128); err != nil {
		t.Fatalf("EnsureBypassOutbound: %v", err)
	}

	if err := e.SetDetour("direct", "dpi-bypass"); err == nil {
		t.Fatal("system outbound (direct) must not accept a detour")
	}
	if err := e.SetDetour("missing", "dpi-bypass"); err == nil {
		t.Fatal("missing target must be rejected")
	}
	if err := e.SetDetour("proxy_vless", "proxy_vless"); err == nil {
		t.Fatal("self-detour must be rejected")
	}
	if err := e.SetDetour("proxy_vless", "no-such-detour"); err == nil {
		t.Fatal("missing detour outbound must be rejected")
	}
}

func TestRouteReferencesAndOutboundType(t *testing.T) {
	e := New(writeRouted(t))

	ref, err := e.RouteReferences("proxy_hy2")
	if err != nil || !ref {
		t.Fatalf("proxy_hy2 should be referenced by route rules: %v, %v", ref, err)
	}
	ref, _ = e.RouteReferences("dpi-bypass")
	if ref {
		t.Fatal("dpi-bypass should not be referenced yet")
	}

	typ, err := e.OutboundType("proxy_hy2")
	if err != nil || typ != "hysteria2" {
		t.Fatalf("OutboundType = %q, %v", typ, err)
	}
	if _, err := e.OutboundType("missing"); err == nil {
		t.Fatal("OutboundType must error on missing tag")
	}
}

func TestSetDetourValidatorBlocksSave(t *testing.T) {
	path := writeRouted(t)
	e := New(path)
	if err := e.EnsureBypassOutbound("dpi-bypass", "127.0.0.1", 3128); err != nil {
		t.Fatalf("EnsureBypassOutbound: %v", err)
	}
	before, _ := os.ReadFile(path)

	e.SetValidator(func(configJSON []byte) error {
		return errors.New("sing-box check failed")
	})
	err := e.SetDetour("proxy_vless", "dpi-bypass")
	if err == nil || !strings.Contains(err.Error(), "sing-box check failed") {
		t.Fatalf("validator error not propagated: %v", err)
	}

	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("config changed despite failed validation")
	}
}
