package configfile

import (
	"os"
	"path/filepath"
	"testing"

	"tray-sing-box/internal/infrastructure/sharelink"
)

// Full import cycle: share link -> parser -> config.json on disk
func TestImportLinkIntoConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(sampleConfig), 0644); err != nil {
		t.Fatal(err)
	}

	link := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@imported.example.com:443" +
		"?type=ws&security=tls&sni=cdn.example.org&path=%2Fws#imported-node"
	outbounds, _, err := sharelink.Parser{}.Parse("шум вокруг ссылки " + link + " ещё шум")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if _, err := New(path).AddOutbounds(outbounds, nil); err != nil {
		t.Fatalf("AddOutbounds: %v", err)
	}

	cfg := load(t, path)
	imported := outboundByTag(t, cfg, "imported-node")
	if imported == nil {
		t.Fatal("imported outbound not found in config")
	}
	if imported["server"] != "imported.example.com" || imported["type"] != "vless" {
		t.Fatalf("imported outbound wrong: %v", imported)
	}

	tls := imported["tls"].(map[string]any)
	if tls["server_name"] != "cdn.example.org" {
		t.Fatalf("tls wrong: %v", tls)
	}

	// Registered in the selector and the rest of the config intact
	members := outboundByTag(t, cfg, "proxy")["outbounds"].([]any)
	found := false
	for _, m := range members {
		if m == "imported-node" {
			found = true
		}
	}
	if !found {
		t.Fatalf("tag not in selector: %v", members)
	}
	if len(cfg["inbounds"].([]any)) != 1 {
		t.Fatal("inbounds were damaged")
	}
}
