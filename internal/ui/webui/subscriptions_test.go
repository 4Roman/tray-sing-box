package webui

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"tray-sing-box/internal/domain"
	"tray-sing-box/internal/infrastructure/configfile"
	"tray-sing-box/internal/infrastructure/sharelink"
	"tray-sing-box/internal/infrastructure/subscription"
)

// TestSubscriptionEndpoints drives add -> list -> remove through the HTTP
// API with a real config editor and file store; only the fetch is stubbed.
func TestSubscriptionEndpoints(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, []byte(testConfig), 0644); err != nil {
		t.Fatal(err)
	}

	editor := configfile.New(configPath)
	vpn := domain.NewVPNService(&nopProcessManager{}, &nopStorage{})
	settings := domain.NewSettingsService(editor, vpn)
	importer := domain.NewImportService(sharelink.Parser{}, editor, vpn)

	fetch := func(url string) (string, error) {
		return "vless://u1@a.example.com:443?security=tls#sub-node-1\n" +
			"vless://u2@b.example.com:443?security=tls#sub-node-2", nil
	}
	store := subscription.NewStore(filepath.Join(dir, "subscriptions.json"))
	subs := domain.NewSubscriptionService(store, fetch, sharelink.Parser{}, editor, vpn)

	server := New(settings, importer, nil, nil, subs, Sources{}, LogAccess{})
	pageURL, err := server.start()
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	u, _ := url.Parse(pageURL)
	token := u.Query().Get("t")
	base := "http://" + u.Host

	// Add
	status, data := call(t, http.MethodPost, base+"/api/subscriptions/add", token,
		map[string]string{"url": "https://p.example/sub"})
	if status != http.StatusOK {
		t.Fatalf("add: status %d, %v", status, data)
	}
	updates := data["updates"].([]any)
	if len(updates) != 1 {
		t.Fatalf("add updates = %#v", updates)
	}
	if got := updates[0].(map[string]any)["count"].(float64); got != 2 {
		t.Fatalf("add count = %v", got)
	}

	// The nodes are now in the config
	list, err := editor.ListOutbounds()
	if err != nil {
		t.Fatal(err)
	}
	tags := map[string]bool{}
	for _, o := range list {
		tags[o.Tag] = true
	}
	if !tags["sub-node-1"] || !tags["sub-node-2"] {
		t.Fatalf("subscription nodes missing from config: %+v", list)
	}

	// List
	status, data = call(t, http.MethodGet, base+"/api/subscriptions", token, nil)
	if status != http.StatusOK {
		t.Fatalf("list: status %d", status)
	}
	if subsList := data["subscriptions"].([]any); len(subsList) != 1 {
		t.Fatalf("list = %#v", subsList)
	}

	// Remove deletes the nodes too
	status, _ = call(t, http.MethodPost, base+"/api/subscriptions/remove", token,
		map[string]string{"url": "https://p.example/sub"})
	if status != http.StatusOK {
		t.Fatalf("remove: status %d", status)
	}
	list, err = editor.ListOutbounds()
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range list {
		if o.Tag == "sub-node-1" || o.Tag == "sub-node-2" {
			t.Fatalf("subscription node survived removal: %+v", list)
		}
	}

	status, data = call(t, http.MethodGet, base+"/api/subscriptions", token, nil)
	if status != http.StatusOK || len(data["subscriptions"].([]any)) != 0 {
		t.Fatalf("after remove: status %d, %v", status, data)
	}
}

// TestImportDetectsSubscriptionURL checks that a clipboard import of a bare
// URL registers a subscription instead of failing share-link parsing
func TestImportDetectsSubscriptionURL(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, []byte(testConfig), 0644); err != nil {
		t.Fatal(err)
	}

	editor := configfile.New(configPath)
	vpn := domain.NewVPNService(&nopProcessManager{}, &nopStorage{})
	settings := domain.NewSettingsService(editor, vpn)
	importer := domain.NewImportService(sharelink.Parser{}, editor, vpn)

	fetch := func(url string) (string, error) {
		return "vless://u1@a.example.com:443?security=tls#from-sub", nil
	}
	store := subscription.NewStore(filepath.Join(dir, "subscriptions.json"))
	subs := domain.NewSubscriptionService(store, fetch, sharelink.Parser{}, editor, vpn)

	clip := func() (string, error) { return "https://p.example/sub", nil }
	server := New(settings, importer, nil, nil, subs, Sources{Clipboard: clip}, LogAccess{})
	pageURL, err := server.start()
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	u, _ := url.Parse(pageURL)
	token := u.Query().Get("t")
	base := "http://" + u.Host

	status, data := call(t, http.MethodPost, base+"/api/import", token,
		map[string]string{"source": "clipboard"})
	if status != http.StatusOK {
		t.Fatalf("import: status %d, %v", status, data)
	}
	if data["subscription"] != true {
		t.Fatalf("URL import must be flagged as a subscription: %v", data)
	}

	saved, err := store.Load()
	if err != nil || len(saved) != 1 {
		t.Fatalf("subscription not saved: %v %+v", err, saved)
	}
}
