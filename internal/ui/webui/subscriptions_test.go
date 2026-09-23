package webui

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tray-sing-box/internal/domain"
	"tray-sing-box/internal/infrastructure/configfile"
	"tray-sing-box/internal/infrastructure/sharelink"
	"tray-sing-box/internal/infrastructure/subscription"
)

// A subscription URL as providers hand them out: the access token sits in
// the userinfo, the path and the query. None of it may reach the page.
const secretSubURL = "https://usersecret:pwsecret@p.example/api/v1/client/pathsecret?token=querysecret#fragsecret"

var subURLSecrets = []string{"usersecret", "pwsecret", "pathsecret", "querysecret", "fragsecret"}

// assertNoSubURL fails when a response body contains any part of the secret
// subscription URL
func assertNoSubURL(t *testing.T, what, body string) {
	t.Helper()
	for _, secret := range subURLSecrets {
		if strings.Contains(body, secret) {
			t.Fatalf("%s reveals the subscription URL (%q): %s", what, secret, body)
		}
	}
}

// newSubsTestServer serves a real config editor and file store; only the
// fetch is stubbed
func newSubsTestServer(t *testing.T, clip TextSource) (*Server, string, *configfile.Editor, *subscription.Store) {
	t.Helper()
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

	server := New(settings, importer, nil, nil, subs, nil, Sources{Clipboard: clip}, LogAccess{})
	return server, start(t, server), editor, store
}

func outboundTags(t *testing.T, editor *configfile.Editor) map[string]bool {
	t.Helper()
	list, err := editor.ListOutbounds()
	if err != nil {
		t.Fatal(err)
	}
	tags := map[string]bool{}
	for _, o := range list {
		tags[o.Tag] = true
	}
	return tags
}

// TestSubscriptionEndpoints drives add -> list -> update -> remove through
// the HTTP API. The page names subscriptions by id and a redacted URL; the
// URL itself never comes back.
func TestSubscriptionEndpoints(t *testing.T) {
	server, base, editor, _ := newSubsTestServer(t, nil)
	session := login(t, server)
	id := domain.SubscriptionID(secretSubURL)
	display := domain.RedactURL(secretSubURL)

	// Add: takes the URL the user typed, answers with the redacted form only
	status, raw := callRaw(t, http.MethodPost, base+"/api/subscriptions/add", session,
		map[string]string{"url": secretSubURL})
	if status != http.StatusOK {
		t.Fatalf("add: status %d, %s", status, raw)
	}
	assertNoSubURL(t, "add", raw)
	_, data := call(t, http.MethodPost, base+"/api/subscriptions/add", session,
		map[string]string{"url": secretSubURL}) // again: a refresh
	updates := data["updates"].([]any)
	if len(updates) != 1 {
		t.Fatalf("add updates = %#v", updates)
	}
	u := updates[0].(map[string]any)
	if u["count"].(float64) != 2 || u["id"] != id || u["display"] != display {
		t.Fatalf("add update = %#v, want id %s display %s", u, id, display)
	}
	if tags := outboundTags(t, editor); !tags["sub-node-1"] || !tags["sub-node-2"] {
		t.Fatalf("subscription nodes missing from config: %v", tags)
	}

	// List
	status, raw = callRaw(t, http.MethodGet, base+"/api/subscriptions", session, nil)
	if status != http.StatusOK {
		t.Fatalf("list: status %d", status)
	}
	assertNoSubURL(t, "list", raw)
	_, data = call(t, http.MethodGet, base+"/api/subscriptions", session, nil)
	subsList := data["subscriptions"].([]any)
	if len(subsList) != 1 {
		t.Fatalf("list = %#v", subsList)
	}
	entry := subsList[0].(map[string]any)
	if entry["id"] != id || entry["display"] != display || entry["count"].(float64) != 2 || entry["updated"] == nil {
		t.Fatalf("list entry = %#v", entry)
	}
	if _, ok := entry["url"]; ok {
		t.Fatalf("list entry has a url field: %#v", entry)
	}

	// Update by id, then all (empty id); an unknown id is an error
	status, raw = callRaw(t, http.MethodPost, base+"/api/subscriptions/update", session, map[string]string{"id": id})
	if status != http.StatusOK {
		t.Fatalf("update by id: status %d, %s", status, raw)
	}
	assertNoSubURL(t, "update", raw)
	if status, data := call(t, http.MethodPost, base+"/api/subscriptions/update", session, map[string]string{"id": ""}); status != http.StatusOK ||
		len(data["updates"].([]any)) != 1 {
		t.Fatalf("update all: status %d, %v", status, data)
	}
	if status, _ := call(t, http.MethodPost, base+"/api/subscriptions/update", session, map[string]string{"id": "0123456789abcdef"}); status != http.StatusBadRequest {
		t.Fatalf("update of an unknown id: status %d", status)
	}
	// The old URL-addressed form finds nothing to remove
	if status, _ := call(t, http.MethodPost, base+"/api/subscriptions/remove", session, map[string]string{"url": secretSubURL}); status != http.StatusBadRequest {
		t.Fatalf("remove by url: status %d", status)
	}

	// Remove by id deletes the nodes too
	status, raw = callRaw(t, http.MethodPost, base+"/api/subscriptions/remove", session, map[string]string{"id": id})
	if status != http.StatusOK {
		t.Fatalf("remove: status %d, %s", status, raw)
	}
	assertNoSubURL(t, "remove", raw)
	if tags := outboundTags(t, editor); tags["sub-node-1"] || tags["sub-node-2"] {
		t.Fatalf("subscription node survived removal: %v", tags)
	}

	status, data = call(t, http.MethodGet, base+"/api/subscriptions", session, nil)
	if status != http.StatusOK || len(data["subscriptions"].([]any)) != 0 {
		t.Fatalf("after remove: status %d, %v", status, data)
	}
}

// An add that fails names the URL in the redacted form too
func TestSubscriptionAddErrorRedacted(t *testing.T) {
	server, base, _, _ := newSubsTestServer(t, nil)
	session := login(t, server)

	// Not a subscription URL (whitespace inside): refused by the domain
	bad := "https://p.example/x pathsecret?token=querysecret"
	status, raw := callRaw(t, http.MethodPost, base+"/api/subscriptions/add", session, map[string]string{"url": bad})
	if status != http.StatusBadRequest {
		t.Fatalf("status %d, %s", status, raw)
	}
	assertNoSubURL(t, "add error", raw)
}

// TestImportDetectsSubscriptionURL checks that a clipboard import of a bare
// URL registers a subscription instead of failing share-link parsing
func TestImportDetectsSubscriptionURL(t *testing.T) {
	clip := func() (string, error) { return secretSubURL, nil }
	server, base, _, store := newSubsTestServer(t, clip)

	status, raw := callRaw(t, http.MethodPost, base+"/api/import", login(t, server),
		map[string]string{"source": "clipboard"})
	if status != http.StatusOK {
		t.Fatalf("import: status %d, %s", status, raw)
	}
	if !strings.Contains(raw, `"subscription":true`) {
		t.Fatalf("URL import must be flagged as a subscription: %s", raw)
	}
	assertNoSubURL(t, "import", raw)

	saved, err := store.Load()
	if err != nil || len(saved) != 1 || saved[0].URL != secretSubURL {
		t.Fatalf("subscription not saved: %v %+v", err, saved)
	}
}
