package subscription

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"tray-sing-box/internal/domain"
)

func TestStoreRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "subscriptions.json")
	store := NewStore(path)

	// Missing file reads as an empty list
	subs, err := store.Load()
	if err != nil {
		t.Fatalf("Load missing: %v", err)
	}
	if len(subs) != 0 {
		t.Fatalf("want empty list, got %+v", subs)
	}

	want := []domain.Subscription{{
		URL:     "https://p.example/sub",
		Tags:    []string{"a", "b"},
		Updated: time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC),
	}}
	if err := store.Save(want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", got, want)
	}
}

func TestStoreSaveNil(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "subscriptions.json"))
	if err := store.Save(nil); err != nil {
		t.Fatalf("Save(nil): %v", err)
	}
	subs, err := store.Load()
	if err != nil || len(subs) != 0 {
		t.Fatalf("Load after Save(nil): %v, %+v", err, subs)
	}
}

// Save replaces the file with a complete new one instead of rewriting it in
// place: an interrupted save leaves the previous list, never an empty or a
// partial file (every subscription operation fails on an unreadable one)
func TestStoreSaveReplacesTheFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subscriptions.json")
	store := NewStore(path)
	if err := store.Save([]domain.Subscription{{URL: "https://p.example/a"}}); err != nil {
		t.Fatal(err)
	}
	// A second name of the file as it is now: a rewrite in place changes
	// what it shows, a replacement does not
	previous := filepath.Join(t.TempDir(), "previous.json")
	if err := os.Link(path, previous); err != nil {
		t.Skipf("no hard links here: %v", err)
	}
	before, err := os.ReadFile(previous)
	if err != nil {
		t.Fatal(err)
	}
	want := []domain.Subscription{{URL: "https://p.example/b", Tags: []string{"b"}}}
	if err := store.Save(want); err != nil {
		t.Fatal(err)
	}
	if after, err := os.ReadFile(previous); err != nil || string(after) != string(before) {
		t.Fatalf("the list was rewritten in place: %s (%v)", after, err)
	}
	if got, err := store.Load(); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("Load = %+v, %v", got, err)
	}
	assertOnlyFile(t, dir, "subscriptions.json")
}

// A rename that fails for a moment (a scanner holding the new file) is
// retried; one that keeps failing leaves the previous list and no temporary
// file behind
func TestStoreSaveRetriesTheRename(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subscriptions.json")
	store := NewStore(path)
	old := []domain.Subscription{{URL: "https://p.example/a"}}
	if err := store.Save(old); err != nil {
		t.Fatal(err)
	}

	failures := 2
	rename = func(from, to string) error {
		if failures > 0 {
			failures--
			return errors.New("sharing violation")
		}
		return os.Rename(from, to)
	}
	defer func() { rename = os.Rename }()
	want := []domain.Subscription{{URL: "https://p.example/b"}}
	if err := store.Save(want); err != nil {
		t.Fatalf("Save with a rename failing twice: %v", err)
	}
	if got, _ := store.Load(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Load = %+v", got)
	}

	failures = renameRetries
	if err := store.Save(old); err == nil {
		t.Fatal("Save succeeded although the rename never did")
	}
	if got, _ := store.Load(); !reflect.DeepEqual(got, want) {
		t.Fatalf("the previous list is lost: %+v", got)
	}
	assertOnlyFile(t, dir, "subscriptions.json")
}

// assertOnlyFile fails when dir holds anything but the named file
func assertOnlyFile(t *testing.T, dir, name string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != name {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("directory holds %v, want only %s", names, name)
	}
}

func TestFetch(t *testing.T) {
	var gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		w.Write([]byte("vless://u@h:443#node"))
	}))
	defer srv.Close()

	body, err := Fetch(srv.URL)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if body != "vless://u@h:443#node" {
		t.Fatalf("body = %q", body)
	}
	if gotUA == "" || gotUA == "Go-http-client/1.1" {
		t.Fatalf("subscription UA not set, got %q", gotUA)
	}
}

func TestFetchHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "gone", http.StatusNotFound)
	}))
	defer srv.Close()

	if _, err := Fetch(srv.URL); err == nil {
		t.Fatal("want error for HTTP 404")
	}
}

// dropConnection answers a request by closing the connection: the client
// fails with an error of its own, which names the URL
func dropConnection(w http.ResponseWriter, r *http.Request) {
	conn, _, err := w.(http.Hijacker).Hijack()
	if err == nil {
		conn.Close()
	}
}

// net/http names the request URL in its errors; the URL carries the
// provider's access token and the error reaches the log, a popup and the
// settings page. Fetch must hand out the redacted form only.
func TestFetchErrorsCarryNoURL(t *testing.T) {
	secrets := []string{"usersecret", "pwsecret", "pathsecret", "querysecret", "redirsecret"}

	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/next/pathsecret?token=redirsecret", http.StatusFound)
			return
		}
		dropConnection(w, r)
	}))
	defer failing.Close()
	host := strings.TrimPrefix(failing.URL, "http://")

	closed := httptest.NewServer(http.NotFoundHandler())
	unreachable := closed.URL
	closed.Close()

	for name, rawURL := range map[string]string{
		"dropped connection": failing.URL + "/sub/pathsecret?token=querysecret",
		"userinfo":           "http://usersecret:pwsecret@" + host + "/sub/pathsecret?token=querysecret",
		"redirect target":    failing.URL + "/start",
		"unreachable":        unreachable + "/sub/pathsecret?token=querysecret",
		"unparsable":         "http://" + host + "/%zz/pathsecret?token=querysecret",
	} {
		_, err := Fetch(rawURL)
		if err == nil {
			t.Fatalf("%s: want an error", name)
		}
		for _, secret := range secrets {
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("%s: error reveals the URL (%q): %v", name, secret, err)
			}
		}
		// The rest of the message stays, and so does the error type
		var ue *url.Error
		if !errors.As(err, &ue) || !(strings.Contains(err.Error(), "/… (") || strings.Contains(err.Error(), "(подписка ")) {
			t.Fatalf("%s: not a redacted *url.Error: %v", name, err)
		}
	}
}
