package subscription

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
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
