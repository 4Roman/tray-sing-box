package connectivity

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProbeSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	if err := Probe("", srv.URL); err != nil {
		t.Fatalf("Probe: %v", err)
	}
}

func TestProbeSecondTargetWins(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	// First target unreachable, second fine -> overall success
	if err := Probe("", "http://127.0.0.1:1/unreachable", srv.URL); err != nil {
		t.Fatalf("Probe: %v", err)
	}
}

func TestProbeAllTargetsFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusBadGateway)
	}))
	defer srv.Close()

	if err := Probe("", srv.URL, "http://127.0.0.1:1/unreachable"); err == nil {
		t.Fatal("want error when every target fails")
	}
}

func TestProbeThroughHTTPProxy(t *testing.T) {
	var proxied bool
	// A trivial HTTP forward proxy: absolute-URI requests are answered 204
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.IsAbs() {
			proxied = true
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer proxy.Close()

	if err := Probe(proxy.URL, "http://target.invalid/generate_204"); err != nil {
		t.Fatalf("Probe via proxy: %v", err)
	}
	if !proxied {
		t.Fatal("request did not go through the proxy")
	}
}

func TestProbeBadProxyURL(t *testing.T) {
	if err := Probe("://broken", "http://target.invalid/"); err == nil {
		t.Fatal("want error for unparsable proxy url")
	}
}
