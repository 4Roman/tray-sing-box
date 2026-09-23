package nettrust

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// A certificate only a test (or a program of the user) trusts is refused.
// The request goes to a host name (httptest's certificate is issued for
// example.com), dialled to the local test server, so the chain check itself
// is what refuses it — not a missing server name.
func TestClientRefusesAnUntrustedServer(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	client := Client(0)
	tr := client.Transport.(*http.Transport)
	addr := srv.Listener.Addr().String()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	resp, err := client.Get("https://example.com/")
	if err == nil {
		resp.Body.Close()
		t.Fatal("the test server's certificate was accepted")
	}
	if !strings.Contains(err.Error(), "not trusted") {
		t.Fatalf("refused for another reason: %v", err)
	}
}

// https to an IP address: no server name to check the certificate against
func TestClientRefusesAnIPLiteral(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	if resp, err := Client(0).Get(srv.URL); err == nil {
		resp.Body.Close()
		t.Fatal("accepted")
	}
}

func TestClientIgnoresTheProxyEnvironment(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	tr := Client(0).Transport.(*http.Transport)
	if tr.Proxy != nil {
		t.Fatal("a proxy function is set")
	}
}

func TestNoDowngrade(t *testing.T) {
	https, _ := http.NewRequest("GET", "https://a.example/", nil)
	plain, _ := http.NewRequest("GET", "http://b.example/", nil)
	if err := noDowngrade(plain, []*http.Request{https}); err == nil {
		t.Fatal("https -> http redirect allowed")
	}
	if err := noDowngrade(https, []*http.Request{plain}); err != nil {
		t.Fatalf("http -> https refused: %v", err)
	}
}

// Real TLS against GitHub (network): the machine's roots are enough
func TestClientReachesGitHub(t *testing.T) {
	if testing.Short() || os.Getenv("CI") != "" && os.Getenv("NETTRUST_NETWORK") == "" {
		t.Skip("network test")
	}
	resp, err := Client(0).Get("https://api.github.com/")
	if err != nil {
		if strings.Contains(err.Error(), "not trusted") || strings.Contains(err.Error(), "policy") {
			t.Fatalf("GitHub's certificate refused: %v", err)
		}
		t.Skipf("network unavailable: %v", err)
	}
	resp.Body.Close()
}
