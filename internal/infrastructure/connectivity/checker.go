// Package connectivity probes whether internet traffic actually flows while
// the VPN is running ("process alive" does not imply "tunnel works").
package connectivity

import (
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// defaultTargets are generate_204-style endpoints: tiny responses, no
// caching, served from infrastructure that is up if anything is
var defaultTargets = []string{
	"http://www.gstatic.com/generate_204",
	"http://cp.cloudflare.com/generate_204",
}

// Probe makes a tiny HTTP request and reports whether the internet is
// reachable. With proxyURL set (http://127.0.0.1:port or socks5://...), the
// request goes through the local sing-box inbound — the most direct proof
// the tunnel works. Without it the request goes out normally, which still
// crosses sing-box when it runs in TUN mode. Success on any target wins.
func Probe(proxyURL string, targets ...string) error {
	if len(targets) == 0 {
		targets = defaultTargets
	}

	// Fresh connections on purpose: the point is to test the current network
	// path, not to reuse a connection from before a VPN restart
	transport := &http.Transport{DisableKeepAlives: true}
	if proxyURL != "" {
		u, err := url.Parse(proxyURL)
		if err != nil {
			return fmt.Errorf("bad proxy url %q: %w", proxyURL, err)
		}
		transport.Proxy = http.ProxyURL(u)
	}
	client := &http.Client{Timeout: 8 * time.Second, Transport: transport}
	defer transport.CloseIdleConnections()

	var lastErr error
	for _, target := range targets {
		resp, err := client.Get(target)
		if err != nil {
			lastErr = err
			continue
		}
		resp.Body.Close()
		if resp.StatusCode < 500 {
			return nil
		}
		lastErr = fmt.Errorf("HTTP %s from %s", resp.Status, target)
	}
	return lastErr
}
