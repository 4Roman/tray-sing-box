// Package nettrust builds the HTTP clients of the elevated app. It runs
// elevated with the user's environment, so two things a non-elevated program
// of the user controls must not decide what it downloads — and it downloads
// sing-box.exe, which then runs as administrator:
//
//   - the proxy: HTTP_PROXY/HTTPS_PROXY come from the environment (a user
//     variable overrides a system one), so the proxy is not taken from there;
//   - TLS trust: Go's Windows verifier uses the current user's certificate
//     chain engine, whose Root store any program of the user may add to. The
//     clients here verify against the machine's stores only.
//
// Redirects from https to http are refused.
package nettrust

import (
	"errors"
	"net/http"
	"time"
)

// Client returns an HTTP client for the elevated app
func Client(timeout time.Duration) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	tr.TLSClientConfig = tlsConfig()
	return &http.Client{Timeout: timeout, Transport: tr, CheckRedirect: noDowngrade}
}

func noDowngrade(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	for _, prev := range via {
		if prev.URL.Scheme == "https" && req.URL.Scheme != "https" {
			return errors.New("redirect from https to http refused")
		}
	}
	return nil
}
