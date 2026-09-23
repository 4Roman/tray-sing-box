package subscription

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"tray-sing-box/internal/domain"
	"tray-sing-box/internal/infrastructure/nettrust"
)

// maxBodySize caps a subscription download; share-link lists are small, so a
// multi-megabyte body means a wrong URL rather than a huge node list
const maxBodySize = 8 << 20 // 8 MB

// The elevated app's client: no proxy from the (user-controlled)
// environment, TLS against the machine's roots, no https->http redirect
var client = nettrust.Client(30 * time.Second)

// Fetch downloads the subscription body. Some providers vary the response
// format by User-Agent; a v2ray-style UA gets the plain/base64 share-link
// form instead of a Clash YAML profile. Errors never carry the URL (see
// redact).
func Fetch(rawURL string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return "", redact(err)
	}
	req.Header.Set("User-Agent", "v2rayN/tray-sing-box")

	resp, err := client.Do(req)
	if err != nil {
		return "", redact(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %s", resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize+1))
	if err != nil {
		return "", redact(err)
	}
	if len(body) > maxBodySize {
		return "", fmt.Errorf("subscription body exceeds %d MB", maxBodySize>>20)
	}
	return string(body), nil
}

// redact takes the URL out of an error. net/http names the full request URL
// (or a redirect's target) in its *url.Error — `Get "https://…?token=…":
// dial tcp …` — and the error ends up in the log, a tray popup and the
// settings page, while the URL carries the provider's access token. The URL
// is replaced by its domain.RedactURL form; the rest of the message and the
// error's Timeout() stay.
func redact(err error) error {
	if ue, ok := err.(*url.Error); ok {
		return &url.Error{Op: ue.Op, URL: domain.RedactURL(ue.URL), Err: redact(ue.Err)}
	}
	return err
}
