package subscription

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

// maxBodySize caps a subscription download; share-link lists are small, so a
// multi-megabyte body means a wrong URL rather than a huge node list
const maxBodySize = 8 << 20 // 8 MB

var client = &http.Client{Timeout: 30 * time.Second}

// Fetch downloads the subscription body. Some providers vary the response
// format by User-Agent; a v2ray-style UA gets the plain/base64 share-link
// form instead of a Clash YAML profile.
func Fetch(url string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "v2rayN/tray-sing-box")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %s", resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize+1))
	if err != nil {
		return "", err
	}
	if len(body) > maxBodySize {
		return "", fmt.Errorf("subscription body exceeds %d MB", maxBodySize>>20)
	}
	return string(body), nil
}
