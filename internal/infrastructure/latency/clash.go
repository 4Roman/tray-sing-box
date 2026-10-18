// Package latency measures the delay of the config's servers
// (docs/design/latency-test.md §3.4). A separate, short-lived sing-box — the
// app's own sing-box.exe with a config built in memory from config.json
// (configfile's ProbePlan) and a Clash API of its own on a free loopback port
// — runs the delay tests sing-box's urltest groups run; this package starts
// it, asks it, and ends it. The running VPN, its process and config.json are
// never touched, and the VPN's own urltest groups are not re-evaluated (a
// delay test on the VPN's instance would, and could switch them).
package latency

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"tray-sing-box/internal/config"
	"tray-sing-box/internal/domain"
)

// ErrForeignPort: a connection to the test instance's API port reached a
// process other than the test instance (ownedDial). Closed before its first
// byte: the secret never reaches it. The check is aborted — the answers
// could not be trusted either.
var ErrForeignPort = errors.New("Порт проверки занят другой программой — проверка прервана")

var (
	// errUnauthorized: the test instance refused the secret it was started
	// with (401): the answers of whatever is listening cannot be trusted
	errUnauthorized = errors.New("the Clash API refused the secret")
	// errNoAnswer stands for any failed request: the client's own errors
	// name the URL (the port) and the dialed address, and this text may
	// reach a log or the page
	errNoAnswer = errors.New("no answer from the Clash API")
	errBadReply = errors.New("not an answer of sing-box's Clash API")
)

// responseLimit bounds what is read of any answer: the Clash API's are a few
// dozen bytes
const responseLimit = 1 << 20

// The measurement, from config; variables for the tests
var (
	testURL           = config.LatencyTestURL
	probeTimeoutMs    = config.LatencyProbeTimeoutMs
	probeConcurrency  = config.LatencyConcurrency
	probeRounds       = config.LatencyRounds
	versionTimeout    = 2 * time.Second
	requestSlack      = 3 * time.Second // on top of the probe timeout, for sing-box to answer 504
	noteNotInInstance = "нет в тестовом конфиге"
)

// client talks to the Clash API of one test instance
type client struct {
	host   string // 127.0.0.1:<port>
	secret string
	http   *http.Client

	testURL        string
	probeTimeoutMs int
	concurrency    int
	rounds         int
}

// newClient returns a client for the Clash API on 127.0.0.1:port; dial makes
// every connection (ownedDial: only to the test instance's own listener).
// Nothing of the environment is used: no proxy, no redirect followed.
func newClient(port int, secret string, dial func(ctx context.Context, network, addr string) (net.Conn, error)) *client {
	return &client{
		host:   net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		secret: secret,
		http: &http.Client{
			Transport: &http.Transport{
				Proxy:               nil,
				DialContext:         dial,
				MaxIdleConnsPerHost: probeConcurrency,
				DisableCompression:  true,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		testURL:        testURL,
		probeTimeoutMs: probeTimeoutMs,
		concurrency:    probeConcurrency,
		rounds:         probeRounds,
	}
}

// get sends one authorized GET and returns the status and the (bounded)
// body. rawPath is the path as it goes on the wire (see escapeAll), path its
// decoded form. The error never quotes the URL, the address or a header: it
// is ErrForeignPort, a context error or errNoAnswer.
func (c *client) get(ctx context.Context, path, rawPath, query string) (int, []byte, error) {
	u := &url.URL{Scheme: "http", Host: c.host, Path: path, RawPath: rawPath, RawQuery: query}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return 0, nil, errNoAnswer
	}
	req.Header.Set("Authorization", "Bearer "+c.secret)
	resp, err := c.http.Do(req)
	if err != nil {
		switch {
		case errors.Is(err, ErrForeignPort):
			return 0, nil, ErrForeignPort
		case ctx.Err() != nil:
			return 0, nil, ctx.Err()
		}
		return 0, nil, errNoAnswer
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, responseLimit))
	if err != nil {
		if ctx.Err() != nil {
			return 0, nil, ctx.Err()
		}
		return 0, nil, errNoAnswer
	}
	return resp.StatusCode, body, nil
}

// version asks the API for sing-box's version: nil once the test instance
// answers (it listens only after every outbound is up), errUnauthorized on a
// 401, another error while it is not there yet
func (c *client) version(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, versionTimeout)
	defer cancel()
	status, body, err := c.get(ctx, "/version", "", "")
	switch {
	case err != nil:
		return err
	case status == http.StatusUnauthorized:
		return errUnauthorized
	case status != http.StatusOK:
		return fmt.Errorf("%w (status %d)", errBadReply, status)
	}
	var reply struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(body, &reply) != nil || reply.Version == "" {
		return errBadReply
	}
	return nil
}

// delay runs one delay test of the outbound tag. The error is set only when
// the whole measurement must stop: errUnauthorized, ErrForeignPort, or
// errNoAnswer — a request that failed below HTTP on the loopback means a
// test instance that is gone or broken, not a slow server. Every other
// outcome is a status: 200 ok, 504 timeout (sing-box's own probe timeout),
// 503 error, 404 error (no such outbound in the test instance), a check
// that ended meanwhile unfinished.
func (c *client) delay(ctx context.Context, tag string) (domain.Delay, error) {
	reqCtx, cancel := context.WithTimeout(ctx, time.Duration(c.probeTimeoutMs)*time.Millisecond+requestSlack)
	defer cancel()
	query := url.Values{"timeout": {strconv.Itoa(c.probeTimeoutMs)}, "url": {c.testURL}}.Encode()
	status, body, err := c.get(reqCtx, "/proxies/"+tag+"/delay", "/proxies/"+escapeAll(tag)+"/delay", query)
	if err != nil {
		switch {
		case errors.Is(err, ErrForeignPort):
			return domain.Delay{}, err
		case ctx.Err() != nil:
			return domain.Delay{Status: domain.LatencyUnfinished}, nil
		case reqCtx.Err() != nil:
			// sing-box did not even answer with its own timeout
			return domain.Delay{Status: domain.LatencyTimeout}, nil
		}
		return domain.Delay{}, errNoAnswer
	}
	switch status {
	case http.StatusOK:
		var reply struct {
			Delay int `json:"delay"`
		}
		if json.Unmarshal(body, &reply) != nil || reply.Delay <= 0 {
			return domain.Delay{Status: domain.LatencyError}, nil
		}
		return domain.Delay{Ms: reply.Delay, Status: domain.LatencyOK}, nil
	case http.StatusGatewayTimeout:
		return domain.Delay{Status: domain.LatencyTimeout}, nil
	case http.StatusNotFound:
		return domain.Delay{Status: domain.LatencyError, Note: noteNotInInstance}, nil
	case http.StatusUnauthorized:
		return domain.Delay{}, errUnauthorized
	}
	return domain.Delay{Status: domain.LatencyError}, nil
}

// escapeAll writes every byte of a tag as %XX. The path then never has the
// standard encoding, so Go's server keeps it in RawPath, and the Clash API's
// router (chi) matches and unescapes exactly that once: the tag comes out as
// it is. With the standard encoding RawPath stays empty, chi works on the
// already decoded Path and sing-box unescapes it a second time — "a%41"
// would address "aA". Also keeps /, ?, #, spaces and any UTF-8 in one
// segment.
func escapeAll(tag string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(3 * len(tag))
	for i := 0; i < len(tag); i++ {
		b.WriteByte('%')
		b.WriteByte(hex[tag[i]>>4])
		b.WriteByte(hex[tag[i]&15])
	}
	return b.String()
}

// measureAll measures the tags, at most c.concurrency at a time, started in
// the order given (the caller puts the active server first: with hundreds of
// servers the check may end before the last ones). The servers that answered
// are measured again (c.rounds in all) once every one has had its first
// test, and the fastest answer counts: the first connection pays for DNS and
// the like. A tag not measured when ctx ends is unfinished. The error is
// set only when the measurement had to stop (see delay); the results so far
// are returned either way.
func measureAll(ctx context.Context, c *client, tags []string) (map[string]domain.Delay, error) {
	results := make(map[string]domain.Delay, len(tags))
	var pending []string
	for _, tag := range tags {
		if _, dup := results[tag]; !dup {
			results[tag] = domain.Delay{Status: domain.LatencyUnfinished}
			pending = append(pending, tag)
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		mu    sync.Mutex
		fatal error
	)
	slots := max(c.concurrency, 1)
	for round := 0; round < c.rounds && len(pending) > 0; round++ {
		answered := make(map[string]bool, len(pending))
		sem := make(chan struct{}, slots)
		var wg sync.WaitGroup
	dispatch:
		for _, tag := range pending {
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				break dispatch
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				d, err := c.delay(ctx, tag)
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					if fatal == nil {
						fatal = err
					}
					cancel()
					return
				}
				switch {
				case round == 0:
					results[tag] = d
				case d.Status == domain.LatencyOK && d.Ms < results[tag].Ms:
					results[tag] = d
				}
				if d.Status == domain.LatencyOK {
					answered[tag] = true
				}
			}()
		}
		wg.Wait()
		if ctx.Err() != nil {
			break
		}
		next := pending[:0:0]
		for _, tag := range pending {
			if answered[tag] {
				next = append(next, tag)
			}
		}
		pending = next
	}
	return results, fatal
}
