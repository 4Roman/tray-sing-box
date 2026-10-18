package latency

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"tray-sing-box/internal/domain"
)

const testSecret = "f00dfeedcafe0123456789abcdef0123456789abcdef0123456789abcdef0123"

// fakeAPI answers like sing-box's Clash API: Bearer authorization, and the
// proxy name taken the way its router does — chi matches on RawPath when Go's
// server set it and on the decoded Path otherwise, and sing-box unescapes the
// name once more (getEscapeParam). A client sending the standard encoding is
// decoded twice here, exactly as there.
type fakeAPI struct {
	t *testing.T
	// reply answers the n-th (from 1) delay test of a tag; nil: 404
	reply func(tag string, n int, r *http.Request) (int, string)

	mu       sync.Mutex
	requests map[string]int
	order    []string // "tag#n" in the order the tests arrived
	inFlight int
	most     int
	queries  []url.Values
	paths    []string // anything requested besides delay tests and /version
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+testSecret {
		http.Error(w, `{"message":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}
	route := r.URL.RawPath
	if route == "" {
		route = r.URL.Path
	}
	if route == "/version" {
		fmt.Fprint(w, `{"meta":true,"premium":true,"version":"sing-box 1.14.2"}`)
		return
	}
	parts := strings.Split(route, "/")
	if len(parts) != 4 || parts[1] != "proxies" || parts[3] != "delay" {
		f.mu.Lock()
		f.paths = append(f.paths, route)
		f.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	tag := parts[2]
	if unescaped, err := url.PathUnescape(tag); err == nil {
		tag = unescaped
	}
	f.mu.Lock()
	f.requests[tag]++
	n := f.requests[tag]
	f.order = append(f.order, tag+"#"+strconv.Itoa(n))
	f.queries = append(f.queries, r.URL.Query())
	f.inFlight++
	f.most = max(f.most, f.inFlight)
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.inFlight--
		f.mu.Unlock()
	}()
	status, body := http.StatusNotFound, `{"message":"Resource not found"}`
	if f.reply != nil {
		status, body = f.reply(tag, n, r)
	}
	if status == http.StatusFound {
		http.Redirect(w, r, body, status)
		return
	}
	w.WriteHeader(status)
	fmt.Fprint(w, body)
}

func (f *fakeAPI) count(tag string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests[tag]
}

// startFakeAPI serves f and returns a client for it (default dialer)
func startFakeAPI(t *testing.T, f *fakeAPI) *client {
	t.Helper()
	f.t = t
	f.requests = map[string]int{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	_, portText, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	var d net.Dialer
	return newClient(port, testSecret, d.DialContext)
}

func delayReply(ms int) (int, string) {
	return http.StatusOK, fmt.Sprintf(`{"delay":%d}`, ms)
}

func TestEscapeAll(t *testing.T) {
	for tag, want := range map[string]string{
		"":      "",
		"aA":    "%61%41",
		"a%41":  "%61%25%34%31",
		"a/b":   "%61%2F%62",
		"ж":     "%D0%B6",
		"🙂":     "%F0%9F%99%82",
		"a b?#": "%61%20%62%3F%23",
	} {
		if got := escapeAll(tag); got != want {
			t.Errorf("escapeAll(%q) = %q, want %q", tag, got, want)
		}
	}
}

// Every tag reaches its own outbound through the router that decodes twice
// when RawPath is empty: "a%41" must not address "aA"
func TestDelayAddressesTheExactTag(t *testing.T) {
	tags := map[string]int{"a%41": 11, "aA": 22, "a/b": 33, "кир 🙂": 44, "sp ace?#&": 55, "100%": 66}
	f := &fakeAPI{reply: func(tag string, _ int, _ *http.Request) (int, string) {
		if ms, ok := tags[tag]; ok {
			return delayReply(ms)
		}
		return http.StatusNotFound, `{"message":"Resource not found"}`
	}}
	c := startFakeAPI(t, f)
	c.rounds = 1
	var list []string
	for tag := range tags {
		list = append(list, tag)
	}
	got, err := measureAll(context.Background(), c, list)
	if err != nil {
		t.Fatal(err)
	}
	for tag, ms := range tags {
		if d := got[tag]; d.Status != domain.LatencyOK || d.Ms != ms {
			t.Errorf("%q: %+v, want ok %d ms", tag, d, ms)
		}
		if n := f.count(tag); n != 1 {
			t.Errorf("%q requested %d times, want 1", tag, n)
		}
	}
	if len(f.paths) != 0 {
		t.Errorf("requests outside the delay route: %q", f.paths)
	}
}

// The query carries the probe timeout and the fixed test URL
func TestDelayQuery(t *testing.T) {
	f := &fakeAPI{reply: func(string, int, *http.Request) (int, string) { return delayReply(5) }}
	c := startFakeAPI(t, f)
	c.probeTimeoutMs = 1234
	c.testURL = "https://example.test/generate_204?x=1&y=2"
	if d, err := c.delay(context.Background(), "n"); err != nil || d.Status != domain.LatencyOK {
		t.Fatalf("delay: %+v, %v", d, err)
	}
	q := f.queries[0]
	if q.Get("timeout") != "1234" || q.Get("url") != c.testURL || len(q) != 2 {
		t.Errorf("query %v, want timeout=1234 and url=%s only", q, c.testURL)
	}
}

func TestDelayStatuses(t *testing.T) {
	redirected := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirected = true
		fmt.Fprint(w, `{"delay":1}`)
	}))
	defer target.Close()
	f := &fakeAPI{reply: func(tag string, _ int, _ *http.Request) (int, string) {
		switch tag {
		case "ok":
			return delayReply(84)
		case "zero":
			return delayReply(0)
		case "timeout":
			return http.StatusGatewayTimeout, `{"message":"Timeout"}`
		case "error":
			return http.StatusServiceUnavailable, `{"message":"An error occurred in the delay test"}`
		case "bad request":
			return http.StatusBadRequest, `{"message":"Body invalid"}`
		case "garbage":
			return http.StatusOK, `<html>`
		case "huge":
			// A valid answer, but beyond what is read of one
			return http.StatusOK, `{"delay":7,"pad":"` + strings.Repeat("x", responseLimit) + `"}`
		case "redirect":
			return http.StatusFound, target.URL + "/proxies/ok/delay"
		}
		return http.StatusNotFound, `{"message":"Resource not found"}`
	}}
	c := startFakeAPI(t, f)
	for tag, want := range map[string]domain.Delay{
		"ok":          {Ms: 84, Status: domain.LatencyOK},
		"zero":        {Status: domain.LatencyError},
		"timeout":     {Status: domain.LatencyTimeout},
		"error":       {Status: domain.LatencyError},
		"bad request": {Status: domain.LatencyError},
		"garbage":     {Status: domain.LatencyError},
		"huge":        {Status: domain.LatencyError},
		"redirect":    {Status: domain.LatencyError},
		"missing":     {Status: domain.LatencyError, Note: noteNotInInstance},
	} {
		d, err := c.delay(context.Background(), tag)
		if err != nil || d != want {
			t.Errorf("%q: %+v, %v; want %+v", tag, d, err, want)
		}
	}
	if redirected {
		t.Error("a redirect was followed")
	}
}

// A 401 stops the whole measurement: whatever answers does not know the
// secret, nothing it says counts
func TestMeasureAllStopsOnUnauthorized(t *testing.T) {
	f := &fakeAPI{reply: func(tag string, _ int, _ *http.Request) (int, string) {
		if tag == "refused" {
			return http.StatusUnauthorized, `{"message":"Unauthorized"}`
		}
		time.Sleep(20 * time.Millisecond)
		return delayReply(10)
	}}
	c := startFakeAPI(t, f)
	c.concurrency = 1
	got, err := measureAll(context.Background(), c, []string{"a", "refused", "b", "c"})
	if !errors.Is(err, errUnauthorized) {
		t.Fatalf("error %v, want errUnauthorized", err)
	}
	if got["a"].Status != domain.LatencyOK {
		t.Errorf("a: %+v, want the answer before the refusal", got["a"])
	}
	for _, tag := range []string{"b", "c"} {
		if f.count(tag) != 0 || got[tag].Status != domain.LatencyUnfinished {
			t.Errorf("%s: requested %d times, %+v; want never requested, unfinished", tag, f.count(tag), got[tag])
		}
	}

	// A wrong secret: the client's own header is what is checked
	c.secret = "not-the-secret"
	if err := c.version(context.Background()); !errors.Is(err, errUnauthorized) {
		t.Errorf("version with a wrong secret: %v, want errUnauthorized", err)
	}
	c.secret = testSecret
	if err := c.version(context.Background()); err != nil {
		t.Errorf("version: %v", err)
	}
}

func TestVersion(t *testing.T) {
	answer := ""
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testSecret {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(status)
		fmt.Fprint(w, answer)
	}))
	defer srv.Close()
	port, _ := strconv.Atoi(srv.URL[strings.LastIndex(srv.URL, ":")+1:])
	var d net.Dialer
	c := newClient(port, testSecret, d.DialContext)
	for _, tc := range []struct {
		status int
		answer string
		ok     bool
	}{
		{http.StatusOK, `{"version":"sing-box 1.14.2"}`, true},
		{http.StatusOK, `{"hello":"world"}`, false},
		{http.StatusOK, `not json`, false},
		{http.StatusNotFound, `{"version":"sing-box 1.14.2"}`, false},
		{http.StatusOK, `{"version":"` + strings.Repeat("1", responseLimit) + `"}`, false},
	} {
		status, answer = tc.status, tc.answer
		if err := c.version(context.Background()); (err == nil) != tc.ok {
			t.Errorf("status %d, %.40q: %v, want ok=%v", tc.status, tc.answer, err, tc.ok)
		}
	}
}

func TestMeasureAllConcurrency(t *testing.T) {
	release := make(chan struct{})
	f := &fakeAPI{reply: func(string, int, *http.Request) (int, string) {
		<-release
		return delayReply(10)
	}}
	c := startFakeAPI(t, f)
	c.rounds = 1
	var tags []string
	for i := range 30 {
		tags = append(tags, "n"+strconv.Itoa(i))
	}
	done := make(chan map[string]domain.Delay)
	go func() {
		got, _ := measureAll(context.Background(), c, tags)
		done <- got
	}()
	// Wait for the slots to fill, then for anything beyond them
	deadline := time.Now().Add(5 * time.Second)
	for {
		f.mu.Lock()
		n := f.inFlight
		f.mu.Unlock()
		if n >= probeConcurrency || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	f.mu.Lock()
	most := f.most
	f.mu.Unlock()
	close(release)
	got := <-done
	if most != probeConcurrency {
		t.Errorf("%d delay tests in flight at most, want %d", most, probeConcurrency)
	}
	for _, tag := range tags {
		if got[tag].Status != domain.LatencyOK {
			t.Errorf("%s: %+v", tag, got[tag])
		}
	}
}

// The servers that answered are measured once more after every server had
// its first test, and the faster answer counts; the others only once
func TestMeasureAllRounds(t *testing.T) {
	answers := map[string][]int{ // per round; 0: 503, -1: 504
		"faster-later": {100, 60},
		"slower-later": {50, 80},
		"then-error":   {70, 0},
		"then-timeout": {90, -1},
		"timeout":      {-1},
		"error":        {0},
	}
	f := &fakeAPI{reply: func(tag string, n int, _ *http.Request) (int, string) {
		ms := answers[tag][n-1]
		switch ms {
		case 0:
			return http.StatusServiceUnavailable, `{}`
		case -1:
			return http.StatusGatewayTimeout, `{}`
		}
		return delayReply(ms)
	}}
	c := startFakeAPI(t, f)
	order := []string{"faster-later", "slower-later", "then-error", "then-timeout", "timeout", "error"}
	got, err := measureAll(context.Background(), c, order)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]domain.Delay{
		"faster-later": {Ms: 60, Status: domain.LatencyOK},
		"slower-later": {Ms: 50, Status: domain.LatencyOK},
		"then-error":   {Ms: 70, Status: domain.LatencyOK},
		"then-timeout": {Ms: 90, Status: domain.LatencyOK},
		"timeout":      {Status: domain.LatencyTimeout},
		"error":        {Status: domain.LatencyError},
	}
	for tag, w := range want {
		if got[tag] != w {
			t.Errorf("%s: %+v, want %+v", tag, got[tag], w)
		}
		if n, wantN := f.count(tag), len(answers[tag]); n != wantN {
			t.Errorf("%s: %d requests, want %d", tag, n, wantN)
		}
	}
	firstSecond := len(f.order)
	for i, r := range f.order {
		if strings.HasSuffix(r, "#2") {
			firstSecond = i
			break
		}
	}
	if firstSecond != len(order) {
		t.Errorf("order %q: a second round began before every server had its first test", f.order)
	}
}

// What the check's deadline leaves unmeasured is unfinished, and the call
// returns at the deadline
func TestMeasureAllDeadline(t *testing.T) {
	f := &fakeAPI{reply: func(tag string, _ int, r *http.Request) (int, string) {
		if tag == "stuck" {
			<-r.Context().Done()
			return http.StatusGatewayTimeout, `{}`
		}
		return delayReply(15)
	}}
	c := startFakeAPI(t, f)
	c.concurrency = 2
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	began := time.Now()
	got, err := measureAll(ctx, c, []string{"quick", "stuck", "stuck2", "later"})
	if err != nil {
		t.Fatal(err)
	}
	if took := time.Since(began); took > 2*time.Second {
		t.Errorf("returned after %v, want about the deadline", took)
	}
	// stuck holds its slot until the deadline, the others answer meanwhile
	// in the other one
	for _, tag := range []string{"quick", "stuck2", "later"} {
		if got[tag].Status != domain.LatencyOK {
			t.Errorf("%s: %+v, want ok", tag, got[tag])
		}
	}
	if got["stuck"].Status != domain.LatencyUnfinished {
		t.Errorf("stuck: %+v, want unfinished", got["stuck"])
	}
	if f.count("stuck") != 1 {
		t.Errorf("stuck requested %d times", f.count("stuck"))
	}

	// A cancel too: everything not answered is unfinished
	block := make(chan struct{})
	f2 := &fakeAPI{reply: func(_ string, _ int, r *http.Request) (int, string) {
		select {
		case <-block:
		case <-r.Context().Done():
		}
		return delayReply(1)
	}}
	c2 := startFakeAPI(t, f2)
	c2.concurrency = 1
	ctx2, cancel2 := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel2)
	got, err = measureAll(ctx2, c2, []string{"a", "b", "c"})
	close(block)
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range []string{"a", "b", "c"} {
		if got[tag].Status != domain.LatencyUnfinished {
			t.Errorf("after the cancel %s: %+v, want unfinished", tag, got[tag])
		}
	}
	if f2.count("b") != 0 {
		t.Error("a test began after the cancel")
	}
}

// sing-box does not answer even with its own 504: the client gives up a
// little after the probe timeout
func TestDelayClientTimeout(t *testing.T) {
	saved := requestSlack
	requestSlack = 50 * time.Millisecond
	defer func() { requestSlack = saved }()
	f := &fakeAPI{reply: func(_ string, _ int, r *http.Request) (int, string) {
		<-r.Context().Done()
		return delayReply(1)
	}}
	c := startFakeAPI(t, f)
	c.probeTimeoutMs = 50
	d, err := c.delay(context.Background(), "hung")
	if err != nil || d.Status != domain.LatencyTimeout {
		t.Errorf("%+v, %v; want timeout", d, err)
	}
}

// The client's errors name neither the URL (the port), the address nor the
// secret: they may reach the log and the page
func TestClientErrorsQuoteNothing(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close() // nothing listens: every dial is refused
	forbidden := []string{"127.0.0.1", strconv.Itoa(port), testSecret, "Bearer", "/version", "proxies", "http"}
	check := func(what string, err error) {
		t.Helper()
		if err == nil {
			t.Fatalf("%s: no error", what)
		}
		for _, s := range forbidden {
			if strings.Contains(err.Error(), s) {
				t.Errorf("%s: %q quotes %q", what, err, s)
			}
		}
	}
	var d net.Dialer
	c := newClient(port, testSecret, d.DialContext)
	check("refused", c.version(context.Background()))
	_, err = c.delay(context.Background(), "x")
	check("delay refused", err)
	if !errors.Is(err, errNoAnswer) {
		t.Errorf("delay on a refused port: %v, want errNoAnswer (the instance is gone)", err)
	}

	foreign := newClient(port, testSecret, func(context.Context, string, string) (net.Conn, error) {
		return nil, ErrForeignPort
	})
	err = foreign.version(context.Background())
	check("foreign", err)
	if !errors.Is(err, ErrForeignPort) {
		t.Errorf("foreign port: %v, want ErrForeignPort", err)
	}
	if _, err := foreign.delay(context.Background(), "x"); !errors.Is(err, ErrForeignPort) {
		t.Errorf("delay on a foreign port: %v, want ErrForeignPort", err)
	}
	if _, err := measureAll(context.Background(), foreign, []string{"x", "y"}); !errors.Is(err, ErrForeignPort) {
		t.Errorf("measureAll on a foreign port: %v, want ErrForeignPort", err)
	}
	check("unauthorized", errUnauthorized)
}
