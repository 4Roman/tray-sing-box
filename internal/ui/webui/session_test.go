package webui

import (
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"tray-sing-box/internal/config"
)

// fakeClock replaces the server's clock; safe to move while the server's
// goroutines read it
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// useClock puts a fake clock into the server (under its lock: the handlers
// read s.now under it)
func useClock(server *Server) *fakeClock {
	clock := &fakeClock{t: time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)}
	server.mu.Lock()
	server.now = clock.Now
	server.mu.Unlock()
	return clock
}

// A login code works once; the session it opened can use the API
func TestLoginCodeIsSingleUse(t *testing.T) {
	server, base := newTestServer(t, nil)
	code, err := server.issueCode()
	if err != nil {
		t.Fatal(err)
	}

	status, body := get(t, base+"/login?code="+code)
	if status != http.StatusOK {
		t.Fatalf("first use: status %d: %s", status, body)
	}
	m := secretInLoginPage.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no session secret in the login page: %s", body)
	}
	if !strings.Contains(body, "location.replace") {
		t.Fatalf("the login page must take the code out of the address bar: %s", body)
	}
	if status, _ := call(t, "GET", base+"/api/config", m[1], nil); status != http.StatusOK {
		t.Fatalf("session of the login: status %d", status)
	}

	status, body = get(t, base+"/login?code="+code)
	if status != http.StatusForbidden || !strings.Contains(body, "уже была использована") {
		t.Fatalf("second use: status %d: %s", status, body)
	}
	if secretInLoginPage.MatchString(body) {
		t.Fatal("a used code produced another session")
	}
}

// A code presented a second time was in two hands: the session created with
// it is closed, whoever holds it
func TestLoginReplayRevokesTheSession(t *testing.T) {
	server, base := newTestServer(t, nil)
	other := login(t, server) // a session of another login, must survive

	code, err := server.issueCode()
	if err != nil {
		t.Fatal(err)
	}
	status, body := get(t, base+"/login?code="+code)
	if status != http.StatusOK {
		t.Fatalf("login: status %d", status)
	}
	first := secretInLoginPage.FindStringSubmatch(body)[1]

	if status, _ := get(t, base+"/login?code="+code); status != http.StatusForbidden {
		t.Fatalf("replay: status %d", status)
	}
	status, data := call(t, "GET", base+"/api/config", first, nil)
	if status != http.StatusUnauthorized || data["error"] == nil {
		t.Fatalf("session of a replayed code: status %d, %v", status, data)
	}
	if status, _ := call(t, "GET", base+"/api/config", other, nil); status != http.StatusOK {
		t.Fatalf("an unrelated session was closed: status %d", status)
	}

	// A third presentation finds nothing left: the plain "expired" answer
	status, body = get(t, base+"/login?code="+code)
	if status != http.StatusForbidden || !strings.Contains(body, "устарела") {
		t.Fatalf("third use: status %d: %s", status, body)
	}
}

// A browser prefetching or prerendering the login address from its history
// neither uses a code nor closes the session opened with it
func TestLoginIgnoresSpeculativeLoads(t *testing.T) {
	server, base := newTestServer(t, nil)
	speculative := func(code string) int {
		req, err := http.NewRequest("GET", base+"/login?code="+code, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Sec-Purpose", "prefetch;prerender")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	code, err := server.issueCode()
	if err != nil {
		t.Fatal(err)
	}
	if status := speculative(code); status == http.StatusOK {
		t.Fatal("a speculative load logged in")
	}
	status, body := get(t, base+"/login?code="+code)
	if status != http.StatusOK {
		t.Fatalf("the code was used up by a speculative load: status %d", status)
	}
	session := secretInLoginPage.FindStringSubmatch(body)[1]

	speculative(code)
	if status, _ := call(t, "GET", base+"/api/config", session, nil); status != http.StatusOK {
		t.Fatalf("a speculative load closed the session: status %d", status)
	}
}

func TestLoginCodeExpires(t *testing.T) {
	server, base := newTestServer(t, nil)
	clock := useClock(server)

	code, err := server.issueCode()
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(config.WebLoginCodeSeconds * time.Second)
	status, body := get(t, base+"/login?code="+code)
	if status != http.StatusForbidden || !strings.Contains(body, "устарела") {
		t.Fatalf("expired code: status %d: %s", status, body)
	}

	// Just inside the window it still works
	code, err = server.issueCode()
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(config.WebLoginCodeSeconds*time.Second - time.Second)
	if status, _ := get(t, base+"/login?code="+code); status != http.StatusOK {
		t.Fatalf("code within its lifetime: status %d", status)
	}

	for _, bad := range []string{"", "?code=", "?code=" + strings.Repeat("0", 64)} {
		if status, _ := get(t, base+"/login"+bad); status != http.StatusForbidden {
			t.Fatalf("login%s: status %d", bad, status)
		}
	}
}

// Every tray click adds a code; only the newest few stay valid
func TestPendingCodesAreLimited(t *testing.T) {
	server, base := newTestServer(t, nil)
	var codes []string
	for i := 0; i < maxPendingCodes+1; i++ {
		code, err := server.issueCode()
		if err != nil {
			t.Fatal(err)
		}
		codes = append(codes, code)
	}
	if status, _ := get(t, base+"/login?code="+codes[0]); status != http.StatusForbidden {
		t.Fatalf("the oldest pending code must have been dropped: status %d", status)
	}
	for _, code := range codes[1:] {
		if status, _ := get(t, base+"/login?code="+code); status != http.StatusOK {
			t.Fatalf("a recent code was refused: status %d", status)
		}
	}
}

// At the limit a new login evicts the session idle the longest, not the
// oldest one still in use
func TestSessionsAreLimited(t *testing.T) {
	server, base := newTestServer(t, nil)
	clock := useClock(server)

	var sessions []string
	for i := 0; i < maxSessions; i++ {
		sessions = append(sessions, login(t, server))
		clock.Advance(time.Minute)
	}
	// The first one is still in use: the second is now idle the longest
	if status, _ := call(t, "GET", base+"/api/config", sessions[0], nil); status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	clock.Advance(time.Minute)
	newest := login(t, server)

	if status, _ := call(t, "GET", base+"/api/config", sessions[1], nil); status != http.StatusUnauthorized {
		t.Fatalf("the session idle the longest survived: status %d", status)
	}
	for _, s := range append([]string{sessions[0], newest}, sessions[2:]...) {
		if status, _ := call(t, "GET", base+"/api/config", s, nil); status != http.StatusOK {
			t.Fatalf("a live session was evicted: status %d", status)
		}
	}
}

func TestSessionIdleExpiry(t *testing.T) {
	server, base := newTestServer(t, nil)
	clock := useClock(server)
	session := login(t, server)
	idle := config.WebSessionIdleMinutes * time.Minute

	// Every use restarts the idle timer
	for i := 0; i < 3; i++ {
		clock.Advance(idle - time.Second)
		if status, _ := call(t, "GET", base+"/api/config", session, nil); status != http.StatusOK {
			t.Fatalf("session used within the idle limit: status %d", status)
		}
	}
	clock.Advance(idle)
	if status, _ := call(t, "GET", base+"/api/config", session, nil); status != http.StatusUnauthorized {
		t.Fatalf("idle session: status %d", status)
	}
}

func TestSessionAbsoluteExpiry(t *testing.T) {
	server, base := newTestServer(t, nil)
	clock := useClock(server)
	session := login(t, server)

	// Kept busy, the session still ends WebSessionMaxHours after the login
	step := 20 * time.Minute
	for elapsed := step; elapsed < config.WebSessionMaxHours*time.Hour; elapsed += step {
		clock.Advance(step)
		if status, _ := call(t, "GET", base+"/api/config", session, nil); status != http.StatusOK {
			t.Fatalf("session in use after %v: status %d", elapsed, status)
		}
	}
	clock.Advance(step)
	if status, _ := call(t, "GET", base+"/api/config", session, nil); status != http.StatusUnauthorized {
		t.Fatalf("session older than %d h: status %d", config.WebSessionMaxHours, status)
	}
}

func TestAPIRequiresSession(t *testing.T) {
	server, base := newTestServer(t, nil)
	session := login(t, server)

	for _, s := range []string{"", "wrong", strings.Repeat("a", 64), session + "0"} {
		status, data := call(t, "GET", base+"/api/config", s, nil)
		if status != http.StatusUnauthorized {
			t.Fatalf("session %q: status %d", s, status)
		}
		if msg, _ := data["error"].(string); !strings.Contains(msg, "сессия завершена") {
			t.Fatalf("401 without the page's JSON error: %v", data)
		}
	}
	if status, _ := call(t, "GET", base+"/api/config", session, nil); status != http.StatusOK {
		t.Fatalf("valid session: status %d", status)
	}
}

// The Host check (DNS rebinding) applies to every path, with a session too
func TestWrongHostRejected(t *testing.T) {
	server, base := newTestServer(t, nil)
	session := login(t, server)
	port := base[strings.LastIndex(base, ":"):]

	for _, host := range []string{"localhost" + port, "rebind.example" + port, "rebind.example", "127.0.0.1"} {
		for _, path := range []string{"/", "/login?code=x", "/api/config"} {
			req, err := http.NewRequest("GET", base+path, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Host = host
			req.Header.Set(sessionHeader, session)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("Host %q, %s: status %d", host, path, resp.StatusCode)
			}
		}
	}
}

func TestSecurityHeaders(t *testing.T) {
	server, base := newTestServer(t, nil)
	session := login(t, server)
	code, err := server.issueCode()
	if err != nil {
		t.Fatal(err)
	}

	requests := []struct {
		name, path, session, host string
	}{
		{"page", "/", "", ""},
		{"login", "/login?code=" + code, "", ""},
		{"refused login", "/login?code=nope", "", ""},
		{"api", "/api/config", session, ""},
		{"api without session", "/api/config", "", ""},
		{"wrong host", "/", "", "rebind.example"},
	}
	for _, r := range requests {
		req, err := http.NewRequest("GET", base+r.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if r.session != "" {
			req.Header.Set(sessionHeader, r.session)
		}
		if r.host != "" {
			req.Host = r.host
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		h := resp.Header
		if h.Get("Cache-Control") != "no-store" || h.Get("X-Content-Type-Options") != "nosniff" ||
			h.Get("Referrer-Policy") != "no-referrer" {
			t.Fatalf("%s: headers %v", r.name, h)
		}
		csp := h.Get("Content-Security-Policy")
		for _, directive := range []string{"frame-ancestors 'none'", "base-uri 'none'", "form-action 'none'", "connect-src 'self'", "default-src 'none'"} {
			if !strings.Contains(csp, directive) {
				t.Fatalf("%s: CSP %q lacks %q", r.name, csp, directive)
			}
		}
	}
}

// The page is the same for everyone: no secret in it; the session comes from
// sessionStorage under the key the login page uses, sent as X-Session
func TestPageCarriesNoSecret(t *testing.T) {
	server, base := newTestServer(t, nil)
	session := login(t, server)

	status, body := get(t, base+"/")
	if status != http.StatusOK {
		t.Fatalf("page: status %d", status)
	}
	if strings.Contains(body, session) || strings.Contains(body, "{{") {
		t.Fatal("the page carries a secret or an unrendered template")
	}
	for _, want := range []string{"'" + sessionStorageKey + "'", "'" + sessionHeader + "'"} {
		if !strings.Contains(body, want) {
			t.Fatalf("the page does not use %s", want)
		}
	}

	// An old-style URL with a token parameter is just the page
	if status, _ := get(t, base+"/?t=whatever"); status != http.StatusOK {
		t.Fatalf("page with a query: status %d", status)
	}
	if status, _ := get(t, base+"/other"); status != http.StatusNotFound {
		t.Fatalf("unknown path: status %d", status)
	}
}
