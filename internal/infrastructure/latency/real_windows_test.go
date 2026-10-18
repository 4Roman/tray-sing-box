//go:build windows

package latency

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"tray-sing-box/internal/config"
	"tray-sing-box/internal/domain"
)

// Against the real sing-box: a COPY of SINGBOX_REAL_DIR\sing-box.exe in a
// temp Bin dir, run as the prober runs it, with configs of no inbound (no
// TUN, no listener but its own loopback Clash API), always ended by the
// prober and checked to be gone. Not in -short. Offline, delays cannot be
// ordered — the delay test fetches a fixed https URL with the system's
// roots — so offline the subtests check what sing-box answers, which
// outbound a tag reaches, the restarts and the isolation; the ordering
// needs the network and is skipped without it.
func TestRealSingBox(t *testing.T) {
	dir := os.Getenv("SINGBOX_REAL_DIR")
	if dir == "" || testing.Short() {
		t.Skip("set SINGBOX_REAL_DIR to a sing-box installation and run without -short")
	}
	bin, data := tempDir(t), tempDir(t)
	exe := filepath.Join(bin, config.SingBoxExe)
	copyFile(t, filepath.Join(dir, config.SingBoxExe), exe)
	noLeftover(t, exe)
	p := New(bin, data)
	gone := func(t *testing.T) {
		t.Helper()
		if pids := processesOf(t, exe); len(pids) != 0 {
			t.Errorf("test instance %v still runs after Measure returned", pids)
		}
	}
	setHook(t, &probeTimeoutMs, 2000)

	// A tag addresses exactly its outbound — "a%41" is not "aA" — through
	// the real router; an unreachable server is a timeout or an error
	t.Run("tags and an offline server", func(t *testing.T) {
		logs := captureLog(t)
		tags := []string{"a%41", "aA", "a/b", "кир 🙂", "sp ace?#&", "100%"}
		hits := map[string]*connCounter{}
		var nodes []map[string]any
		for _, tag := range tags {
			c := countConns(t)
			hits[tag] = c
			nodes = append(nodes, socksNode(tag, "127.0.0.1", c.port, ""))
		}
		nodes = append(nodes, socksNode("dead", "192.0.2.1", 1080, ""))
		plan := handPlan(nodes...)
		// A candidate the instance does not carry: sing-box's own 404
		plan.Candidates = append(plan.Candidates, domain.LatencyCandidate{Tag: "phantom", Type: "socks", Testable: true, Eligible: true})
		got, err := measure(t, p, plan, append(append([]string{}, tags...), "dead", "phantom")...)
		if err != nil {
			t.Fatal(err)
		}
		gone(t)
		for _, tag := range tags {
			// The relay closes at once: the test fails, once (no second round)
			if got[tag].Status != domain.LatencyError {
				t.Errorf("%q: %+v, want an error", tag, got[tag])
			}
			if n := hits[tag].count(); n != 1 {
				t.Errorf("%q: its server got %d connections, want 1", tag, n)
			}
		}
		if s := got["dead"].Status; s != domain.LatencyTimeout && s != domain.LatencyError {
			t.Errorf("dead: %+v, want a timeout or an error", got["dead"])
		}
		if got["phantom"] != (domain.Delay{Status: domain.LatencyError, Note: noteNotInInstance}) {
			t.Errorf("phantom: %+v, want sing-box's 404", got["phantom"])
		}
		if lines := logs.lines(); len(lines) != 1 || !strings.Contains(lines[0], "Latency: 0 of 8 answered") {
			t.Errorf("log %q", lines)
		}
	})

	t.Run("a taken port", func(t *testing.T) {
		taken := holdPort(t)
		picks := 0
		setHook(t, &pickPort, func() (int, error) {
			if picks++; picks == 1 {
				return taken.port, nil
			}
			return freeLoopbackPort()
		})
		got, err := measure(t, p, handPlan(socksNode("dead", "192.0.2.1", 1080, "")), "dead")
		if err != nil {
			t.Fatal(err)
		}
		gone(t)
		if picks != 2 {
			t.Errorf("%d ports picked, want 2 (one retry)", picks)
		}
		if s := got["dead"].Status; s != domain.LatencyTimeout && s != domain.LatencyError {
			t.Errorf("dead: %+v", got["dead"])
		}
		taken.received(t)
	})

	// REALITY without uTLS cannot be created: left out with sing-box's
	// reason, with what dials through it; the rest is measured
	t.Run("isolation", func(t *testing.T) {
		picks := 0
		setHook(t, &pickPort, func() (int, error) {
			picks++
			return freeLoopbackPort()
		})
		via := socksNode("via-rea", "192.0.2.3", 1080, "")
		via["detour"] = "rea"
		plan := filePlan(t, data, map[string]any{"outbounds": []any{
			socksNode("dead", "192.0.2.1", 1080, ""),
			map[string]any{"type": "vless", "tag": "rea", "server": "192.0.2.2", "server_port": 443,
				"uuid": "11111111-2222-3333-4444-555555555555",
				"tls": map[string]any{"enabled": true, "server_name": "example.com",
					"reality": map[string]any{"enabled": true, "public_key": "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0", "short_id": "0123abcd"}}},
			via,
		}})
		got, err := measure(t, p, plan, "dead", "rea", "via-rea")
		if err != nil {
			t.Fatal(err)
		}
		gone(t)
		if s := got["dead"].Status; s != domain.LatencyTimeout && s != domain.LatencyError {
			t.Errorf("dead: %+v", got["dead"])
		}
		if r := got["rea"]; r.Status != domain.LatencySkipped || !strings.Contains(r.Note, "uTLS is required by reality client") {
			t.Errorf("rea: %+v, want skipped with sing-box's reason", r)
		}
		if v := got["via-rea"]; v.Status != domain.LatencySkipped || v.Note != "не проверяется: зависит от «rea»" {
			t.Errorf("via-rea: %+v", v)
		}
		if picks != 2 {
			t.Errorf("%d starts, want 2", picks)
		}
	})

	// The main selector as the DNS detour, its default one sing-box cannot
	// create: the test instance — the DNS server with the group copied
	// without it — starts, and the other members are measured (offline:
	// they do not answer; a local relay would be the info node of a
	// provider to the plan)
	t.Run("the DNS server's group without a member it cannot carry", func(t *testing.T) {
		picks := 0
		setHook(t, &pickPort, func() (int, error) {
			picks++
			return freeLoopbackPort()
		})
		plan := filePlan(t, data, map[string]any{
			"dns": map[string]any{"servers": []any{
				map[string]any{"type": "https", "tag": "remote", "server": "1.1.1.1", "detour": "proxy"},
				map[string]any{"type": "udp", "tag": "local-dns", "server": "192.0.2.53"},
			}, "final": "remote"},
			"outbounds": []any{
				map[string]any{"type": "selector", "tag": "proxy", "outbounds": []any{"good", "rea", "other"}, "default": "rea"},
				socksNode("good", "192.0.2.21", 1080, ""),
				map[string]any{"type": "vless", "tag": "rea", "server": "192.0.2.2", "server_port": 443,
					"uuid": "11111111-2222-3333-4444-555555555555",
					"tls": map[string]any{"enabled": true, "server_name": "example.com",
						"reality": map[string]any{"enabled": true, "public_key": "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0", "short_id": "0123abcd"}}},
				socksNode("other", "192.0.2.22", 1080, ""),
			},
			"route": map[string]any{"final": "proxy", "default_domain_resolver": "local-dns"},
		})
		got, err := measure(t, p, plan, "good", "rea", "other")
		if err != nil {
			t.Fatal(err)
		}
		gone(t)
		if r := got["rea"]; r.Status != domain.LatencySkipped || !strings.Contains(r.Note, "uTLS is required by reality client") {
			t.Errorf("rea: %+v, want skipped with sing-box's reason", r)
		}
		for _, tag := range []string{"good", "other"} {
			if s := got[tag].Status; s != domain.LatencyTimeout && s != domain.LatencyError {
				t.Errorf("%s: %+v, want measured (a timeout or an error)", tag, got[tag])
			}
		}
		if picks != 2 {
			t.Errorf("%d starts, want 2", picks)
		}
	})

	// How long the instance takes to answer with many outbounds (U8)
	t.Run("many outbounds", func(t *testing.T) {
		var nodes []map[string]any
		for i := range 300 {
			nodes = append(nodes, map[string]any{"type": "vless", "tag": "n" + strconv.Itoa(i),
				"server": "192.0.2." + strconv.Itoa(i%250+1), "server_port": 443,
				"uuid": "11111111-2222-3333-4444-555555555555",
				"tls": map[string]any{"enabled": true, "server_name": "example.com",
					"utls": map[string]any{"enabled": true, "fingerprint": "chrome"}},
				"transport": map[string]any{"type": "ws", "path": "/x"}})
		}
		setHook(t, &probeTimeoutMs, 200)
		began := time.Now()
		got, err := measure(t, p, handPlan(nodes...), "n0")
		if err != nil {
			t.Fatal(err)
		}
		gone(t)
		t.Logf("300 outbounds: one server measured in %v (start, API, a %d ms probe)", time.Since(began), probeTimeoutMs)
		if s := got["n0"].Status; s != domain.LatencyTimeout && s != domain.LatencyError {
			t.Errorf("n0: %+v", got["n0"])
		}
	})

	// The ordering, through two local SOCKS5 relays to the real test URL:
	// one answers its CONNECT 300 ms late
	t.Run("network", func(t *testing.T) {
		fast, slow := socksRelay(t, 0), socksRelay(t, 300*time.Millisecond)
		setHook(t, &probeTimeoutMs, 5000)
		got, err := measure(t, p, handPlan(socksNode("fast", "127.0.0.1", fast, ""), socksNode("slow", "127.0.0.1", slow, "")), "fast", "slow")
		if err != nil {
			t.Fatal(err)
		}
		gone(t)
		if got["fast"].Status != domain.LatencyOK {
			t.Skipf("no network: fast %+v", got["fast"])
		}
		t.Logf("fast %d ms, slow %d ms", got["fast"].Ms, got["slow"].Ms)
		if got["slow"].Status != domain.LatencyOK || got["slow"].Ms < got["fast"].Ms+200 {
			t.Errorf("slow %+v, want ok and at least 200 ms slower than fast (%d ms)", got["slow"], got["fast"].Ms)
		}
	})
}

// connCounter is a server that counts connections and closes them at once
type connCounter struct {
	port int
	mu   sync.Mutex
	n    int
}

func countConns(t *testing.T) *connCounter {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	c := &connCounter{port: l.Addr().(*net.TCPAddr).Port}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			c.mu.Lock()
			c.n++
			c.mu.Unlock()
			conn.Close()
		}
	}()
	return c
}

func (c *connCounter) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// socksRelay is a minimal SOCKS5 server (no authentication, CONNECT) that
// answers the CONNECT after wait; returns its port
func socksRelay(t *testing.T, wait time.Duration) int {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go relaySocks(conn, wait)
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

func relaySocks(conn net.Conn, wait time.Duration) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil || head[0] != 5 {
		return
	}
	if _, err := io.ReadFull(conn, make([]byte, head[1])); err != nil {
		return
	}
	conn.Write([]byte{5, 0})
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil || req[1] != 1 {
		return
	}
	var host string
	switch req[3] {
	case 1:
		ip := make([]byte, 4)
		io.ReadFull(conn, ip)
		host = net.IP(ip).String()
	case 3:
		n := make([]byte, 1)
		io.ReadFull(conn, n)
		name := make([]byte, n[0])
		io.ReadFull(conn, name)
		host = string(name)
	case 4:
		ip := make([]byte, 16)
		io.ReadFull(conn, ip)
		host = net.IP(ip).String()
	default:
		return
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(conn, port); err != nil {
		return
	}
	time.Sleep(wait)
	target, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port)))), 10*time.Second)
	if err != nil {
		conn.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer target.Close()
	conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	go io.Copy(target, conn)
	io.Copy(conn, target)
}
