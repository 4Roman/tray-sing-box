//go:build windows

package latency

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"tray-sing-box/internal/config"
	"tray-sing-box/internal/domain"
	"tray-sing-box/internal/infrastructure/configfile"
	"tray-sing-box/internal/infrastructure/process"
)

// Measure against the fake sing-box (fake_windows_test.go): the start, the
// restarts and their limits, the connection check, the output that may be
// shown, and that no test instance outlives a call

func socksNode(tag, server string, port int, password string) map[string]any {
	o := map[string]any{"type": "socks", "tag": tag, "server": server, "server_port": port}
	if password != "" {
		o["username"], o["password"] = "user", password
	}
	return o
}

// handPlan is a plan of the given outbounds, all testable, with a Redact
// that replaces their passwords and the extra secrets
func handPlan(outbounds ...map[string]any) *domain.ProbePlan {
	var list []any
	var candidates []domain.LatencyCandidate
	var secrets []string
	for _, o := range outbounds {
		list = append(list, o)
		candidates = append(candidates, domain.LatencyCandidate{Tag: o["tag"].(string), Type: o["type"].(string), Testable: true, Eligible: true})
		if pw, ok := o["password"].(string); ok {
			secrets = append(secrets, pw)
		}
	}
	return &domain.ProbePlan{
		Config: map[string]any{
			"log":       map[string]any{"level": "warn"},
			"outbounds": list,
			"route":     map[string]any{"auto_detect_interface": true},
		},
		Candidates: candidates,
		Redact: func(text string, extra ...string) string {
			for _, s := range append(secrets, extra...) {
				if s != "" {
					text = strings.ReplaceAll(text, s, "(скрыто)")
				}
			}
			return text
		},
	}
}

// filePlan is the plan configfile builds for a config.json written into
// data
func filePlan(t *testing.T, data string, cfg map[string]any) *domain.ProbePlan {
	t.Helper()
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(data, config.SingBoxConfig)
	if err := os.WriteFile(path, raw, 0644); err != nil {
		t.Fatal(err)
	}
	plan, err := configfile.New(path).ProbePlan()
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

// logLines captures the log for the rest of the test
type logLines struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logLines) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logLines) lines() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	text := strings.TrimSpace(l.buf.String())
	if text == "" {
		return nil
	}
	return strings.Split(text, "\n")
}

func captureLog(t *testing.T) *logLines {
	l := &logLines{}
	log.SetOutput(l)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return l
}

func setHook[T any](t *testing.T, v *T, value T) {
	saved := *v
	*v = value
	t.Cleanup(func() { *v = saved })
}

func measure(t *testing.T, p *Prober, plan *domain.ProbePlan, tags ...string) (map[string]domain.Delay, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return p.Measure(ctx, plan, tags)
}

var hexSecret = regexp.MustCompile(`^[0-9a-f]{64}$`)

func TestMeasure(t *testing.T) {
	p, bin, data := installFake(t, fakeMode{Mode: "serve", Delays: map[string]int{"ok1": 30, "ok2": 40, "slow": -1, "bad": -2}})
	logs := captureLog(t)
	plan := handPlan(
		socksNode("ok1", "198.51.100.1", 1080, "pw-one"),
		socksNode("ok2", "198.51.100.2", 1080, ""),
		socksNode("slow", "198.51.100.3", 1080, ""),
		socksNode("bad", "198.51.100.4", 1080, ""),
	)
	plan.Candidates = append(plan.Candidates, domain.LatencyCandidate{Tag: "group", Type: "selector", Note: "группа — проверяются её серверы"})
	got, err := measure(t, p, plan, "ok2", "ok1", "slow", "bad", "group", "ghost", "ok1")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]domain.Delay{
		"ok1":   {Ms: 30, Status: domain.LatencyOK},
		"ok2":   {Ms: 40, Status: domain.LatencyOK},
		"slow":  {Status: domain.LatencyTimeout},
		"bad":   {Status: domain.LatencyError},
		"group": {Status: domain.LatencySkipped, Note: "группа — проверяются её серверы"},
		"ghost": {Status: domain.LatencySkipped, Note: noteNotInInstance},
	}
	if len(got) != len(want) {
		t.Errorf("results %v, want %d of them", got, len(want))
	}
	for tag, w := range want {
		if got[tag] != w {
			t.Errorf("%s: %+v, want %+v", tag, got[tag], w)
		}
	}

	starts, requests := fakeEvents(t, bin)
	if len(starts) != 1 {
		t.Fatalf("%d starts, want 1", len(starts))
	}
	s := starts[0]
	exe := filepath.Join(bin, config.SingBoxExe)
	if s.Via != "stdin" || len(s.Args) != 4 || !strings.EqualFold(s.Args[0], exe) || strings.Join(s.Args[1:], " ") != "run -c stdin" {
		t.Errorf("started as %q via %s, want %s run -c stdin", s.Args, s.Via, exe)
	}
	if !strings.EqualFold(s.Dir, data) {
		t.Errorf("working directory %s, want the data dir %s", s.Dir, data)
	}
	if !strings.HasPrefix(strings.ToLower(s.Path), strings.ToLower(bin)+";") {
		t.Errorf("PATH %q: not the environment SingBoxEnv builds", s.Path)
	}
	api, _ := s.Config["experimental"].(map[string]any)["clash_api"].(map[string]any)
	secret, _ := api["secret"].(string)
	controller, _ := api["external_controller"].(string)
	host, port, _ := net.SplitHostPort(controller)
	if !hexSecret.MatchString(secret) || host != "127.0.0.1" || len(api) != 2 {
		t.Errorf("clash_api %v: want a loopback controller and a 64-hex secret only", api)
	}
	delete(s.Config, "experimental")
	wantConfig, _ := json.Marshal(plan.Config)
	if gotConfig, _ := json.Marshal(s.Config); !bytes.Equal(gotConfig, wantConfig) {
		t.Errorf("config\n%s\nwant the plan's\n%s", gotConfig, wantConfig)
	}
	measured := map[string]int{}
	for _, r := range requests {
		measured[r.Tag]++
	}
	// Two rounds for the ones that answered, one for the others; the
	// skipped ones never asked
	for tag, n := range map[string]int{"ok1": 2, "ok2": 2, "slow": 1, "bad": 1, "group": 0, "ghost": 0} {
		if measured[tag] != n {
			t.Errorf("%s measured %d times, want %d", tag, measured[tag], n)
		}
	}

	lines := logs.lines()
	if len(lines) != 1 || !strings.Contains(lines[0], "Latency: 2 of 4 answered in ") ||
		!strings.Contains(lines[0], "test sing-box PID "+strconv.Itoa(s.PID)+")") {
		t.Errorf("log %q, want one line: 2 of 4 answered, with the PID", lines)
	}
	portRe := regexp.MustCompile(`` + port + ``)
	for _, line := range lines {
		if strings.Contains(line, secret) || portRe.MatchString(line) || strings.Contains(line, "198.51.100") {
			t.Errorf("log line %q quotes the secret, the port or a server", line)
		}
	}
	entries, _ := os.ReadDir(data)
	for _, e := range entries {
		if e.Name() != "tmp" { // SingBoxEnv's TEMP
			t.Errorf("left in the data dir: %s", e.Name())
		}
	}
}

func TestMeasureWithoutSingBox(t *testing.T) {
	p := New(tempDir(t), tempDir(t))
	_, err := measure(t, p, handPlan(socksNode("a", "198.51.100.1", 1, "")), "a")
	if !errors.Is(err, domain.ErrSingBoxMissing) {
		t.Errorf("error %v, want ErrSingBoxMissing", err)
	}
}

// Nothing testable among the tags: no test instance at all
func TestMeasureNothingToTest(t *testing.T) {
	p, bin, _ := installFake(t, fakeMode{Mode: "serve"})
	plan := handPlan(socksNode("a", "198.51.100.1", 1, ""))
	plan.Candidates[0].Testable, plan.Candidates[0].Note = false, "не проверяется: зависит от «x»"
	got, err := measure(t, p, plan, "a", "ghost")
	if err != nil {
		t.Fatal(err)
	}
	if got["a"].Status != domain.LatencySkipped || got["a"].Note != plan.Candidates[0].Note || got["ghost"].Status != domain.LatencySkipped {
		t.Errorf("results %+v", got)
	}
	if starts, _ := fakeEvents(t, bin); len(starts) != 0 {
		t.Errorf("%d test instances started for nothing", len(starts))
	}
}

// heldPort is a loopback port the test listens on, recording what any
// connection to it sent before it was closed
type heldPort struct {
	port int
	mu   sync.Mutex
	got  []int // bytes received, per connection
}

func holdPort(t *testing.T) *heldPort {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	h := &heldPort{port: l.Addr().(*net.TCPAddr).Port}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetReadDeadline(time.Now().Add(10 * time.Second))
				n, _ := io.Copy(io.Discard, conn)
				h.mu.Lock()
				h.got = append(h.got, int(n))
				h.mu.Unlock()
			}()
		}
	}()
	return h
}

func (h *heldPort) received(t *testing.T) {
	t.Helper()
	time.Sleep(50 * time.Millisecond) // the reader of a just closed connection
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, n := range h.got {
		if n != 0 {
			t.Errorf("a connection to the taken port sent %d bytes, want none (the secret goes with the first)", n)
		}
	}
}

// The API port taken between choosing and listening: one more start on a
// new port; taken again: the check stops
func TestMeasureRetriesATakenPort(t *testing.T) {
	p, bin, _ := installFake(t, fakeMode{Mode: "serve", Delays: map[string]int{"a": 12}})
	taken := holdPort(t)
	picks := 0
	setHook(t, &pickPort, func() (int, error) {
		picks++
		if picks == 1 {
			return taken.port, nil
		}
		return freeLoopbackPort()
	})
	got, err := measure(t, p, handPlan(socksNode("a", "198.51.100.1", 1, "")), "a")
	if err != nil || got["a"].Status != domain.LatencyOK {
		t.Fatalf("%+v, %v", got, err)
	}
	if starts, _ := fakeEvents(t, bin); len(starts) != 2 || picks != 2 {
		t.Errorf("%d starts, %d ports picked; want 2 each", len(starts), picks)
	}
	taken.received(t)

	t.Run("twice", func(t *testing.T) {
		p, bin, _ := installFake(t, fakeMode{Mode: "serve"})
		taken2 := holdPort(t)
		setHook(t, &pickPort, func() (int, error) {
			if picks++; picks%2 == 1 {
				return taken.port, nil
			}
			return taken2.port, nil
		})
		_, err := measure(t, p, handPlan(socksNode("a", "198.51.100.1", 1, "")), "a")
		if !errors.Is(err, ErrForeignPort) {
			t.Errorf("error %v, want ErrForeignPort", err)
		}
		if starts, _ := fakeEvents(t, bin); len(starts) != 2 {
			t.Errorf("%d starts, want 2", len(starts))
		}
		taken.received(t)
		taken2.received(t)
	})
}

// A build that takes "stdin" for a file name gets the config through a
// temporary file in the data dir, gone once the instance has read it
func TestMeasureFallsBackToAFile(t *testing.T) {
	p, bin, data := installFake(t, fakeMode{Mode: "nostdin", Delays: map[string]int{"a": 5}})
	logs := captureLog(t)
	got, err := measure(t, p, handPlan(socksNode("a", "198.51.100.1", 1, "")), "a")
	if err != nil || got["a"].Status != domain.LatencyOK {
		t.Fatalf("%+v, %v", got, err)
	}
	starts, requests := fakeEvents(t, bin)
	if len(starts) != 2 || starts[0].Via != "stdin" || starts[1].Via != "file" {
		t.Fatalf("starts %+v, want stdin then a file", starts)
	}
	file := starts[1].File
	if !strings.EqualFold(filepath.Dir(file), data) || !strings.HasPrefix(filepath.Base(file), ".latency-") {
		t.Errorf("config file %s, want .latency-* in the data dir %s", file, data)
	}
	for _, r := range requests {
		if r.Tag != "/version" && r.FileLeft {
			t.Errorf("the config file (with the secret) still existed at the request for %s", r.Tag)
		}
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Errorf("config file left behind: %v", err)
	}
	if lines := logs.lines(); len(lines) != 1 || !strings.Contains(lines[0], "2 starts; config via a file") {
		t.Errorf("log %q", lines)
	}
}

func TestMeasureWithoutClashAPI(t *testing.T) {
	p, bin, _ := installFake(t, fakeMode{Mode: "noclash"})
	_, err := measure(t, p, handPlan(socksNode("a", "198.51.100.1", 1, "")), "a")
	if !errors.Is(err, ErrNoClashAPI) {
		t.Errorf("error %v, want ErrNoClashAPI", err)
	}
	if starts, _ := fakeEvents(t, bin); len(starts) != 1 {
		t.Errorf("%d starts, want 1", len(starts))
	}
}

// A server sing-box cannot create on its own is left out with its reason,
// and what dials through it with it; the others are measured
func TestMeasureLeavesOutWhatCannotStart(t *testing.T) {
	p, bin, data := installFake(t, fakeMode{Mode: "fail-tag", Tag: "b", Delays: map[string]int{"a": 21, "d": 23}})
	via := socksNode("c", "198.51.100.3", 1080, "")
	via["detour"] = "b"
	plan := filePlan(t, data, map[string]any{"outbounds": []any{
		socksNode("a", "198.51.100.1", 1080, ""),
		socksNode("b", "198.51.100.2", 1080, "b-password-secret"),
		via,
		socksNode("d", "198.51.100.4", 1080, ""),
	}})
	got, err := measure(t, p, plan, "a", "b", "c", "d")
	if err != nil {
		t.Fatal(err)
	}
	if got["a"].Status != domain.LatencyOK || got["d"].Status != domain.LatencyOK {
		t.Errorf("a %+v, d %+v: want both measured", got["a"], got["d"])
	}
	b, c := got["b"], got["c"]
	if b.Status != domain.LatencySkipped || !strings.Contains(b.Note, "sing-box не смог его запустить отдельно: cannot use password") {
		t.Errorf("b: %+v, want skipped with sing-box's reason", b)
	}
	if strings.Contains(b.Note, "b-password-secret") {
		t.Errorf("b's note quotes its password: %q", b.Note)
	}
	if c.Status != domain.LatencySkipped || c.Note != "не проверяется: зависит от «b»" {
		t.Errorf("c: %+v, want skipped as depending on b", c)
	}
	starts, _ := fakeEvents(t, bin)
	if len(starts) != 2 {
		t.Fatalf("%d starts, want 2", len(starts))
	}
	var second []string
	for _, o := range starts[1].Config["outbounds"].([]any) {
		second = append(second, o.(map[string]any)["tag"].(string))
	}
	if strings.Join(second, ",") != "a,d" {
		t.Errorf("the second instance carries %v, want a,d", second)
	}
}

// Servers are left out at most LatencyIsolateRetries times, then the check
// fails as a whole
func TestMeasureGivesUpLeavingOut(t *testing.T) {
	p, bin, data := installFake(t, fakeMode{Mode: "fail-first"})
	var outbounds []any
	var tags []string
	for i := range 6 {
		tag := "n" + strconv.Itoa(i)
		outbounds = append(outbounds, socksNode(tag, "198.51.100."+strconv.Itoa(i+1), 1080, "pw-"+tag+"-secret"))
		tags = append(tags, tag)
	}
	_, err := measure(t, p, filePlan(t, data, map[string]any{"outbounds": outbounds}), tags...)
	if err == nil || !strings.HasPrefix(err.Error(), "Тестовый sing-box не запустился: create service: initialize outbound «n3»: cannot use password") {
		t.Fatalf("error %v, want the start failure", err)
	}
	if strings.Contains(err.Error(), "-secret") {
		t.Errorf("error quotes a password: %v", err)
	}
	if starts, _ := fakeEvents(t, bin); len(starts) != config.LatencyIsolateRetries+1 {
		t.Errorf("%d starts, want %d", len(starts), config.LatencyIsolateRetries+1)
	}
}

// What a failed start prints reaches the page only redacted: no secret, no
// password, no API port
func TestMeasureRedactsTheOutput(t *testing.T) {
	p, bin, _ := installFake(t, fakeMode{Mode: "crash"})
	_, err := measure(t, p, handPlan(socksNode("a", "198.51.100.1", 1, "a-password-secret")), "a")
	starts, _ := fakeEvents(t, bin)
	if len(starts) != 1 {
		t.Fatalf("%d starts", len(starts))
	}
	api := starts[0].Config["experimental"].(map[string]any)["clash_api"].(map[string]any)
	if err == nil || !strings.HasPrefix(err.Error(), "Тестовый sing-box не запустился: create service: something broke") {
		t.Fatalf("error %v", err)
	}
	for _, s := range []string{api["secret"].(string), api["external_controller"].(string), "a-password-secret", "\x1b", "FATAL"} {
		if strings.Contains(err.Error(), s) {
			t.Errorf("error %q quotes %q", err, s)
		}
	}
}

func TestMeasureNotReady(t *testing.T) {
	setHook(t, &startTimeout, time.Second)
	p, bin, _ := installFake(t, fakeMode{Mode: "hang"})
	began := time.Now()
	_, err := measure(t, p, handPlan(socksNode("a", "198.51.100.1", 1, "")), "a")
	if err == nil || err.Error() != "Тестовый sing-box не ответил за 1 с" {
		t.Errorf("error %v", err)
	}
	if took := time.Since(began); took > 8*time.Second {
		t.Errorf("took %v", took)
	}
	if starts, _ := fakeEvents(t, bin); len(starts) != 1 {
		t.Errorf("%d starts, want 1", len(starts))
	}
	if pids := processesOf(t, filepath.Join(bin, config.SingBoxExe)); len(pids) != 0 {
		t.Errorf("test instance %v still runs after Measure returned", pids)
	}
}

// The listener of the API port is not the test instance: not a single
// request reaches it, the check stops
func TestMeasureRefusesAForeignListener(t *testing.T) {
	setHook(t, &startTimeout, time.Second)
	setHook(t, &connOwner, func(local, remote netip.AddrPort) (uint32, error) { return 4, nil })
	p, bin, _ := installFake(t, fakeMode{Mode: "serve", Delays: map[string]int{"a": 1}})
	_, err := measure(t, p, handPlan(socksNode("a", "198.51.100.1", 1, "")), "a")
	if !errors.Is(err, ErrForeignPort) {
		t.Errorf("error %v, want ErrForeignPort", err)
	}
	if _, requests := fakeEvents(t, bin); len(requests) != 0 {
		t.Errorf("requests reached the listener: %+v", requests)
	}

	t.Run("while measuring", func(t *testing.T) {
		// The connection of the readiness check is the instance's; every
		// further one (eight tests in parallel need more) is not
		calls := 0
		var mu sync.Mutex
		setHook(t, &connOwner, func(local, remote netip.AddrPort) (uint32, error) {
			mu.Lock()
			defer mu.Unlock()
			if calls++; calls == 1 {
				return process.ConnOwnerPID(local, remote)
			}
			return 4, nil
		})
		p, _, _ := installFake(t, fakeMode{Mode: "serve", Delays: map[string]int{"a": 300, "b": 300, "c": 300}})
		_, err := measure(t, p, handPlan(socksNode("a", "198.51.100.1", 1, ""), socksNode("b", "198.51.100.2", 1, ""), socksNode("c", "198.51.100.3", 1, "")), "a", "b", "c")
		if !errors.Is(err, ErrForeignPort) {
			t.Errorf("error %v, want ErrForeignPort", err)
		}
	})
}

func TestMeasureUnauthorized(t *testing.T) {
	p, _, _ := installFake(t, fakeMode{Mode: "unauthorized"})
	_, err := measure(t, p, handPlan(socksNode("a", "198.51.100.1", 1, "")), "a")
	if err == nil || err.Error() != msgRefused {
		t.Errorf("error %v, want %q", err, msgRefused)
	}
}

func TestMeasureInstanceDies(t *testing.T) {
	p, bin, _ := installFake(t, fakeMode{Mode: "die-after-first"})
	_, err := measure(t, p, handPlan(socksNode("a", "198.51.100.1", 1, "")), "a")
	if err == nil || !strings.HasPrefix(err.Error(), "Тестовый sing-box завершился во время проверки") {
		t.Errorf("error %v", err)
	}
	if pids := processesOf(t, filepath.Join(bin, config.SingBoxExe)); len(pids) != 0 {
		t.Errorf("test instance %v still runs", pids)
	}
}

// The end of ctx while measuring leaves the rest unfinished, at once;
// before, it is the error
func TestMeasureCancel(t *testing.T) {
	p, bin, _ := installFake(t, fakeMode{Mode: "serve", Delays: map[string]int{"a": -3, "b": -3}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		// Once both tests are in flight (the readiness check is a request too)
		for range 200 {
			if data, _ := os.ReadFile(filepath.Join(bin, fakeLogFile)); strings.Count(string(data), `"request"`) > 2 {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		cancel()
	}()
	began := time.Now()
	got, err := p.Measure(ctx, handPlan(socksNode("a", "198.51.100.1", 1, ""), socksNode("b", "198.51.100.2", 1, "")), []string{"a", "b"})
	if err != nil {
		t.Fatal(err)
	}
	if got["a"].Status != domain.LatencyUnfinished || got["b"].Status != domain.LatencyUnfinished {
		t.Errorf("results %+v, want unfinished", got)
	}
	if took := time.Since(began); took > 4*time.Second {
		t.Errorf("returned %v after the start, want at the cancel", took)
	}
	if pids := processesOf(t, filepath.Join(bin, config.SingBoxExe)); len(pids) != 0 {
		t.Errorf("test instance %v still runs", pids)
	}

	t.Run("before the API answers", func(t *testing.T) {
		p, _, _ := installFake(t, fakeMode{Mode: "hang"})
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		_, err := p.Measure(ctx, handPlan(socksNode("a", "198.51.100.1", 1, "")), []string{"a"})
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("error %v, want the context's", err)
		}
	})
}

// ownedDial hands over only connections whose far end is the expected
// process; any other is closed before a byte is sent
func TestOwnedDial(t *testing.T) {
	taken := holdPort(t)
	ctx := context.Background()
	conn, err := ownedDial(taken.port, uint32(os.Getpid()))(ctx, "tcp", "ignored:1")
	if err != nil {
		t.Fatalf("own listener: %v", err)
	}
	conn.Close()
	if _, err := ownedDial(taken.port, uint32(os.Getpid())+4)(ctx, "tcp", "ignored:1"); !errors.Is(err, ErrForeignPort) {
		t.Errorf("another process's listener: %v, want ErrForeignPort", err)
	}
	taken.received(t)
	taken.mu.Lock()
	n := len(taken.got)
	taken.mu.Unlock()
	if n != 2 {
		t.Errorf("%d connections reached the listener, want 2", n)
	}
}

// The plan's config reaches the instance with the prober's clash_api and no
// other spelling of "experimental"
func TestInstanceConfig(t *testing.T) {
	plan := handPlan(socksNode("a", "198.51.100.1", 1, ""))
	plan.Config["Experimental"] = map[string]any{"clash_api": map[string]any{"external_controller": "0.0.0.0:9090"}}
	r := &run{plan: plan, secret: "s"}
	raw, err := r.instanceConfig(4321)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	json.Unmarshal(raw, &got)
	if _, ok := got["Experimental"]; ok {
		t.Error("the plan's Experimental reached the instance")
	}
	want := `{"clash_api":{"external_controller":"127.0.0.1:4321","secret":"s"}}`
	if ex, _ := json.Marshal(got["experimental"]); string(ex) != want {
		t.Errorf("experimental %s, want %s", ex, want)
	}
}
