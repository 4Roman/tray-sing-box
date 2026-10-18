//go:build windows

package latency

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"tray-sing-box/internal/config"
	"tray-sing-box/internal/domain"
	"tray-sing-box/internal/infrastructure/process"
)

// The checks that could not run, as the user reads them
var (
	ErrNoClashAPI  = errors.New("Ваш sing-box собран без Clash API (with_clash_api) — проверка задержки недоступна")
	ErrNotIsolated = errors.New("Не удалось изолировать тестовый sing-box — проверка отменена")
)

const (
	msgNotStarted = "Тестовый sing-box не запустился: %s"
	msgNotReady   = "Тестовый sing-box не ответил за %d с"
	msgDied       = "Тестовый sing-box завершился во время проверки: %s"
	msgRefused    = "Тестовый sing-box не принял ключ своего Clash API — проверка прервана"
	msgNoAnswer   = "Тестовый sing-box перестал отвечать — проверка прервана"
)

// What sing-box prints when it cannot run the config it is given
const (
	listenError = "external controller listen error" // the API port was taken meanwhile
	noClashAPI  = "clash api is not included"        // a build without with_clash_api
	stdinRead   = "read config at stdin"             // reading the config from stdin failed
	stdinOpened = "open stdin:"                      // a build without stdin took "stdin" for a file name
)

const (
	portShown   = "127.0.0.1:<порт проверки>" // what a message shows for the API address
	tempPattern = ".latency-*.json"           // the fallback config file, in the data dir
)

var errExited = errors.New("the test instance exited before its API answered")

// Test hooks
var (
	pickPort       = freeLoopbackPort
	connOwner      = process.ConnOwnerPID
	startTimeout   = time.Duration(config.LatencyStartTimeout) * time.Second
	readyPoll      = 100 * time.Millisecond
	isolateRetries = config.LatencyIsolateRetries
	// diedWait: how long a test instance whose API failed below HTTP is
	// given to be seen gone (its exit is what the user is told then)
	diedWait = time.Second
)

// Prober is the domain.LatencyProber: every Measure starts the app's own
// <Bin>\sing-box.exe as a process.Helper — not the VPN to the process
// manager, killed with its job when the app goes away — with the plan's
// config plus a Clash API on a free loopback port and a secret only this
// process knows. Both reach it through stdin: nothing on disk, nothing on
// its command line (which every program can read).
type Prober struct{ binDir, dataDir string }

// New returns a prober running the sing-box.exe in binDir with dataDir as
// its working directory, like the VPN: relative paths of the config resolve
// there
func New(binDir, dataDir string) *Prober {
	return &Prober{binDir: binDir, dataDir: dataDir}
}

// Measure measures the given tags of the plan in a test instance of its own,
// started for this call and ended before it returns. The tags are measured
// in the order given (the caller puts the active server first). A tag the
// instance does not carry is LatencySkipped, with the note of the plan as it
// finally ran: a server sing-box could not start on its own is left out
// (plan.Exclude, at most LatencyIsolateRetries of them) and the others are
// measured. Once the measuring has begun, the end of ctx leaves the rest
// LatencyUnfinished and is no error (the caller tells a deadline from a
// cancel by its ctx); before, it is ctx.Err(). Every text of the test
// instance has passed plan.Redact. One log line per call.
func (p *Prober) Measure(ctx context.Context, plan *domain.ProbePlan, tags []string) (map[string]domain.Delay, error) {
	began := time.Now()
	exe := filepath.Join(p.binDir, config.SingBoxExe)
	if _, err := os.Stat(exe); err != nil {
		return nil, fmt.Errorf("%w at: %s", domain.ErrSingBoxMissing, exe)
	}
	secret, err := newSecret()
	if err != nil {
		return nil, fmt.Errorf(msgNotStarted, "не удалось создать ключ проверки")
	}
	r := &run{prober: p, exe: exe, plan: plan, secret: secret}

	inst, err := r.start(ctx, tags)
	if err != nil {
		log.Printf("Latency: no check after %.1f s%s: %v", time.Since(began).Seconds(), r.summary(), r.logged(err))
		return nil, err
	}
	results := r.skipped(tags)
	measured := r.measurable(tags)
	if inst == nil {
		log.Printf("Latency: nothing to measure of %d servers%s", len(tags), r.summary())
		return results, nil
	}
	defer inst.stop()

	// A test instance that dies meanwhile ends the measuring at once
	mctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	go func() {
		select {
		case <-inst.helper.Done():
			cancel(errExited)
		case <-mctx.Done():
		}
	}()
	delays, err := measureAll(mctx, inst.client, measured)
	if errors.Is(err, errNoAnswer) {
		// Its API failed below HTTP: the instance is going, or gone
		select {
		case <-inst.helper.Done():
		case <-time.After(diedWait):
		}
	}
	// The end of ctx is no error here: what was measured stands
	switch {
	case errors.Is(context.Cause(mctx), errExited) || (err != nil && inst.exited()):
		err = fmt.Errorf(msgDied, r.message(r.redact(inst.output.String(), inst.port)))
	case errors.Is(err, errUnauthorized):
		err = errors.New(msgRefused)
	case errors.Is(err, errNoAnswer):
		err = errors.New(msgNoAnswer)
	}
	if err != nil {
		log.Printf("Latency: check failed after %.1f s (test sing-box PID %d%s): %v",
			time.Since(began).Seconds(), inst.helper.PID(), r.summary(), err)
		return nil, err
	}

	answered := 0
	for tag, d := range delays {
		results[tag] = d
		if d.Status == domain.LatencyOK {
			answered++
		}
	}
	log.Printf("Latency: %d of %d answered in %.1f s (test sing-box PID %d%s)",
		answered, len(measured), time.Since(began).Seconds(), inst.helper.PID(), r.summary())
	return results, nil
}

// run is one Measure: the plan as it stands after the servers left out, and
// how the test instance came up
type run struct {
	prober *Prober
	exe    string
	plan   *domain.ProbePlan
	secret string

	starts      int
	portRetried bool // the API port was taken between choosing and listening, once
	viaFile     bool // a build that cannot read its config from stdin
	excluded    int  // servers left out because sing-box could not start them alone
	isolation   error
}

// instance is a test instance whose API answers
type instance struct {
	helper *process.Helper
	client *client
	output *tailBuffer
	port   int
}

func (i *instance) stop() {
	if err := i.helper.Stop(time.Duration(config.LatencyStopTimeout) * time.Second); err != nil {
		log.Printf("Warning: latency test instance: %v", err)
	}
	i.client.http.CloseIdleConnections()
}

// exited: the instance has ended (on its own, unless stop was called)
func (i *instance) exited() bool {
	select {
	case <-i.helper.Done():
		return true
	default:
		return false
	}
}

// start brings up a test instance for the measurable tags: nil (and no
// error) when no tag is left to measure. A test instance that exits before
// its API answers is started again when the reason can be dealt with: the
// API port taken meanwhile (once, on a new port), a build without stdin
// (once, through a temporary file), or one server sing-box could not create
// on its own (left out, at most isolateRetries times).
func (r *run) start(ctx context.Context, tags []string) (*instance, error) {
	for {
		if len(r.measurable(tags)) == 0 {
			return nil, nil
		}
		inst, output, err := r.launch(ctx)
		if !errors.Is(err, errExited) {
			return inst, err
		}
		switch {
		case strings.Contains(output, listenError):
			if r.portRetried {
				// Taken twice in a row: someone takes whatever port is free
				return nil, ErrForeignPort
			}
			r.portRetried = true
			continue
		case strings.Contains(output, noClashAPI):
			return nil, ErrNoClashAPI
		case !r.viaFile && (strings.Contains(output, stdinRead) || strings.Contains(output, stdinOpened)):
			r.viaFile = true
			continue
		}
		if r.plan.Exclude != nil && r.excluded < isolateRetries {
			if next, ok := r.plan.Exclude(output); ok {
				r.plan = next
				r.excluded++
				continue
			}
		}
		return nil, fmt.Errorf(msgNotStarted, r.message(output))
	}
}

// launch starts one test instance and waits until its API answers. When
// the instance exits first, the error is errExited and the output its
// redacted output.
func (r *run) launch(ctx context.Context) (*instance, string, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	port, err := pickPort()
	if err != nil {
		return nil, "", fmt.Errorf(msgNotStarted, "нет свободного порта на 127.0.0.1")
	}
	data, err := r.instanceConfig(port)
	if err != nil {
		return nil, "", fmt.Errorf(msgNotStarted, "конфиг проверки не кодируется в JSON")
	}
	args := []string{"run", "-c", "stdin"}
	if r.viaFile {
		// Only the fallback: the secret is on disk, in the data dir (admin
		// only in the installed layout), until the instance has read it
		file, err := writeTempConfig(r.prober.dataDir, data)
		if err != nil {
			return nil, "", fmt.Errorf(msgNotStarted, "не удалось записать временный конфиг в папку данных")
		}
		defer os.Remove(file)
		args[2] = file
	}
	cmd := process.NewHiddenCommand(r.exe, args...)
	cmd.Dir = r.prober.dataDir
	cmd.Env = process.SingBoxEnv(r.prober.binDir, r.prober.dataDir)
	if !r.viaFile {
		cmd.Stdin = bytes.NewReader(data)
	}
	out := newTailBuffer(config.StartErrorTailBytes)
	cmd.Stdout, cmd.Stderr = out, out

	r.starts++
	h, err := process.StartHelper(cmd)
	if err != nil {
		if errors.Is(err, process.ErrHelperNotIsolated) {
			r.isolation = err
			return nil, "", ErrNotIsolated
		}
		return nil, "", fmt.Errorf(msgNotStarted, err)
	}
	inst := &instance{helper: h, client: newClient(port, r.secret, ownedDial(port, h.PID())), output: out, port: port}

	deadline := time.NewTimer(startTimeout)
	defer deadline.Stop()
	poll := time.NewTicker(readyPoll)
	defer poll.Stop()
	foreign := false
	for {
		switch err := inst.client.version(ctx); {
		case err == nil:
			return inst, "", nil
		case errors.Is(err, errUnauthorized):
			inst.stop()
			return nil, "", errors.New(msgRefused)
		case errors.Is(err, ErrForeignPort):
			// Not ready yet: someone else holds the port, and the instance
			// is about to fail to listen on it (or is listening beside it)
			foreign = true
		}
		select {
		case <-h.Done():
			inst.stop()
			return nil, r.redact(out.String(), port), errExited
		case <-ctx.Done():
			inst.stop()
			return nil, "", ctx.Err()
		case <-deadline.C:
			inst.stop()
			if foreign {
				return nil, "", ErrForeignPort
			}
			return nil, "", fmt.Errorf(msgNotReady, int(startTimeout.Round(time.Second)/time.Second))
		case <-poll.C:
		}
	}
}

// instanceConfig is the plan's config with the Clash API of the test
// instance: on the loopback, with the secret
func (r *run) instanceConfig(port int) ([]byte, error) {
	cfg := make(map[string]any, len(r.plan.Config)+1)
	for k, v := range r.plan.Config {
		// The plan has none; a second spelling would be merged into ours
		// field by field by sing-box's case-insensitive decoder
		if !strings.EqualFold(k, "experimental") {
			cfg[k] = v
		}
	}
	cfg["experimental"] = map[string]any{"clash_api": map[string]any{
		"external_controller": net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		"secret":              r.secret,
	}}
	return json.Marshal(cfg)
}

// redact is what may be shown of an output: the plan's credentials and the
// secret replaced, the API address not named
func (r *run) redact(output string, port int) string {
	output = r.plan.Redact(output, r.secret)
	return strings.ReplaceAll(output, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), portShown)
}

// message is the reason a test instance gave for its end, on one line, an
// outbound named by its tag instead of its position (which counts every
// outbound of the instance's config — nothing the user can count). output
// has passed redact.
func (r *run) message(output string) string {
	outbounds, _ := r.plan.Config["outbounds"].([]any)
	named := indexedOutbound.ReplaceAllStringFunc(failureMessage(output), func(m string) string {
		n, err := strconv.Atoi(indexedOutbound.FindStringSubmatch(m)[1])
		if err != nil || n >= len(outbounds) {
			return m
		}
		o, _ := outbounds[n].(map[string]any)
		if tag, _ := o["tag"].(string); tag != "" {
			return "outbound «" + domain.DisplayName(tag) + "»"
		}
		return m
	})
	return clip(named, messageLimit)
}

// indexedOutbound is how sing-box names an outbound of its config
var indexedOutbound = regexp.MustCompile(`\boutbounds?\[(\d+)\]`)

// measurable are the tags the plan can test, without repeats, in the order
// given
func (r *run) measurable(tags []string) []string {
	testable := make(map[string]bool, len(r.plan.Candidates))
	for _, c := range r.plan.Candidates {
		if c.Testable {
			testable[c.Tag] = true
		}
	}
	var list []string
	for _, tag := range tags {
		if testable[tag] {
			list = append(list, tag)
			testable[tag] = false
		}
	}
	return list
}

// skipped is the result of every tag the plan does not test, with its note
func (r *run) skipped(tags []string) map[string]domain.Delay {
	notes := make(map[string]*domain.LatencyCandidate, len(r.plan.Candidates))
	for i := range r.plan.Candidates {
		if c := &r.plan.Candidates[i]; notes[c.Tag] == nil {
			notes[c.Tag] = c
		}
	}
	results := make(map[string]domain.Delay, len(tags))
	for _, tag := range tags {
		switch c := notes[tag]; {
		case c == nil:
			results[tag] = domain.Delay{Status: domain.LatencySkipped, Note: noteNotInInstance}
		case !c.Testable:
			results[tag] = domain.Delay{Status: domain.LatencySkipped, Note: c.Note}
		}
	}
	return results
}

// summary is what the log line says about the starts, if anything
func (r *run) summary() string {
	var s string
	if r.starts > 1 {
		s += fmt.Sprintf("; %d starts", r.starts)
	}
	if r.excluded > 0 {
		s += fmt.Sprintf("; %d left out", r.excluded)
	}
	if r.viaFile {
		s += "; config via a file"
	}
	return s
}

// logged is err as the log gets it: with the cause the user is not shown
func (r *run) logged(err error) error {
	if errors.Is(err, ErrNotIsolated) && r.isolation != nil {
		return fmt.Errorf("%v (%v)", err, r.isolation)
	}
	return err
}

// ownedDial connects to the test instance's API port and hands the
// connection over only when the process at its other end is the test
// instance itself: the listener of a loopback port is not proven by the
// port having been free a moment ago — a program of the user may have
// bound it since, or beside it (no SO_EXCLUSIVEADDRUSE), and would get the
// secret with the first request. Anything else is closed before its first
// byte.
func ownedDial(port int, pid uint32) func(ctx context.Context, network, addr string) (net.Conn, error) {
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		conn, err := d.DialContext(ctx, "tcp4", address)
		if err != nil {
			return nil, err
		}
		local, lok := conn.LocalAddr().(*net.TCPAddr)
		remote, rok := conn.RemoteAddr().(*net.TCPAddr)
		if lok && rok {
			// The row of the far end: the API port talking to our address
			if owner, err := connOwner(remote.AddrPort(), local.AddrPort()); err == nil && owner == pid {
				return conn, nil
			}
		}
		conn.Close()
		return nil, ErrForeignPort
	}
}

// freeLoopbackPort is a port nothing listens on at the moment (the test
// instance may still find it taken: a retry on a new one)
func freeLoopbackPort() (int, error) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// newSecret is the Clash API secret of one Measure: 32 random bytes in hex
func newSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// writeTempConfig writes the config of the test instance into a new file in
// dir (the data dir: inherits its DACL, admin only in the installed layout)
func writeTempConfig(dir string, data []byte) (string, error) {
	f, err := os.CreateTemp(dir, tempPattern)
	if err != nil {
		return "", err
	}
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}
