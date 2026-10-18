//go:build windows

package latency

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"tray-sing-box/internal/config"
)

// The fake sing-box: the test binary copied into a test's Bin dir as
// sing-box.exe (installFake) and started by the prober as "sing-box run -c
// <stdin|file>". What it does is read from fake-mode.json next to it — the
// prober builds the child's environment from scratch, so nothing can be
// passed that way — and what it saw goes to fake-log.json there, one JSON
// event per line. It answers like sing-box's Clash API, chi's routing
// included (RawPath when Go's server set it, then sing-box's own unescape).

const (
	fakeModeFile = "fake-mode.json"
	fakeLogFile  = "fake-log.json"
)

// fakeMode is what the fake does
type fakeMode struct {
	// Mode: "serve"; "nostdin" (a build that takes "stdin" for a file
	// name); "noclash" (a build without the Clash API); "fail-tag" (the
	// outbound Tag cannot be created: initialize outbound[N]); "fail-first"
	// (outbound[0] cannot be created, whichever it is); "crash" (exits
	// printing the secret and the first outbound's password); "hang" (never
	// listens); "unauthorized" (refuses every request); "die-after-first"
	// (exits at the first delay test)
	Mode string
	Tag  string
	// Delays answer the delay tests by tag: >0 ok with that delay, after
	// as long, -1 504,
	// -2 503, -3 no answer until the request is gone; a tag not listed but
	// in the config 503, not in the config 404
	Delays map[string]int
}

// fakeEvent is one line of fake-log.json
type fakeEvent struct {
	Event  string         // "start" or "request"
	PID    int            `json:",omitempty"`
	Args   []string       `json:",omitempty"`
	Dir    string         `json:",omitempty"`
	Path   string         `json:",omitempty"` // the PATH it was given
	Via    string         `json:",omitempty"` // "stdin" or "file"
	File   string         `json:",omitempty"` // the config file, via a file
	Config map[string]any `json:",omitempty"`
	Tag    string         `json:",omitempty"` // request: the decoded tag ("/version" for that)
	// FileLeft: at this request, the config file still existed
	FileLeft bool `json:",omitempty"`
}

func TestMain(m *testing.M) {
	if len(os.Args) > 2 && os.Args[1] == "run" && strings.EqualFold(filepath.Base(os.Args[0]), config.SingBoxExe) {
		os.Exit(fakeSingBox())
	}
	// Started as "sing-box run" by anything else: never run the suite
	// recursively
	if len(os.Args) > 1 && os.Args[1] == "run" {
		os.Exit(3)
	}
	os.Exit(m.Run())
}

var fakeLogMu sync.Mutex

func fakeLog(dir string, e fakeEvent) {
	fakeLogMu.Lock()
	defer fakeLogMu.Unlock()
	line, _ := json.Marshal(e)
	f, err := os.OpenFile(filepath.Join(dir, fakeLogFile), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	f.Write(append(line, '\n'))
}

func fakeFatal(format string, args ...any) int {
	// Coloured, like the real thing
	fmt.Fprintf(os.Stderr, "\x1b[31mFATAL\x1b[0m[0000] "+format+"\n", args...)
	return 1
}

func fakeSingBox() int {
	exe, _ := os.Executable()
	dir := filepath.Dir(exe)
	data, err := os.ReadFile(filepath.Join(dir, fakeModeFile))
	if err != nil {
		return 3
	}
	var mode fakeMode
	if json.Unmarshal(data, &mode) != nil {
		return 3
	}
	source := os.Args[3]
	cwd, _ := os.Getwd()
	start := fakeEvent{Event: "start", PID: os.Getpid(), Args: os.Args, Dir: cwd, Path: os.Getenv("PATH")}
	var raw []byte
	switch {
	case source == "stdin" && mode.Mode == "nostdin":
		fakeLog(dir, fakeEvent{Event: "start", PID: os.Getpid(), Args: os.Args, Via: "stdin"})
		return fakeFatal("read config at stdin: open stdin: The system cannot find the file specified.")
	case source == "stdin":
		start.Via = "stdin"
		raw, err = io.ReadAll(os.Stdin)
	default:
		start.Via, start.File = "file", source
		raw, err = os.ReadFile(source)
	}
	if err != nil {
		return fakeFatal("read config at %s: %v", source, err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fakeFatal("decode config at %s: %v", source, err)
	}
	start.Config = cfg
	fakeLog(dir, start)

	outbounds, _ := cfg["outbounds"].([]any)
	tags := map[string]bool{}
	var firstPassword string
	for i, o := range outbounds {
		ob, _ := o.(map[string]any)
		tag, _ := ob["tag"].(string)
		tags[tag] = true
		if i == 0 {
			firstPassword, _ = ob["password"].(string)
		}
		switch {
		case mode.Mode == "fail-tag" && tag == mode.Tag,
			mode.Mode == "fail-first" && i == 0:
			password, _ := ob["password"].(string)
			return fakeFatal("create service: initialize outbound[%d]: cannot use password %s here", i, password)
		}
	}
	api, _ := cfg["experimental"].(map[string]any)["clash_api"].(map[string]any)
	controller, _ := api["external_controller"].(string)
	secret, _ := api["secret"].(string)
	switch mode.Mode {
	case "noclash":
		return fakeFatal("create service: clash api is not included in this build, rebuild with -tags with_clash_api")
	case "crash":
		return fakeFatal("create service: something broke: secret %s, password %s, controller %s", secret, firstPassword, controller)
	case "hang":
		time.Sleep(time.Hour)
		return 0
	}

	l, err := net.Listen("tcp", controller)
	if err != nil {
		return fakeFatal("start service: finish-start clash server: external controller listen error: %v", err)
	}
	fileLeft := func() bool {
		if start.File == "" {
			return false
		}
		_, err := os.Stat(start.File)
		return err == nil
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route := r.URL.RawPath
		if route == "" {
			route = r.URL.Path
		}
		if mode.Mode == "unauthorized" || r.Header.Get("Authorization") != "Bearer "+secret {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"message":"Unauthorized"}`)
			return
		}
		if route == "/version" {
			fakeLog(dir, fakeEvent{Event: "request", Tag: "/version", FileLeft: fileLeft()})
			fmt.Fprint(w, `{"meta":true,"premium":true,"version":"sing-box 1.14.2"}`)
			return
		}
		parts := strings.Split(route, "/")
		if len(parts) != 4 || parts[1] != "proxies" || parts[3] != "delay" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		tag := parts[2]
		if unescaped, err := url.PathUnescape(tag); err == nil {
			tag = unescaped
		}
		fakeLog(dir, fakeEvent{Event: "request", Tag: tag, FileLeft: fileLeft()})
		if mode.Mode == "die-after-first" {
			os.Exit(1)
		}
		ms, listed := mode.Delays[tag]
		switch {
		case !tags[tag]:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"message":"Resource not found"}`)
		case !listed || ms == -2:
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, `{"message":"An error occurred in the delay test"}`)
		case ms == -1:
			w.WriteHeader(http.StatusGatewayTimeout)
			fmt.Fprint(w, `{"message":"Timeout"}`)
		case ms == -3:
			<-r.Context().Done()
		default:
			time.Sleep(time.Duration(ms) * time.Millisecond)
			fmt.Fprintf(w, `{"delay":%d}`, ms)
		}
	})
	http.Serve(l, handler)
	return 0
}

// installFake puts the fake sing-box into a new Bin dir and returns a
// prober for it with a data dir of its own
func installFake(t *testing.T, mode fakeMode) (p *Prober, bin, data string) {
	t.Helper()
	bin, data = tempDir(t), tempDir(t)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	copyFile(t, self, filepath.Join(bin, config.SingBoxExe))
	raw, _ := json.Marshal(mode)
	if err := os.WriteFile(filepath.Join(bin, fakeModeFile), raw, 0644); err != nil {
		t.Fatal(err)
	}
	noLeftover(t, filepath.Join(bin, config.SingBoxExe))
	return New(bin, data), bin, data
}

// fakeEvents reads what the fake logged in bin
func fakeEvents(t *testing.T, bin string) (starts, requests []fakeEvent) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(bin, fakeLogFile))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var e fakeEvent
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("fake log line %q: %v", line, err)
		}
		if e.Event == "start" {
			starts = append(starts, e)
		} else {
			requests = append(requests, e)
		}
	}
	return starts, requests
}

// tempDir is t.TempDir with a patient cleanup: the antivirus briefly holds a
// freshly written exe, and t.TempDir's single attempt then fails the test
func tempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "latency-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		var err error
		for range 50 {
			if err = os.RemoveAll(dir); err == nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Logf("leaving %s behind: %v", dir, err)
	})
	return dir
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	src, err := os.Open(from)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	dst, err := os.Create(to)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		t.Fatal(err)
	}
	if err := dst.Close(); err != nil {
		t.Fatal(err)
	}
}

// noLeftover makes the test fail when a process of exe still runs at its
// end — and ends it, so that the temp dir can go. Registered after the
// dir's cleanup: runs before it. Matched by full image path: only this
// test's copy.
func noLeftover(t *testing.T, exe string) {
	t.Helper()
	t.Cleanup(func() {
		for _, pid := range processesOf(t, exe) {
			t.Errorf("a process of %s (PID %d) outlived the test", exe, pid)
			if h, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, pid); err == nil {
				windows.TerminateProcess(h, 1)
				windows.WaitForSingleObject(h, 5000)
				windows.CloseHandle(h)
			}
		}
	})
}

// processesOf lists the processes whose image is exe (full path)
func processesOf(t *testing.T, exe string) []uint32 {
	t.Helper()
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		t.Fatalf("process snapshot: %v", err)
	}
	defer windows.CloseHandle(snapshot)
	var pids []uint32
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	for err = windows.Process32First(snapshot, &entry); err == nil; err = windows.Process32Next(snapshot, &entry) {
		if !strings.EqualFold(windows.UTF16ToString(entry.ExeFile[:]), filepath.Base(exe)) {
			continue
		}
		h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, entry.ProcessID)
		if err != nil {
			continue
		}
		buf := make([]uint16, windows.MAX_LONG_PATH)
		size := uint32(len(buf))
		err = windows.QueryFullProcessImageName(h, 0, &buf[0], &size)
		windows.CloseHandle(h)
		if err == nil && strings.EqualFold(syscall.UTF16ToString(buf[:size]), exe) {
			pids = append(pids, entry.ProcessID)
		}
	}
	return pids
}
