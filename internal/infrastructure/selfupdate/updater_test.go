package selfupdate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The staged exe is really executed with --version: the test binary copies
// itself into the temp dir and answers as the fake app when this env is set
const fakeVersionEnv = "TRAY_SELFUPDATE_FAKE_VERSION"

func TestMain(m *testing.M) {
	if v := os.Getenv(fakeVersionEnv); v != "" {
		// Fake mode: NEVER fall through into m.Run() — a Relaunch with wrong
		// arguments would otherwise start the whole test suite recursively
		switch {
		case len(os.Args) > 1 && os.Args[1] == "--version":
			fmt.Println(v)
		case len(os.Args) > 1 && strings.HasPrefix(os.Args[1], "--wait-pid="):
			// The relaunched app: report what it was started with, atomically
			if p := os.Getenv("TRAY_SELFUPDATE_ARGS_FILE"); p != "" {
				os.WriteFile(p+".tmp", []byte(strings.Join(os.Args[1:], " ")), 0644)
				os.Rename(p+".tmp", p)
			}
		case len(os.Args) > 1 && os.Args[1] == "--hang":
			time.Sleep(time.Minute)
		default:
			fmt.Fprintln(os.Stderr, "fake app: unexpected arguments", os.Args[1:])
			os.Exit(3)
		}
		return
	}
	os.Exit(m.Run())
}

// fakeRelease is a GitHub release served by an httptest server
type fakeRelease struct {
	version   string
	exe       []byte
	pub, priv string
	tamper    func(assets map[string][]byte) // last-minute changes to the served files
}

func serveRelease(t *testing.T, r fakeRelease) *httptest.Server {
	t.Helper()
	exeName := AssetName(r.version)
	assets := map[string][]byte{exeName: r.exe}

	sums := map[string]string{exeName: sha256Hex(r.exe)}
	manifest := FormatChecksums(sums, []string{exeName})
	assets[ChecksumsFile] = manifest
	priv, err := ParsePrivateKey(r.priv)
	if err != nil {
		t.Fatal(err)
	}
	assets[SignatureFile] = []byte(Sign(priv, manifest) + "\n")
	if r.tamper != nil {
		r.tamper(assets)
	}

	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/releases/latest", func(w http.ResponseWriter, req *http.Request) {
		type asset struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		}
		var list []asset
		for name := range assets {
			list = append(list, asset{Name: name, URL: srv.URL + "/download/" + name})
		}
		json.NewEncoder(w).Encode(map[string]any{
			"tag_name": "v" + r.version,
			"body":     "release notes",
			"assets":   list,
		})
	})
	mux.HandleFunc("/download/", func(w http.ResponseWriter, req *http.Request) {
		data, ok := assets[strings.TrimPrefix(req.URL.Path, "/download/")]
		if !ok {
			http.NotFound(w, req)
			return
		}
		w.Write(data)
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func sha256Hex(data []byte) string {
	dir, _ := os.MkdirTemp("", "sum")
	defer os.RemoveAll(dir)
	p := filepath.Join(dir, "f")
	os.WriteFile(p, data, 0644)
	sum, _ := FileSHA256(p)
	return sum
}

// newTestUpdater installs a fake "running exe" in a temp dir and points the
// updater at the fake release server
func newTestUpdater(t *testing.T, srv *httptest.Server, pub string) (*Updater, string) {
	t.Helper()
	dir := t.TempDir()
	exePath := filepath.Join(dir, "tray-sing-box.exe")
	if err := os.WriteFile(exePath, []byte("old build"), 0755); err != nil {
		t.Fatal(err)
	}
	u, err := New(exePath, "owner/repo", pub)
	if err != nil {
		t.Fatal(err)
	}
	u.apiURL = srv.URL + "/releases/latest"
	u.client = srv.Client()
	return u, exePath
}

func selfBinary(t *testing.T) []byte {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestNewRequiresConfiguration(t *testing.T) {
	if _, err := New("x.exe", "", "AAAA"); err == nil {
		t.Fatal("empty repo accepted")
	}
	if _, err := New("x.exe", "o/r", ""); err == nil {
		t.Fatal("empty key accepted")
	}
	if _, err := New("x.exe", "o/r", "not-a-key"); err == nil {
		t.Fatal("garbage key accepted")
	}
}

func TestAssetName(t *testing.T) {
	if got := AssetName("v1.2.3"); !strings.HasPrefix(got, "tray-sing-box-1.2.3-windows-") || !strings.HasSuffix(got, ".exe") {
		t.Fatalf("AssetName = %q", got)
	}
}

// The whole happy path: latest release -> signed manifest -> exe download ->
// checksum -> the staged exe really runs and reports the version -> swap
func TestDownloadVerifiesAndInstallSwaps(t *testing.T) {
	pub, priv, _ := GenerateKey()
	srv := serveRelease(t, fakeRelease{version: "1.2.3", exe: selfBinary(t), pub: pub, priv: priv})
	u, exePath := newTestUpdater(t, srv, pub)
	u.versionCommand = func(ctx context.Context, staged string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, staged, "--version")
		cmd.Env = append(os.Environ(), fakeVersionEnv+"=v1.2.3")
		return cmd
	}

	rel, err := u.LatestRelease()
	if err != nil {
		t.Fatalf("LatestRelease: %v", err)
	}
	if rel.Version != "1.2.3" || rel.Notes != "release notes" {
		t.Fatalf("release = %+v", rel)
	}

	staged, err := u.Download(rel)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if staged != exePath+".new" {
		t.Fatalf("staged at %q, want next to the exe", staged)
	}

	if err := u.Install(staged); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if old, err := os.ReadFile(exePath + ".old"); err != nil || string(old) != "old build" {
		t.Fatalf("previous exe not kept as .old: %v", err)
	}
	if info, err := os.Stat(exePath); err != nil || info.Size() != int64(len(selfBinary(t))) {
		t.Fatalf("new exe not in place: %v", err)
	}
	if _, err := os.Stat(staged); !os.IsNotExist(err) {
		t.Fatal("staged file still there after Install")
	}
}

func TestDownloadRejectsBadSignature(t *testing.T) {
	pub, priv, _ := GenerateKey()
	otherPub, otherPriv, _ := GenerateKey()
	_ = pub
	cases := map[string]fakeRelease{
		"signed with another key": {version: "1.2.3", exe: []byte("exe"), pub: otherPub, priv: otherPriv},
		"manifest modified after signing": {version: "1.2.3", exe: []byte("exe"), pub: pub, priv: priv, tamper: func(a map[string][]byte) {
			a[ChecksumsFile] = append(a[ChecksumsFile], []byte("# evil\n")...)
		}},
		"garbage signature": {version: "1.2.3", exe: []byte("exe"), pub: pub, priv: priv, tamper: func(a map[string][]byte) {
			a[SignatureFile] = []byte("nope")
		}},
	}
	for name, r := range cases {
		srv := serveRelease(t, r)
		u, exePath := newTestUpdater(t, srv, pub)
		rel, err := u.LatestRelease()
		if err != nil {
			t.Fatalf("%s: LatestRelease: %v", name, err)
		}
		if _, err := u.Download(rel); err == nil || !strings.Contains(err.Error(), "rejected") {
			t.Fatalf("%s: Download = %v, want rejection", name, err)
		}
		if _, err := os.Stat(exePath + ".new"); !os.IsNotExist(err) {
			t.Fatalf("%s: staged file left behind", name)
		}
	}
}

func TestDownloadRejectsChecksumMismatch(t *testing.T) {
	pub, priv, _ := GenerateKey()
	srv := serveRelease(t, fakeRelease{version: "1.2.3", exe: []byte("exe"), pub: pub, priv: priv, tamper: func(a map[string][]byte) {
		a[AssetName("1.2.3")] = []byte("replaced exe") // manifest still signed for the original
	}})
	u, exePath := newTestUpdater(t, srv, pub)
	rel, _ := u.LatestRelease()
	if _, err := u.Download(rel); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("Download = %v, want checksum mismatch", err)
	}
	if _, err := os.Stat(exePath + ".new"); !os.IsNotExist(err) {
		t.Fatal("staged file left behind")
	}
}

func TestDownloadRejectsWrongVersionAndBrokenExe(t *testing.T) {
	pub, priv, _ := GenerateKey()
	srv := serveRelease(t, fakeRelease{version: "1.2.3", exe: selfBinary(t), pub: pub, priv: priv})
	u, _ := newTestUpdater(t, srv, pub)
	rel, _ := u.LatestRelease()

	u.versionCommand = func(ctx context.Context, staged string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, staged, "--version")
		cmd.Env = append(os.Environ(), fakeVersionEnv+"=v9.9.9")
		return cmd
	}
	if _, err := u.Download(rel); err == nil || !strings.Contains(err.Error(), "reports version") {
		t.Fatalf("Download = %v, want version mismatch", err)
	}

	// An exe that never answers must not hang the update (and every other
	// operation behind the locks) forever
	setStagedVersionTimeout(t, 2*time.Second)
	u.versionCommand = func(ctx context.Context, staged string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, staged, "--hang")
		cmd.Env = append(os.Environ(), fakeVersionEnv+"=v1.2.3")
		return cmd
	}
	start := time.Now()
	if _, err := u.Download(rel); err == nil || !strings.Contains(err.Error(), "no answer to --version") {
		t.Fatalf("Download = %v, want a timeout", err)
	}
	if time.Since(start) > 30*time.Second {
		t.Fatal("timeout did not bound the --version run")
	}

	// An exe that is not runnable at all
	srv2 := serveRelease(t, fakeRelease{version: "1.2.3", exe: []byte("not an exe"), pub: pub, priv: priv})
	u2, _ := newTestUpdater(t, srv2, pub)
	rel2, _ := u2.LatestRelease()
	if _, err := u2.Download(rel2); err == nil || !strings.Contains(err.Error(), "does not run") {
		t.Fatalf("Download = %v, want 'does not run'", err)
	}
}

func TestLatestReleaseRefusesNonReleaseTags(t *testing.T) {
	pub, priv, _ := GenerateKey()
	srv := serveRelease(t, fakeRelease{version: "1.2.3-rc1", exe: []byte("exe"), pub: pub, priv: priv})
	u, _ := newTestUpdater(t, srv, pub)
	if _, err := u.LatestRelease(); err == nil || !strings.Contains(err.Error(), "not a release version") {
		t.Fatalf("rc tag accepted as latest: %v", err)
	}
}

func TestLatestReleaseRequiresAllAssets(t *testing.T) {
	pub, priv, _ := GenerateKey()
	for _, missing := range []string{SignatureFile, ChecksumsFile, AssetName("1.2.3")} {
		srv := serveRelease(t, fakeRelease{version: "1.2.3", exe: []byte("exe"), pub: pub, priv: priv, tamper: func(a map[string][]byte) {
			delete(a, missing)
		}})
		u, _ := newTestUpdater(t, srv, pub)
		if _, err := u.LatestRelease(); err == nil {
			t.Fatalf("release without %s accepted", missing)
		}
	}
}

func TestInstallRestoresOnFailure(t *testing.T) {
	dir := t.TempDir()
	exePath := filepath.Join(dir, "tray-sing-box.exe")
	os.WriteFile(exePath, []byte("old build"), 0755)
	pub, _, _ := GenerateKey()
	u, _ := New(exePath, "o/r", pub)

	// No staged file: the swap must fail and the old exe must be back
	if err := u.Install(exePath + ".new"); err == nil {
		t.Fatal("Install without a staged file succeeded")
	}
	if data, err := os.ReadFile(exePath); err != nil || string(data) != "old build" {
		t.Fatalf("running exe not restored: %v", err)
	}
}

func TestRelaunchStartsTheExe(t *testing.T) {
	dir := t.TempDir()
	exePath := filepath.Join(dir, "tray-sing-box.exe")
	if err := os.WriteFile(exePath, selfBinary(t), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv(fakeVersionEnv, "v1.0.0") // the child exits at once on --wait-pid
	argsFile := filepath.Join(t.TempDir(), "args.txt")
	t.Setenv("TRAY_SELFUPDATE_ARGS_FILE", argsFile)
	pub, _, _ := GenerateKey()
	u, _ := New(exePath, "o/r", pub)
	if err := u.Relaunch(); err != nil {
		t.Fatalf("Relaunch: %v", err)
	}

	// The child must have been told which process to wait for: ours
	deadline := time.Now().Add(15 * time.Second)
	for {
		if data, err := os.ReadFile(argsFile); err == nil {
			want := fmt.Sprintf("--wait-pid=%d", os.Getpid())
			if strings.TrimSpace(string(data)) != want {
				t.Fatalf("relaunched with %q, want %q", data, want)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("relaunched process never reported its arguments")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// setStagedVersionTimeout overrides the --version timeout for one test
func setStagedVersionTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	old := stagedVersionTimeout
	stagedVersionTimeout = d
	t.Cleanup(func() { stagedVersionTimeout = old })
}
