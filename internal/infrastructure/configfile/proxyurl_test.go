package configfile

import (
	"os"
	"path/filepath"
	"testing"
)

func editorFor(t *testing.T, configJSON string) *Editor {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(configJSON), 0644); err != nil {
		t.Fatal(err)
	}
	return New(path)
}

func TestLocalProxyURLPrefersMixed(t *testing.T) {
	editor := editorFor(t, `{
	  "inbounds": [
	    {"type": "socks", "tag": "s", "listen": "127.0.0.1", "listen_port": 1080},
	    {"type": "mixed", "tag": "m", "listen": "127.0.0.1", "listen_port": 2080}
	  ],
	  "outbounds": []
	}`)

	got, err := editor.LocalProxyURL()
	if err != nil {
		t.Fatal(err)
	}
	if got != "http://127.0.0.1:2080" {
		t.Fatalf("LocalProxyURL = %q", got)
	}
}

func TestLocalProxyURLSocksFallback(t *testing.T) {
	editor := editorFor(t, `{
	  "inbounds": [
	    {"type": "tun", "tag": "t"},
	    {"type": "socks", "tag": "s", "listen": "127.0.0.1", "listen_port": 1080}
	  ],
	  "outbounds": []
	}`)

	got, err := editor.LocalProxyURL()
	if err != nil {
		t.Fatal(err)
	}
	if got != "socks5://127.0.0.1:1080" {
		t.Fatalf("LocalProxyURL = %q", got)
	}
}

func TestLocalProxyURLNoneForTunOnly(t *testing.T) {
	editor := editorFor(t, `{
	  "inbounds": [{"type": "tun", "tag": "t"}],
	  "outbounds": []
	}`)

	got, err := editor.LocalProxyURL()
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Fatalf("TUN-only config must yield no proxy URL, got %q", got)
	}
}
