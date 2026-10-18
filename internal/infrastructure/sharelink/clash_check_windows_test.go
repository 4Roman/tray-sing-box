package sharelink

import (
	"os"
	"path/filepath"
	"testing"

	"tray-sing-box/internal/infrastructure/singboxcheck"
)

// The Clash samples through the real sing-box, as TestSamplesPassSingBoxCheck
// takes the links and the JSON profiles: every entry the translation accepts
// must pass `sing-box check`. Enabled by SINGBOX_REAL_DIR; nothing is
// written there.
func TestClashSamplesPassSingBoxCheck(t *testing.T) {
	dir := os.Getenv("SINGBOX_REAL_DIR")
	if dir == "" {
		t.Skip("SINGBOX_REAL_DIR not set")
	}
	if _, err := os.Stat(filepath.Join(dir, "sing-box.exe")); err != nil {
		t.Skipf("sing-box.exe not found in %s", dir)
	}
	check := singboxcheck.NewValidator(dir, t.TempDir())

	var entries []string
	for _, c := range acceptedClash {
		entries = append(entries, c.entry)
	}
	for name, body := range map[string]string{"3x-ui": clash3xui, "entries": clashProxyList(entries...)} {
		t.Run(name, func(t *testing.T) {
			outbounds, _, err := ParseAllReport(body)
			if err != nil {
				t.Fatalf("ParseAllReport: %v", err)
			}
			err = check(minimalConfig(t, outbounds))
			if err == nil {
				t.Logf("%d outbound(s) accepted by sing-box check", len(outbounds))
				return
			}
			t.Errorf("sing-box check: %v", err)
			// Which ones: each alone
			for _, o := range outbounds {
				if err := check(minimalConfig(t, []Outbound{o})); err != nil {
					t.Errorf("%s: %v", o.Tag(), err)
				}
			}
		})
	}
}
