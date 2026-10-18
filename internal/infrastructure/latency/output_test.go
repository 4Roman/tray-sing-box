package latency

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTailBufferKeepsTheEnd(t *testing.T) {
	b := newTailBuffer(32)
	b.Write([]byte("first line that will be cut\nWARN[0000] a warning\n"))
	b.Write([]byte("\x1b[31mFATAL\x1b[0m[0000] the end\n"))
	got := b.String()
	if got != "FATAL[0000] the end\n" {
		t.Errorf("%q: want the last whole lines, colours removed", got)
	}
	short := newTailBuffer(100)
	short.Write([]byte("only line"))
	if s := short.String(); s != "only line" {
		t.Errorf("uncut: %q", s)
	}
}

func TestFailureMessage(t *testing.T) {
	for output, want := range map[string]string{
		"FATAL[0000] create service: initialize outbound[2]: uTLS is required by reality client\n": "create service: initialize outbound[2]: uTLS is required by reality client",
		"WARN[0000] something\nERROR[0000] first\nERROR[0000] second\n":                            "second",
		"ERROR[0000] noise\nFATAL[0000] the reason\nERROR[0000] after\n":                           "the reason",
		"panic: boom\n\ngoroutine 1 [running]:\nmain.main()\n":                                     "panic: boom",
		"just text\nlast words\n": "last words",
		"FATAL[0000] decode config at C:\\data\\.latency-123.json: outbounds[0].x: unknown field": "outbounds[0].x: unknown field",
		"": "",
	} {
		if got := failureMessage(output); got != want {
			t.Errorf("failureMessage(%q) = %q, want %q", output, got, want)
		}
	}
	long := failureMessage("FATAL[0000] " + strings.Repeat("ж", 1000))
	if n := utf8.RuneCountInString(long); n != messageLimit || !strings.HasSuffix(long, "…") {
		t.Errorf("a long message: %d runes, want %d ending in …", n, messageLimit)
	}
}
