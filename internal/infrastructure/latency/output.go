package latency

import (
	"bytes"
	"regexp"
	"strings"
	"sync"
	"unicode/utf8"
)

// What the test instance printed, and the message taken from it. The text
// reaches the log, the page and popups — always after the plan's Redact.

// tailBuffer keeps the last bytes written to it: the test instance's stdout
// and stderr, of which only the end (the FATAL line) is of interest
type tailBuffer struct {
	mu  sync.Mutex
	buf []byte
	max int
	cut bool // something was dropped from the front
}

func newTailBuffer(max int) *tailBuffer { return &tailBuffer{max: max} }

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if over := len(t.buf) - t.max; over > 0 {
		t.buf = append(t.buf[:0], t.buf[over:]...)
		t.cut = true
	}
	return len(p), nil
}

// String is the kept output in whole lines, without terminal colour codes
// (sing-box prints them even into a pipe)
func (t *tailBuffer) String() string {
	t.mu.Lock()
	data := bytes.Clone(t.buf)
	cut := t.cut
	t.mu.Unlock()
	if cut {
		// The cut lands mid-line (possibly mid-rune or mid-escape)
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			data = data[i+1:]
		}
	}
	return ansiEscapes.ReplaceAllString(string(data), "")
}

var (
	ansiEscapes = regexp.MustCompile(`\x1b\[[0-9;]*m`)
	// logPrefix is the level and time of a sing-box log line
	logPrefix = regexp.MustCompile(`^(FATAL|ERROR|WARN)\[\d+\] `)
	// configFileAt names the temporary config file (the fallback for builds
	// without stdin): a path in the data dir that tells the user nothing
	configFileAt = regexp.MustCompile(`(read|decode) config at .*?\.json: `)
)

// messageLimit caps the message in runes: it ends up in a popup
const messageLimit = 300

// failureMessage reduces the output of a test instance that exited to its
// reason on one line: the FATAL line (sing-box's run ends with it), else a
// panic's first line, else the last ERROR line, else the last line printed
func failureMessage(output string) string {
	var fatal, panicked, lastError, last string
	for _, l := range strings.Split(output, "\n") {
		l = strings.TrimSpace(l)
		switch {
		case l == "":
			continue
		case strings.HasPrefix(l, "FATAL") && fatal == "":
			fatal = l
		case strings.HasPrefix(l, "panic:") && panicked == "":
			panicked = l
		case strings.HasPrefix(l, "ERROR"):
			lastError = l
		}
		last = l
	}
	line := last
	for _, l := range []string{fatal, panicked, lastError} {
		if l != "" {
			line = l
			break
		}
	}
	line = configFileAt.ReplaceAllString(logPrefix.ReplaceAllString(line, ""), "")
	return clip(line, messageLimit)
}

// clip cuts s to at most n runes, marking the cut
func clip(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	runes := []rune(s)
	return string(runes[:n-1]) + "…"
}
