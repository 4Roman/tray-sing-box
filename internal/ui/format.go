package ui

import (
	"strings"
	"unicode/utf8"
)

// ShowVersion writes a version the same way everywhere: the build stamp
// carries the tag's "v" ("v1.0.0"), the release lookup drops it ("1.0.1"),
// and a popup must not say "1.0.1 (установлена v1.0.0)". A development
// build ("b056ce3-dirty") stays as it is.
func ShowVersion(v string) string {
	return strings.TrimPrefix(v, "v")
}

// notesLimit bounds the release notes in the update question: a message box
// grows with its text and has no scroll bar
const notesLimit = 1200

// PlainNotes turns the Markdown release notes into text for a message box:
// the first section only (what is new; the rest is on the release page), no
// heading marks, emphasis or code quotes, bullets as "•", at most notesLimit
// characters.
func PlainNotes(md string) string {
	var lines []string
	headings := 0
	for _, line := range strings.Split(strings.ReplaceAll(md, "\r\n", "\n"), "\n") {
		line = strings.TrimRight(line, " \t")
		if strings.HasPrefix(line, "#") {
			headings++
			if headings > 1 {
				break
			}
			// The first heading ("Что нового") says nothing the question does not
			continue
		}
		if strings.HasPrefix(line, "- ") || strings.HasPrefix(line, "* ") {
			line = "• " + line[2:]
		}
		line = strings.NewReplacer("**", "", "`", "").Replace(line)
		if line == "" && (len(lines) == 0 || lines[len(lines)-1] == "") {
			continue
		}
		lines = append(lines, line)
	}
	text := strings.TrimSpace(strings.Join(lines, "\n"))
	if utf8.RuneCountInString(text) > notesLimit {
		text = strings.TrimSpace(string([]rune(text)[:notesLimit])) + "…"
	}
	return text
}
