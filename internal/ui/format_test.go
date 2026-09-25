package ui

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestShowVersion(t *testing.T) {
	for in, want := range map[string]string{
		"v1.0.0":        "1.0.0",
		"1.0.1":         "1.0.1",
		"b056ce3-dirty": "b056ce3-dirty",
		"":              "",
	} {
		if got := ShowVersion(in); got != want {
			t.Errorf("ShowVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

// The shape of the notes release.yml / the maintainer writes
const sampleNotes = "### Что нового\r\n\r\n" +
	"- **Установка на чистую машину.** Раздел «Первоначальная настройка» и `config.json`.\r\n" +
	"- **Лог**: штатное выключение не `ERROR`.\r\n\r\n" +
	"### Проверка сборки\r\n\r\n" +
	"Сборка воспроизводима.\r\n"

func TestPlainNotes(t *testing.T) {
	got := PlainNotes(sampleNotes)
	want := "• Установка на чистую машину. Раздел «Первоначальная настройка» и config.json." + "\n" +
		"• Лог: штатное выключение не ERROR."
	if got != want {
		t.Fatalf("PlainNotes:\n%s\nwant:\n%s", got, want)
	}
}

func TestPlainNotesIsBounded(t *testing.T) {
	long := "### Что нового\n\n" + strings.Repeat("- пункт с достаточно длинным текстом\n", 200)
	got := PlainNotes(long)
	if n := utf8.RuneCountInString(got); n > notesLimit+1 {
		t.Fatalf("%d characters, limit %d", n, notesLimit)
	}
	if !strings.HasSuffix(got, "…") {
		t.Fatalf("a cut text does not say so: %q", got[len(got)-20:])
	}
	// Plain text or nothing at all stays as it is
	if got := PlainNotes("Исправления."); got != "Исправления." {
		t.Fatalf("plain notes changed: %q", got)
	}
	if got := PlainNotes(""); got != "" {
		t.Fatalf("empty notes: %q", got)
	}
}
