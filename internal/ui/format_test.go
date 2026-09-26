package ui

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"tray-sing-box/internal/domain"
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

func TestImportMessage(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result domain.ImportResult
		want   string
	}{
		{"one", domain.ImportResult{Tags: []string{"DE-1"}}, "Сервер «DE-1» импортирован"},
		{"one restarted", domain.ImportResult{Tags: []string{"DE-1"}, Restarted: true}, "Сервер «DE-1» импортирован, VPN перезапущен"},
		{"many", domain.ImportResult{Tags: []string{"DE-1", "NL-1"}}, "Импортировано серверов: 2\n\nDE-1\nNL-1"},
		{"some", domain.ImportResult{
			Tags:      []string{"ok", "direct (2)"},
			Renamed:   []domain.TagRename{{From: "direct", To: "direct (2)"}},
			Skipped:   []domain.SkippedNode{{Name: "ss-obfs", Reason: "плагин obfs-local не поддерживается"}},
			Restarted: true,
		}, "Импортировано серверов: 2 из 3, VPN перезапущен\n\nok\ndirect (2)" +
			"\n\nИмя уже занято — сохранены под другим:\n«direct» → «direct (2)»" +
			"\n\nПропущены:\n«ss-obfs» — плагин obfs-local не поддерживается"},
		{"one of two", domain.ImportResult{
			Tags:    []string{"ok"},
			Skipped: []domain.SkippedNode{{Name: "ссылка 2", Reason: "ссылка повреждена"}},
		}, "Импортировано серверов: 1 из 2\n\nok\n\nПропущены:\n«ссылка 2» — ссылка повреждена"},
	} {
		if got := ImportMessage(&tc.result); got != tc.want {
			t.Errorf("%s:\n got %q\nwant %q", tc.name, got, tc.want)
		}
	}
}

func TestSubscriptionMessage(t *testing.T) {
	const url = "https://p.example/sub?token=secret"
	result := &domain.SubscriptionResult{
		Updates: []domain.SubscriptionUpdate{
			{
				URL: url, Tags: []string{"a", "b", "direct (2)"}, Added: []string{"b"}, Removed: []string{"c"},
				Renamed:  []domain.TagRename{{From: "a|12GB", To: "a"}},
				Suffixed: []domain.TagRename{{From: "direct", To: "direct (2)"}},
				Skipped: []domain.SkippedNode{
					{Name: "bad", Reason: "sing-box не принимает: unsupported flow: x"},
					{Name: "tuic-1", Reason: "тип ссылки не поддерживается"},
				},
			},
			{URL: "https://q.example/sub", Err: errors.New("не удалось скачать подписку: HTTP 502")},
		},
		Restarted: true,
	}
	p, q := domain.RedactURL(url), domain.RedactURL("https://q.example/sub")
	want := p + " — серверов: 3, новых: 1, удалено: 1, переименовано: 1" +
		"\n  имя уже занято, сохранены под другим: «direct» → «direct (2)»" +
		"\n  пропущены:\n  «bad» — sing-box не принимает: unsupported flow: x\n  «tuic-1» — тип ссылки не поддерживается" +
		"\n" + q + " — ошибка: не удалось скачать подписку: HTTP 502" +
		"\n\nVPN перезапущен"
	got := SubscriptionMessage(result)
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
	if strings.Contains(got, "secret") {
		t.Fatal("the subscription URL leaked")
	}
}

// The unattended refresh reports only what is new, and nothing when all is
// as before
func TestAutoRefreshReport(t *testing.T) {
	result := &domain.SubscriptionResult{Updates: []domain.SubscriptionUpdate{
		{URL: "https://p.example/sub", Err: errors.New("не удалось скачать подписку: timeout"), NewProblem: true},
		{URL: "https://q.example/sub", Tags: []string{"a"}, Skipped: []domain.SkippedNode{{Name: "x", Reason: "r"}}},
	}}
	got := AutoRefreshReport(result)
	if !strings.Contains(got, domain.RedactURL("https://p.example/sub")+" — ошибка: не удалось скачать подписку: timeout") ||
		strings.Contains(got, domain.RedactURL("https://q.example/sub")) {
		t.Fatalf("report = %q", got)
	}
	result.Updates[0].NewProblem = false
	if got := AutoRefreshReport(result); got != "" {
		t.Fatalf("report without new problems = %q", got)
	}
}
