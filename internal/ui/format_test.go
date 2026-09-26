package ui

import (
	"errors"
	"fmt"
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
		}, "Импортировано серверов: 2 из 3, VPN перезапущен" +
			"\n\nПропущены:\n«ss-obfs» — плагин obfs-local не поддерживается" +
			"\n\nok\ndirect (2)" +
			"\n\nИмя уже занято — сохранены под другим:\n«direct» → «direct (2)»"},
		{"one of two", domain.ImportResult{
			Tags:    []string{"ok"},
			Skipped: []domain.SkippedNode{{Name: "ссылка 2", Reason: "ссылка повреждена"}},
		}, "Импортировано серверов: 1 из 2\n\nПропущены:\n«ссылка 2» — ссылка повреждена\n\nok"},
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
		"\n  пропущены:\n  «bad» — sing-box не принимает: unsupported flow: x\n  «tuic-1» — тип ссылки не поддерживается" +
		"\n  имя уже занято, сохранены под другим: «direct» → «direct (2)»" +
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

// Only the VPN restart after the refresh failed: the popups show the result
// and the error. The unattended one does so only for new problems — a
// restart failure alone is reported by the monitor.
func TestSubscriptionPopupsWithRestartError(t *testing.T) {
	restartErr := errors.New("подписки обновлены, но VPN restart failed on start: TUN setup failed")
	result := &domain.SubscriptionResult{
		Updates: []domain.SubscriptionUpdate{{
			URL: "https://p.example/sub", Tags: []string{"a"}, NewProblem: true,
			Skipped: []domain.SkippedNode{{Name: "bad", Reason: "тип «tor» не поддерживается"}},
		}},
		RestartErr: restartErr,
	}
	line := domain.RedactURL("https://p.example/sub") + " — серверов: 1\n  пропущены:\n  «bad» — тип «tor» не поддерживается"
	if got, want := SubscriptionMessage(result), line+"\n\n"+restartErr.Error(); got != want {
		t.Fatalf("message:\n%q\nwant\n%q", got, want)
	}
	if got := AutoRefreshReport(result); !strings.Contains(got, line+"\n\n"+restartErr.Error()+"\n\n") {
		t.Fatalf("report = %q", got)
	}
	result.Updates[0].NewProblem = false
	if got := AutoRefreshReport(result); got != "" {
		t.Fatalf("report without new problems = %q", got)
	}
}

// A message box has no scroll bar: every list is bounded, and what went
// wrong comes before the long lists, where it stays visible
func TestPopupListsAreBounded(t *testing.T) {
	var result domain.ImportResult
	var suffixed []domain.TagRename
	for i := 1; i <= 60; i++ {
		tag := fmt.Sprintf("node-%d", i)
		result.Tags = append(result.Tags, tag+" (2)")
		result.Renamed = append(result.Renamed, domain.TagRename{From: tag, To: tag + " (2)"})
		suffixed = append(suffixed, domain.TagRename{From: tag, To: tag + " (2)"})
	}
	result.Skipped = []domain.SkippedNode{{Name: "bad", Reason: "тип «tor» не поддерживается"}}

	lines := strings.Split(ImportMessage(&result), "\n")
	if len(lines) > 3*listLimit+12 {
		t.Fatalf("%d lines:\n%s", len(lines), strings.Join(lines, "\n"))
	}
	if lines[2] != ImportSkippedHeader || lines[3] != "«bad» — тип «tor» не поддерживается" {
		t.Fatalf("the nodes left out are not first:\n%s", strings.Join(lines, "\n"))
	}
	if strings.Count(strings.Join(lines, "\n"), "…и ещё 50") != 2 {
		t.Fatalf("the lists do not say how many more there are:\n%s", strings.Join(lines, "\n"))
	}

	message := SubscriptionMessage(&domain.SubscriptionResult{Updates: []domain.SubscriptionUpdate{
		{URL: "https://p.example/sub", Tags: result.Tags, Suffixed: suffixed},
	}})
	if n := strings.Count(message, "→"); n != listLimit || !strings.HasSuffix(message, ", …и ещё 50") {
		t.Fatalf("%d renames listed: %s", n, message)
	}
}

// Tags and names come from links and providers: written on one line each,
// they cannot add lines to a popup that look like the app's own text
func TestPopupNamesOnOneLine(t *testing.T) {
	const fake = "Внимание! Подписка истекла. Продлите на http://evil.example"
	evil := "x»\n\n" + fake + "\n\n«y"
	messages := []string{
		ImportMessage(&domain.ImportResult{Tags: []string{evil}}),
		ImportMessage(&domain.ImportResult{
			Tags:    []string{evil, "ok"},
			Renamed: []domain.TagRename{{From: evil, To: evil + " (2)"}},
			Skipped: []domain.SkippedNode{{Name: evil, Reason: "тип «tor» не поддерживается"}},
		}),
		AutoRefreshReport(&domain.SubscriptionResult{Updates: []domain.SubscriptionUpdate{{
			URL: "https://p.example/sub", Tags: []string{"ok"}, NewProblem: true,
			Suffixed: []domain.TagRename{{From: evil, To: evil + " (2)"}},
			Skipped:  []domain.SkippedNode{{Name: evil, Reason: "sing-box не принимает: " + evil}},
		}}}),
	}
	for _, message := range messages {
		for _, line := range strings.Split(message, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "Внимание") || strings.HasPrefix(strings.TrimSpace(line), "«y") {
				t.Fatalf("a name made a line of its own:\n%s", message)
			}
		}
		if !strings.Contains(message, fake) {
			t.Fatalf("the name is not shown at all:\n%s", message)
		}
	}
	long := strings.Repeat("Я", 5000)
	if n := utf8.RuneCountInString(ImportMessage(&domain.ImportResult{Tags: []string{long}})); n > 200 {
		t.Fatalf("a %d-character message for one long name", n)
	}
}
