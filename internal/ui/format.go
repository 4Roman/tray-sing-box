package ui

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"tray-sing-box/internal/domain"
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

// listLimit bounds every list in a popup (servers imported, renamed, left
// out): a message box grows with its text and has no scroll bar, and what
// does not fit on the screen is simply not shown (the settings page lists
// all)
const listLimit = 10

// ImportMessage is the popup text for a finished import: the servers
// imported, the links left out with the reason, and the servers saved under
// another name (theirs was taken). What went wrong comes first: the lists
// after it may be long. Names are the link's or the provider's text, written
// on one line each (domain.DisplayName).
func ImportMessage(result *domain.ImportResult) string {
	total := len(result.Tags) + len(result.Skipped)
	var message string
	switch {
	case len(result.Tags) == 1 && total == 1:
		message = fmt.Sprintf(ImportOneAdded, domain.DisplayName(result.Tags[0]))
	case total == len(result.Tags):
		message = fmt.Sprintf(ImportManyAdded, len(result.Tags))
	default:
		message = fmt.Sprintf(ImportSomeAdded, len(result.Tags), total)
	}
	if result.Restarted {
		message += ImportRestarted
	}
	if len(result.Skipped) > 0 {
		message += "\n\n" + ImportSkippedHeader + "\n" + domain.DescribeSkipped(result.Skipped, listLimit)
	}
	if total > 1 {
		message += "\n\n" + nameList(result.Tags, "\n")
	}
	if len(result.Renamed) > 0 {
		message += "\n\n" + ImportRenamedHeader + "\n" + renameList(result.Renamed, "\n")
	}
	return message
}

// nameList shows tags one per line, at most listLimit of them
func nameList(tags []string, sep string) string {
	items := make([]string, len(tags))
	for i, tag := range tags {
		items[i] = domain.DisplayName(tag)
	}
	return bounded(items, sep)
}

// renameList shows renamed outbounds as "«old» → «new»", at most listLimit
// of them
func renameList(renames []domain.TagRename, sep string) string {
	items := make([]string, len(renames))
	for i, r := range renames {
		items[i] = fmt.Sprintf("«%s» → «%s»", domain.DisplayName(r.From), domain.DisplayName(r.To))
	}
	return bounded(items, sep)
}

// bounded joins the first listLimit items and says how many more there are
func bounded(items []string, sep string) string {
	if len(items) > listLimit {
		items = append(items[:listLimit:listLimit], fmt.Sprintf("…и ещё %d", len(items)-listLimit))
	}
	return strings.Join(items, sep)
}

// SubscriptionMessage is the popup text for finished subscription work — and
// for one after which only the VPN restart failed: then the error closes it.
// Subscriptions are named by their redacted URL: the full one carries the
// provider's access token.
func SubscriptionMessage(result *domain.SubscriptionResult) string {
	var lines []string
	for _, u := range result.Updates {
		lines = append(lines, subscriptionLine(u))
	}
	message := strings.Join(lines, "\n")
	if result.Restarted {
		message += SubsRestartedSuffix
	}
	if result.RestartErr != nil {
		message += "\n\n" + result.RestartErr.Error()
	}
	return message
}

// AutoRefreshReport is the popup text for the problems of an unattended
// refresh the user has not been told about yet, "" when there are none. A
// failed VPN restart after the refresh is added to them (it says why the
// new servers are not in use); alone it is the monitor's to report.
func AutoRefreshReport(result *domain.SubscriptionResult) string {
	var blocks []string
	for _, u := range result.Updates {
		if u.NewProblem {
			blocks = append(blocks, subscriptionLine(u))
		}
	}
	if len(blocks) == 0 {
		return ""
	}
	report := strings.Join(blocks, "\n")
	if result.RestartErr != nil {
		report += "\n\n" + result.RestartErr.Error()
	}
	return fmt.Sprintf(SubsAutoMsg, report)
}

// subscriptionLine describes the outcome for one subscription: the counts,
// the nodes left out and why, the nodes saved under another name
func subscriptionLine(u domain.SubscriptionUpdate) string {
	if u.Err != nil {
		// The error of a subscription with no usable node lists them itself,
		// a line each: indented under the subscription. Any error can quote
		// the provider's words at any length (a node's tag in a config
		// refusal, the server's status line), and this line reaches the
		// popup of an unattended refresh: bounded line by line and in lines.
		text := domain.DisplayLines(u.Err.Error())
		return fmt.Sprintf(SubsLineError, domain.RedactURL(u.URL), strings.ReplaceAll(text, "\n", "\n  "))
	}
	line := fmt.Sprintf(SubsLineOK, domain.RedactURL(u.URL), len(u.Tags))
	if len(u.Added) > 0 {
		line += fmt.Sprintf(SubsLineAdded, len(u.Added))
	}
	if len(u.Removed) > 0 {
		line += fmt.Sprintf(SubsLineRemoved, len(u.Removed))
	}
	if len(u.Renamed) > 0 {
		line += fmt.Sprintf(SubsLineRenamed, len(u.Renamed))
	}
	if len(u.Skipped) > 0 {
		skipped := domain.DescribeSkipped(u.Skipped, listLimit)
		line += fmt.Sprintf(SubsLineSkipped, "  "+strings.ReplaceAll(skipped, "\n", "\n  "))
	}
	if len(u.Suffixed) > 0 {
		line += fmt.Sprintf(SubsLineSuffixed, renameList(u.Suffixed, ", "))
	}
	return line
}
