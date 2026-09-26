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

// skippedLimit bounds the lists of skipped nodes in a popup: a message box
// grows with its text and has no scroll bar (the settings page lists all)
const skippedLimit = 10

// ImportMessage is the popup text for a finished import: the servers
// imported, the ones saved under another name (theirs was taken), and the
// links left out with the reason
func ImportMessage(result *domain.ImportResult) string {
	total := len(result.Tags) + len(result.Skipped)
	var message string
	switch {
	case len(result.Tags) == 1 && total == 1:
		message = fmt.Sprintf(ImportOneAdded, result.Tags[0])
	case total == len(result.Tags):
		message = fmt.Sprintf(ImportManyAdded, len(result.Tags))
	default:
		message = fmt.Sprintf(ImportSomeAdded, len(result.Tags), total)
	}
	if result.Restarted {
		message += ImportRestarted
	}
	if total > 1 {
		message += "\n\n" + strings.Join(result.Tags, "\n")
	}
	if len(result.Renamed) > 0 {
		message += "\n\n" + ImportRenamedHeader + "\n" + renameList(result.Renamed, "\n")
	}
	if len(result.Skipped) > 0 {
		message += "\n\n" + ImportSkippedHeader + "\n" + domain.DescribeSkipped(result.Skipped, skippedLimit)
	}
	return message
}

// renameList shows renamed outbounds as "«old» → «new»"
func renameList(renames []domain.TagRename, sep string) string {
	items := make([]string, len(renames))
	for i, r := range renames {
		items[i] = fmt.Sprintf("«%s» → «%s»", r.From, r.To)
	}
	return strings.Join(items, sep)
}

// SubscriptionMessage is the popup text for finished subscription work.
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
	return message
}

// AutoRefreshReport is the popup text for the problems of an unattended
// refresh the user has not been told about yet, "" when there are none
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
	return fmt.Sprintf(SubsAutoMsg, strings.Join(blocks, "\n"))
}

// subscriptionLine describes the outcome for one subscription: the counts,
// the nodes saved under another name, the nodes left out and why
func subscriptionLine(u domain.SubscriptionUpdate) string {
	if u.Err != nil {
		// The error of a subscription with no usable node lists them itself,
		// a line each: indented under the subscription
		return fmt.Sprintf(SubsLineError, domain.RedactURL(u.URL), strings.ReplaceAll(u.Err.Error(), "\n", "\n  "))
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
	if len(u.Suffixed) > 0 {
		line += fmt.Sprintf(SubsLineSuffixed, renameList(u.Suffixed, ", "))
	}
	if len(u.Skipped) > 0 {
		skipped := domain.DescribeSkipped(u.Skipped, skippedLimit)
		line += fmt.Sprintf(SubsLineSkipped, "  "+strings.ReplaceAll(skipped, "\n", "\n  "))
	}
	return line
}
