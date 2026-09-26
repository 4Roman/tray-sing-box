package domain

import (
	"fmt"
	"log"
	"strings"
)

// SkippedNode is a link or subscription node that was left out, and why.
// Never the link itself: it carries the server's credentials, and the text
// reaches the log, the tray popups and the settings page.
type SkippedNode struct {
	Name   string `json:"name"`   // the node's name; "ссылка N" when it has none
	Reason string `json:"reason"` // for the user, in Russian
}

// TagRename is an outbound saved under another tag than the one it came
// with (its name belongs to an outbound it may not replace) or than the one
// it had (the subscription renamed the node)
type TagRename struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// OutboundParser converts text with share links (or a subscription body)
// into sing-box outbounds. Each outbound carries its tag in "tag". Links that
// cannot be converted are left out and listed in skipped; err is returned
// only when nothing could be converted.
type OutboundParser interface {
	Parse(text string) (outbounds []map[string]any, skipped []SkippedNode, err error)
}

// ConfigEditor persists outbounds into the sing-box configuration
type ConfigEditor interface {
	// AddOutbounds saves the outbounds in one pass. An existing outbound with
	// the same tag is replaced — re-importing a server updates it — unless it
	// is one an import may not replace: direct, block, dns, a selector/urltest
	// group, the DPI-bypass outbound, or a subscription's node (reserved);
	// then the incoming outbound is saved as "<tag> (N)" and listed in
	// Renamed. Outbounds the config check refuses are left out and listed in
	// Skipped; when it refuses every one, nothing is saved (Tags is empty).
	AddOutbounds(outbounds []map[string]any, reserved []string) (*AddResult, error)
}

// AddResult describes how ConfigEditor.AddOutbounds changed the config
type AddResult struct {
	Tags    []string      // tags the saved outbounds carry, in import order
	Renamed []TagRename   // saved under another tag: the name was taken
	Skipped []SkippedNode // refused by the config check, not saved
	Changed bool          // whether the config file was rewritten
}

// ImportResult describes a completed outbound import
type ImportResult struct {
	Tags      []string      // tags of the imported outbounds
	Renamed   []TagRename   // imported under another tag: the name was taken
	Skipped   []SkippedNode // links left out, with the reason
	Restarted bool          // whether the VPN was restarted to apply the config
}

// ImportService imports proxy outbounds from share links into the config
// and applies them by restarting the VPN when it is running.
type ImportService struct {
	parser OutboundParser
	editor ConfigEditor
	subs   SubscriptionStore // nil: no subscriptions to keep apart
	vpn    *VPNService
}

// NewImportService creates a new import service. subs names the nodes the
// subscriptions own: an import never replaces them (a refresh of their
// subscription would delete or overwrite the imported server again).
func NewImportService(parser OutboundParser, editor ConfigEditor, subs SubscriptionStore, vpn *VPNService) *ImportService {
	return &ImportService{
		parser: parser,
		editor: editor,
		subs:   subs,
		vpn:    vpn,
	}
}

// ImportFromText parses all share links found in text (or a base64
// subscription blob), stores the resulting outbounds in the config and
// restarts the VPN if it is running.
func (s *ImportService) ImportFromText(text string) (*ImportResult, error) {
	outbounds, skipped, err := s.parser.Parse(text)
	for _, sk := range skipped {
		log.Printf("Import: skipped %q: %s", sk.Name, sk.Reason)
	}
	if err != nil {
		return nil, noneUsable("ни один сервер не импортирован", skipped, err)
	}

	reserved := s.subscriptionTags()
	log.Printf("Importing %d outbound(s)", len(outbounds))

	added, err := s.editor.AddOutbounds(outbounds, reserved)
	if err != nil {
		// No config yet (a fresh install): an import cannot start one — the
		// servers need the rest of a config (inbounds, route) around them
		return nil, withSetupHint(fmt.Errorf("не удалось сохранить серверы в конфиг: %w", err))
	}
	for _, sk := range added.Skipped {
		log.Printf("Import: %q refused by the config check: %s", sk.Name, sk.Reason)
	}
	skipped = append(skipped, added.Skipped...)
	if len(added.Tags) == 0 {
		return nil, noneUsable("ни один сервер не импортирован", skipped, nil)
	}
	for _, r := range added.Renamed {
		log.Printf("Import: %q saved as %q (the name is taken)", r.From, r.To)
	}

	result := &ImportResult{Tags: added.Tags, Renamed: added.Renamed, Skipped: skipped}
	if !added.Changed {
		log.Printf("Outbounds %v are already in the config as imported", added.Tags)
		return result, nil
	}

	restarted, err := s.vpn.RestartIfRunning()
	if err != nil {
		return result, fmt.Errorf("серверы импортированы, но VPN %w", err)
	}
	result.Restarted = restarted

	log.Printf("Outbounds %v imported successfully (restarted: %v)", added.Tags, result.Restarted)
	return result, nil
}

// subscriptionTags lists the outbounds the subscriptions own. An unreadable
// list does not stop the import: every subscription operation fails on it
// anyway, and the worst an import can do without it is replace a
// subscription's node, which the next refresh of that subscription puts
// back. Refusing would block every import until the file is repaired by
// hand (nothing in the app rewrites a list it cannot read).
func (s *ImportService) subscriptionTags() []string {
	if s.subs == nil {
		return nil
	}
	subs, err := s.subs.Load()
	if err != nil {
		log.Printf("Import: the subscription list is unreadable, its nodes are not kept apart: %v", err)
		return nil
	}
	var tags []string
	for _, sub := range subs {
		tags = append(tags, sub.Tags...)
	}
	return tags
}

// skippedLimit bounds the node list in an error: it lands in a message box,
// which grows with its text and has no scroll bar
const skippedLimit = 10

// DescribeSkipped lists skipped nodes one per line, "«name» — reason", at
// most limit of them (0: all) and then how many more there are
func DescribeSkipped(skipped []SkippedNode, limit int) string {
	lines := make([]string, 0, len(skipped))
	for i, sk := range skipped {
		if limit > 0 && i == limit {
			lines = append(lines, fmt.Sprintf("…и ещё %d", len(skipped)-limit))
			break
		}
		lines = append(lines, fmt.Sprintf("«%s» — %s", sk.Name, sk.Reason))
	}
	return strings.Join(lines, "\n")
}

// noneUsableError: not one node of an import or a subscription could be
// used; the message names every node with its reason
type noneUsableError struct {
	what    string
	skipped []SkippedNode
	cause   error
}

func (e *noneUsableError) Error() string {
	return e.what + ":\n" + DescribeSkipped(e.skipped, skippedLimit)
}

func (e *noneUsableError) Unwrap() error { return e.cause }

// noneUsable is the error when nothing of an import or a subscription body
// could be used: the skipped nodes with their reasons, or — when there were
// none to name (no link found at all) — the cause
func noneUsable(what string, skipped []SkippedNode, cause error) error {
	if len(skipped) == 0 {
		if cause == nil {
			return fmt.Errorf("%s", what)
		}
		return fmt.Errorf("%s: %w", what, cause)
	}
	return &noneUsableError{what: what, skipped: skipped, cause: cause}
}
