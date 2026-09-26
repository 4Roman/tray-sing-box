package domain

import (
	"fmt"
	"log"
)

// SkippedNode is a link or subscription node that was left out, and why.
// Never the link itself: it carries the server's credentials, and the text
// reaches the log, the tray popups and the settings page.
type SkippedNode struct {
	Name   string // the node's name; "ссылка N" when it has none
	Reason string // for the user, in Russian
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
	AddOutbounds(outbounds []map[string]any) error
}

// ImportResult describes a completed outbound import
type ImportResult struct {
	Tags      []string      // tags of the imported outbounds
	Skipped   []SkippedNode // links left out, with the reason
	Restarted bool          // whether the VPN was restarted to apply the config
}

// ImportService imports proxy outbounds from share links into the config
// and applies them by restarting the VPN when it is running.
type ImportService struct {
	parser OutboundParser
	editor ConfigEditor
	vpn    *VPNService
}

// NewImportService creates a new import service
func NewImportService(parser OutboundParser, editor ConfigEditor, vpn *VPNService) *ImportService {
	return &ImportService{
		parser: parser,
		editor: editor,
		vpn:    vpn,
	}
}

// ImportFromText parses all share links found in text (or a base64
// subscription blob), stores the resulting outbounds in the config and
// restarts the VPN if it is running.
func (s *ImportService) ImportFromText(text string) (*ImportResult, error) {
	outbounds, skipped, err := s.parser.Parse(text)
	if err != nil {
		return nil, fmt.Errorf("failed to parse share link: %w", err)
	}
	for _, sk := range skipped {
		log.Printf("Import: skipped %q: %s", sk.Name, sk.Reason)
	}

	tags := make([]string, len(outbounds))
	for i, o := range outbounds {
		tags[i], _ = o["tag"].(string)
	}
	log.Printf("Importing %d outbound(s): %v", len(outbounds), tags)

	if err := s.editor.AddOutbounds(outbounds); err != nil {
		// No config yet (a fresh install): an import cannot start one — the
		// servers need the rest of a config (inbounds, route) around them
		return nil, withSetupHint(fmt.Errorf("failed to update config: %w", err))
	}

	result := &ImportResult{Tags: tags, Skipped: skipped}

	restarted, err := s.vpn.RestartIfRunning()
	if err != nil {
		return result, fmt.Errorf("outbounds imported, but VPN %w", err)
	}
	result.Restarted = restarted

	log.Printf("Outbounds %v imported successfully (restarted: %v)", tags, result.Restarted)
	return result, nil
}
