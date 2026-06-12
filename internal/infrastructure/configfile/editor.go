// Package configfile edits the sing-box config.json: inserting imported
// outbounds and editing whole sections while preserving the rest of the
// user's configuration.
package configfile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"sync"

	"tray-sing-box/internal/domain"
)

// Validator checks a candidate config (full JSON bytes) before it is saved.
// Used to plug in `sing-box check` so broken configs never reach disk.
type Validator func(configJSON []byte) error

// Editor modifies a sing-box configuration file in place
type Editor struct {
	path      string
	validator Validator
	mu        sync.Mutex
}

// New creates an editor for the given config.json path
func New(path string) *Editor {
	return &Editor{path: path}
}

// SetValidator installs a pre-save config validator
func (e *Editor) SetValidator(v Validator) {
	e.validator = v
}

// groupTypes are outbound types that hold a list of other outbound tags
var groupTypes = map[string]bool{"selector": true, "urltest": true}

// systemTypes are outbound types that never carry user traffic to a proxy
// server; they are excluded when deciding which outbound is "active".
var systemTypes = map[string]bool{
	"direct": true, "block": true, "dns": true,
	"selector": true, "urltest": true,
}

// editableSections are the config sections exposed for raw JSON editing.
// The value records whether the section is a JSON array (true) or object.
var editableSections = map[string]bool{
	"outbounds": true,
	"route":     false,
}

// load reads and decodes the config, preserving number representation
func (e *Editor) load() (map[string]any, []byte, error) {
	raw, err := os.ReadFile(e.path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read config: %w", err)
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var cfg map[string]any
	if err := decoder.Decode(&cfg); err != nil {
		return nil, nil, fmt.Errorf("failed to parse config: %w", err)
	}
	return cfg, raw, nil
}

// save validates the updated config, backs up the original and writes
func (e *Editor) save(cfg map[string]any, original []byte) error {
	updated, err := marshalIndent(cfg)
	if err != nil {
		return fmt.Errorf("failed to serialize config: %w", err)
	}

	if e.validator != nil {
		if err := e.validator(updated); err != nil {
			return fmt.Errorf("config validation failed: %w", err)
		}
	}

	if err := os.WriteFile(e.path+".bak", original, 0644); err != nil {
		return fmt.Errorf("failed to write config backup: %w", err)
	}
	if err := os.WriteFile(e.path, updated, 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}
	return nil
}

// AddOutbound inserts a single outbound into the config; see AddOutbounds.
func (e *Editor) AddOutbound(outbound map[string]any) error {
	return e.AddOutbounds([]map[string]any{outbound})
}

// AddOutbounds inserts the outbounds into the config in one pass. An existing
// outbound with the same tag is replaced; otherwise the outbound is appended.
// Each tag is also registered in every selector/urltest group so it becomes
// selectable. The previous config is kept next to the original as a .bak file.
func (e *Editor) AddOutbounds(newOutbounds []map[string]any) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	cfg, raw, err := e.load()
	if err != nil {
		return err
	}
	if err := upsertOutbounds(cfg, newOutbounds); err != nil {
		return err
	}
	return e.save(cfg, raw)
}

// upsertOutbounds applies the AddOutbounds merge to a loaded config in place:
// replace by tag or append, then register each tag in selector/urltest groups.
func upsertOutbounds(cfg map[string]any, newOutbounds []map[string]any) error {
	outbounds, _ := cfg["outbounds"].([]any)

	for _, outbound := range newOutbounds {
		tag, _ := outbound["tag"].(string)
		if tag == "" {
			return fmt.Errorf("outbound has no tag")
		}

		replaced := false
		for i, item := range outbounds {
			existing, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if existing["tag"] == tag {
				if groupTypes[fmt.Sprint(existing["type"])] {
					return fmt.Errorf("tag %q is already used by a %v group", tag, existing["type"])
				}
				outbounds[i] = any(outbound)
				replaced = true
				break
			}
		}
		if !replaced {
			outbounds = append(outbounds, any(outbound))
		}

		// Make the imported outbound selectable in selector/urltest groups
		for _, item := range outbounds {
			group, ok := item.(map[string]any)
			if !ok || !groupTypes[fmt.Sprint(group["type"])] {
				continue
			}
			members, _ := group["outbounds"].([]any)
			present := false
			for _, m := range members {
				if m == any(tag) {
					present = true
					break
				}
			}
			if !present {
				group["outbounds"] = append(members, any(tag))
			}
		}
	}

	cfg["outbounds"] = outbounds
	return nil
}

// SyncOutbounds reconciles the set of outbounds owned by one subscription:
// outbounds from ownedTags that are absent from newOutbounds are deleted
// (including their selector/urltest registrations, detour references and
// route references — the latter are repointed to a surviving outbound), the
// rest of newOutbounds are added or replaced as in AddOutbounds. The file is
// only rewritten when the config actually changed.
func (e *Editor) SyncOutbounds(ownedTags []string, newOutbounds []map[string]any) (*domain.SyncResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	cfg, raw, err := e.load()
	if err != nil {
		return nil, err
	}
	before, err := marshalIndent(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize config: %w", err)
	}

	newTags := map[string]bool{}
	for _, o := range newOutbounds {
		tag, _ := o["tag"].(string)
		if tag == "" {
			return nil, fmt.Errorf("outbound has no tag")
		}
		newTags[tag] = true
	}
	owned := map[string]bool{}
	for _, t := range ownedTags {
		owned[t] = true
	}

	// Tags that existed before the sync, to report what was actually added
	outbounds, _ := cfg["outbounds"].([]any)
	presentBefore := map[string]bool{}
	for _, item := range outbounds {
		if o, ok := item.(map[string]any); ok {
			if tag, _ := o["tag"].(string); tag != "" {
				presentBefore[tag] = true
			}
		}
	}

	// Drop owned outbounds that disappeared from the subscription
	removedSet := map[string]bool{}
	kept := make([]any, 0, len(outbounds))
	for _, item := range outbounds {
		if o, ok := item.(map[string]any); ok {
			tag, _ := o["tag"].(string)
			if owned[tag] && !newTags[tag] {
				removedSet[tag] = true
				continue
			}
		}
		kept = append(kept, item)
	}
	cfg["outbounds"] = kept

	if err := upsertOutbounds(cfg, newOutbounds); err != nil {
		return nil, err
	}

	if len(removedSet) > 0 {
		pruneOutboundReferences(cfg, removedSet, newOutbounds)
	}

	result := &domain.SyncResult{}
	for _, o := range newOutbounds {
		if tag, _ := o["tag"].(string); !presentBefore[tag] {
			result.Added = append(result.Added, tag)
		}
	}
	for tag := range removedSet {
		result.Removed = append(result.Removed, tag)
	}
	sort.Strings(result.Removed)

	after, err := marshalIndent(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize config: %w", err)
	}
	if bytes.Equal(before, after) {
		return result, nil
	}
	result.Changed = true
	return result, e.save(cfg, raw)
}

// pruneOutboundReferences removes every reference to the removed tags:
// selector/urltest membership, detour fields, and route rules/final (those
// are repointed to the first new outbound, else any surviving proxy, else a
// direct outbound; a rule with no usable replacement is dropped).
func pruneOutboundReferences(cfg map[string]any, removed map[string]bool, newOutbounds []map[string]any) {
	outbounds, _ := cfg["outbounds"].([]any)

	for _, item := range outbounds {
		o, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if groupTypes[fmt.Sprint(o["type"])] {
			members, _ := o["outbounds"].([]any)
			filtered := make([]any, 0, len(members))
			for _, m := range members {
				if tag, _ := m.(string); !removed[tag] {
					filtered = append(filtered, m)
				}
			}
			o["outbounds"] = filtered
		}
		if detour, _ := o["detour"].(string); removed[detour] {
			delete(o, "detour")
		}
	}

	// Pick the replacement for route references that pointed at removed tags
	replacement := ""
	if len(newOutbounds) > 0 {
		replacement, _ = newOutbounds[0]["tag"].(string)
	}
	if replacement == "" {
		proxies := proxyTags(cfg)
		for _, item := range outbounds {
			if o, ok := item.(map[string]any); ok {
				if tag, _ := o["tag"].(string); proxies[tag] {
					replacement = tag
					break
				}
			}
		}
	}
	if replacement == "" {
		for _, item := range outbounds {
			if o, ok := item.(map[string]any); ok && o["type"] == "direct" {
				replacement, _ = o["tag"].(string)
				break
			}
		}
	}

	route, _ := cfg["route"].(map[string]any)
	if route == nil {
		return
	}
	rules, _ := route["rules"].([]any)
	keptRules := make([]any, 0, len(rules))
	for _, item := range rules {
		rule, ok := item.(map[string]any)
		if ok {
			if out, _ := rule["outbound"].(string); removed[out] {
				if replacement == "" {
					continue // no outbound left to point at — drop the rule
				}
				rule["outbound"] = replacement
			}
		}
		keptRules = append(keptRules, item)
	}
	if rules != nil {
		route["rules"] = keptRules
	}
	if final, _ := route["final"].(string); removed[final] {
		if replacement == "" {
			delete(route, "final")
		} else {
			route["final"] = replacement
		}
	}
}

// ReadSection returns a config section as pretty-printed JSON text
func (e *Editor) ReadSection(name string) (string, error) {
	isArray, ok := editableSections[name]
	if !ok {
		return "", fmt.Errorf("section %q is not editable", name)
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	cfg, _, err := e.load()
	if err != nil {
		return "", err
	}

	section, exists := cfg[name]
	if !exists {
		if isArray {
			return "[]", nil
		}
		return "{}", nil
	}

	text, err := marshalIndent(section)
	if err != nil {
		return "", fmt.Errorf("failed to serialize section %q: %w", name, err)
	}
	return string(bytes.TrimSpace(text)), nil
}

// WriteSection replaces a config section with user-provided JSON text
func (e *Editor) WriteSection(name string, raw []byte) error {
	isArray, ok := editableSections[name]
	if !ok {
		return fmt.Errorf("section %q is not editable", name)
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	// Reject trailing garbage after the JSON document
	if decoder.More() {
		return fmt.Errorf("invalid JSON: unexpected data after the document")
	}

	switch value.(type) {
	case []any:
		if !isArray {
			return fmt.Errorf("section %q must be a JSON object, got an array", name)
		}
	case map[string]any:
		if isArray {
			return fmt.Errorf("section %q must be a JSON array, got an object", name)
		}
	default:
		return fmt.Errorf("section %q must be a JSON %s", name, sectionKind(isArray))
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	cfg, original, err := e.load()
	if err != nil {
		return err
	}
	cfg[name] = value
	return e.save(cfg, original)
}

func sectionKind(isArray bool) string {
	if isArray {
		return "array"
	}
	return "object"
}

// ListOutbounds returns tag and type of every configured outbound
func (e *Editor) ListOutbounds() ([]domain.OutboundInfo, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	cfg, _, err := e.load()
	if err != nil {
		return nil, err
	}

	outbounds, _ := cfg["outbounds"].([]any)
	list := make([]domain.OutboundInfo, 0, len(outbounds))
	for _, item := range outbounds {
		o, ok := item.(map[string]any)
		if !ok {
			continue
		}
		tag, _ := o["tag"].(string)
		typ, _ := o["type"].(string)
		if tag != "" {
			list = append(list, domain.OutboundInfo{Tag: tag, Type: typ})
		}
	}
	return list, nil
}

// proxyTags returns the set of outbound tags that carry traffic to a proxy
// server (everything except direct/block/dns and selector/urltest groups).
func proxyTags(cfg map[string]any) map[string]bool {
	tags := map[string]bool{}
	outbounds, _ := cfg["outbounds"].([]any)
	for _, item := range outbounds {
		o, ok := item.(map[string]any)
		if !ok {
			continue
		}
		tag, _ := o["tag"].(string)
		typ, _ := o["type"].(string)
		if tag != "" && !systemTypes[typ] {
			tags[tag] = true
		}
	}
	return tags
}

// ActiveOutbound returns the proxy outbound the routing currently uses:
// the first proxy referenced by route rules, otherwise route.final.
func (e *Editor) ActiveOutbound() (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	cfg, _, err := e.load()
	if err != nil {
		return "", err
	}

	proxies := proxyTags(cfg)
	route, _ := cfg["route"].(map[string]any)
	if route == nil {
		return "", nil
	}

	rules, _ := route["rules"].([]any)
	for _, item := range rules {
		rule, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if out, ok := rule["outbound"].(string); ok && proxies[out] {
			return out, nil
		}
	}

	if final, ok := route["final"].(string); ok && proxies[final] {
		return final, nil
	}
	return "", nil
}

// SwitchOutbound routes traffic through the given proxy outbound: every
// route rule (and route.final) that currently points to a proxy outbound is
// repointed to tag. If nothing referenced a proxy before, route.final is set
// so the whole flow goes through the selected outbound.
func (e *Editor) SwitchOutbound(tag string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	cfg, original, err := e.load()
	if err != nil {
		return err
	}

	proxies := proxyTags(cfg)
	if !proxies[tag] {
		return fmt.Errorf("outbound %q not found or is not a proxy", tag)
	}

	route, _ := cfg["route"].(map[string]any)
	if route == nil {
		route = map[string]any{}
		cfg["route"] = route
	}

	changed := false
	rules, _ := route["rules"].([]any)
	for _, item := range rules {
		rule, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if out, ok := rule["outbound"].(string); ok && proxies[out] && out != tag {
			rule["outbound"] = tag
			changed = true
		} else if ok && out == tag {
			changed = true
		}
	}

	if final, ok := route["final"].(string); ok && proxies[final] {
		if final != tag {
			route["final"] = tag
		}
		changed = true
	}

	// Nothing routed through a proxy before: route everything through tag
	if !changed {
		route["final"] = tag
	}

	return e.save(cfg, original)
}

// EnsureBypassOutbound adds or replaces the HTTP-proxy outbound used for DPI
// bypass (zapret). Unlike AddOutbounds it is NOT registered in selector/urltest
// groups: it is plumbing, not a user-selectable server. When an identical
// outbound already exists the file is left untouched (no .bak churn, no save).
func (e *Editor) EnsureBypassOutbound(tag, server string, port int) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	cfg, raw, err := e.load()
	if err != nil {
		return err
	}

	desired := map[string]any{
		"type":        "http",
		"tag":         tag,
		"server":      server,
		"server_port": port,
	}

	outbounds, _ := cfg["outbounds"].([]any)
	for i, item := range outbounds {
		o, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if o["tag"] == tag {
			if sameOutbound(o, desired) {
				return nil // already present and identical
			}
			outbounds[i] = any(desired)
			cfg["outbounds"] = outbounds
			return e.save(cfg, raw)
		}
	}

	cfg["outbounds"] = append(outbounds, any(desired))
	return e.save(cfg, raw)
}

// SetDetour makes the proxy outbound targetTag dial its server through
// detourTag (sing-box "detour" field). targetTag must be an existing,
// non-system outbound and must differ from detourTag.
func (e *Editor) SetDetour(targetTag, detourTag string) error {
	if targetTag == detourTag {
		return fmt.Errorf("cannot route %q through itself", targetTag)
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	cfg, raw, err := e.load()
	if err != nil {
		return err
	}

	outbounds, _ := cfg["outbounds"].([]any)
	if !hasOutbound(outbounds, detourTag) {
		return fmt.Errorf("detour outbound %q not found", detourTag)
	}

	var target map[string]any
	for _, item := range outbounds {
		if o, ok := item.(map[string]any); ok && o["tag"] == targetTag {
			target = o
			break
		}
	}
	if target == nil {
		return fmt.Errorf("outbound %q not found", targetTag)
	}
	if systemTypes[fmt.Sprint(target["type"])] {
		return fmt.Errorf("outbound %q (%v) cannot use a detour", targetTag, target["type"])
	}

	if detour, _ := target["detour"].(string); detour == detourTag {
		return nil // already set
	}
	target["detour"] = detourTag
	return e.save(cfg, raw)
}

// ClearDetour removes "detour": detourTag from every outbound. The file is
// only rewritten when something actually changed.
func (e *Editor) ClearDetour(detourTag string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	cfg, raw, err := e.load()
	if err != nil {
		return err
	}

	outbounds, _ := cfg["outbounds"].([]any)
	changed := false
	for _, item := range outbounds {
		if o, ok := item.(map[string]any); ok && o["detour"] == detourTag {
			delete(o, "detour")
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return e.save(cfg, raw)
}

// DetourTargets returns the tags of outbounds whose "detour" equals detourTag.
func (e *Editor) DetourTargets(detourTag string) ([]string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	cfg, _, err := e.load()
	if err != nil {
		return nil, err
	}

	outbounds, _ := cfg["outbounds"].([]any)
	var tags []string
	for _, item := range outbounds {
		o, ok := item.(map[string]any)
		if !ok || o["detour"] != detourTag {
			continue
		}
		if tag, _ := o["tag"].(string); tag != "" {
			tags = append(tags, tag)
		}
	}
	return tags, nil
}

// RouteReferences reports whether any route rule or route.final points at tag.
func (e *Editor) RouteReferences(tag string) (bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	cfg, _, err := e.load()
	if err != nil {
		return false, err
	}

	route, _ := cfg["route"].(map[string]any)
	if route == nil {
		return false, nil
	}
	rules, _ := route["rules"].([]any)
	for _, item := range rules {
		if rule, ok := item.(map[string]any); ok {
			if out, ok := rule["outbound"].(string); ok && out == tag {
				return true, nil
			}
		}
	}
	if final, ok := route["final"].(string); ok && final == tag {
		return true, nil
	}
	return false, nil
}

// OutboundType returns the "type" of the outbound with the given tag.
func (e *Editor) OutboundType(tag string) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	cfg, _, err := e.load()
	if err != nil {
		return "", err
	}

	outbounds, _ := cfg["outbounds"].([]any)
	for _, item := range outbounds {
		if o, ok := item.(map[string]any); ok && o["tag"] == tag {
			typ, _ := o["type"].(string)
			return typ, nil
		}
	}
	return "", fmt.Errorf("outbound %q not found", tag)
}

// hasOutbound reports whether an outbound with the given tag exists.
func hasOutbound(outbounds []any, tag string) bool {
	for _, item := range outbounds {
		if o, ok := item.(map[string]any); ok && o["tag"] == tag {
			return true
		}
	}
	return false
}

// sameOutbound reports whether two outbound objects serialize identically.
func sameOutbound(a, b map[string]any) bool {
	am, err1 := marshalIndent(a)
	bm, err2 := marshalIndent(b)
	return err1 == nil && err2 == nil && bytes.Equal(am, bm)
}

// marshalIndent serializes without escaping non-ASCII characters (tags are
// often Cyrillic or emoji) and with 2-space indentation.
func marshalIndent(v any) ([]byte, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
