// Package configfile edits the sing-box config.json: inserting imported
// outbounds and editing whole sections while preserving the rest of the
// user's configuration.
package configfile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"sync"
	"time"

	"tray-sing-box/internal/config"
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
	if errors.Is(err, fs.ErrNotExist) {
		// An installed copy has none until it took over a portable one or the
		// user gave it one (CreateConfig): the UI says how
		return nil, nil, fmt.Errorf("%w at: %s", domain.ErrConfigMissing, e.path)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read config: %w", err)
	}

	cfg, err := decodeConfig(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse config: %w", err)
	}
	return cfg, raw, nil
}

// decodeConfig decodes config JSON, preserving number representation
func decodeConfig(raw []byte) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var cfg map[string]any
	if err := decoder.Decode(&cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// save validates the updated config, backs up the original and writes
func (e *Editor) save(cfg map[string]any, original []byte) error {
	updated, err := e.check(cfg, original)
	if err != nil {
		return err
	}
	return e.write(updated, original)
}

// check runs the pre-save checks on a candidate config and returns it
// serialized: the guard, the selector defaults, the outbound dependencies,
// then the validator
func (e *Editor) check(cfg map[string]any, original []byte) ([]byte, error) {
	updated, err := marshalIndent(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize config: %w", err)
	}

	// Before anything else: nothing written through the app may give the
	// elevated sing-box a program to run or a file to write (guard.go)
	if err := checkNoNewRisky(original, cfg); err != nil {
		return nil, err
	}
	// What sing-box check passes and sing-box then does not start with
	if err := checkSelectorDefaults(original, cfg); err != nil {
		return nil, err
	}
	if err := checkDependencies(original, cfg); err != nil {
		return nil, err
	}
	if e.validator != nil {
		// Without sing-box.exe there is nothing to check with: saved as before
		if err := e.validator(updated); err != nil && !errors.Is(err, domain.ErrSingBoxMissing) {
			return nil, newCheckError(err, cfg)
		}
	}
	return updated, nil
}

// write backs up the original config, archives it and writes the update
func (e *Editor) write(updated, original []byte) error {
	if err := os.WriteFile(e.path+".bak", original, 0644); err != nil {
		return fmt.Errorf("failed to write config backup: %w", err)
	}
	e.archive(original)
	if err := os.WriteFile(e.path, updated, 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}
	return nil
}

// errConfigExists: CreateConfig never replaces a config
var errConfigExists = errors.New("config.json уже есть — правьте его по разделам ниже")

// linkFile hard-links a finished file into place (a variable for tests: file
// systems without hard links)
var linkFile = os.Link

// CreateConfig writes the first config.json of an installation that has
// none. An installed copy starts without one unless it took over a portable
// copy, and its data directory is writable by administrators only, so the
// settings page is the user's way in. What arrives this way is checked like
// any save, against an empty config — the guard refuses everything that lets
// the elevated sing-box run a program, touch a file, change the system or
// open to the network (guard.go) — and then by `sing-box check`, which is
// required here: the page edits only outbounds and route, so a mistake
// elsewhere could not be fixed later without an administrator. The file is
// written aside and hard-linked into place: never partial, and never over a
// config — also when two requests race.
func (e *Editor) CreateConfig(raw []byte) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, err := os.Lstat(e.path); err == nil {
		if _, err := os.Stat(e.path); errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("на месте config.json — ссылка на несуществующий файл (%s): её удаляет администратор", e.path)
		}
		return errConfigExists
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("failed to check config: %w", err)
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var cfg map[string]any
	if err := decoder.Decode(&cfg); err != nil {
		return fmt.Errorf("config.json должен быть JSON-объектом, без комментариев: %w", err)
	}
	if cfg == nil {
		return errors.New("config.json должен быть JSON-объектом")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("после JSON-объекта в config.json есть что-то ещё")
	}

	updated, err := marshalIndent(cfg)
	if err != nil {
		return fmt.Errorf("failed to serialize config: %w", err)
	}
	if err := checkNoNewRisky(nil, cfg); err != nil {
		var refused *riskyError
		if errors.As(err, &refused) {
			return fmt.Errorf("уберите из конфига: %s — остальное приложение примет. sing-box работает с правами администратора, а эти параметры позволили бы запускать программы, читать и писать файлы от его имени, менять систему или открыть его в сеть; если они нужны, config.json кладёт по пути %s администратор", refused.listed(), e.path)
		}
		return err
	}
	if err := checkSelectorDefaults(nil, cfg); err != nil {
		return err
	}
	if err := checkDependencies(nil, cfg); err != nil {
		return err
	}
	if e.validator != nil {
		if err := e.validator(updated); errors.Is(err, domain.ErrSingBoxMissing) {
			return errors.New("сначала скачайте sing-box (кнопка «Скачать sing-box» здесь же): первый конфиг проверяется им перед сохранением — ошибку в разделах, которых нет на этой странице, потом не исправить без администратора")
		} else if err != nil {
			return newCheckError(err, cfg)
		}
	}

	tmp, err := os.CreateTemp(filepath.Dir(e.path), ".config.json.new-*")
	if err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}
	defer os.Remove(tmp.Name())
	_, werr := tmp.Write(updated)
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return fmt.Errorf("failed to write config: %w", werr)
	}
	if err := linkFile(tmp.Name(), e.path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return errConfigExists
		}
		// A file system without hard links (FAT32/exFAT: a portable copy on
		// a stick): an exclusive create still never replaces a config
		return createExclusive(e.path, updated, err)
	}
	return nil
}

// createExclusive writes a new file, failing when one exists; a partial file
// is removed
func createExclusive(path string, data []byte, linkErr error) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if errors.Is(err, fs.ErrExist) {
		return errConfigExists
	}
	if err != nil {
		return fmt.Errorf("failed to write config: %w (hard link: %v)", err, linkErr)
	}
	_, werr := f.Write(data)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		os.Remove(path)
		return fmt.Errorf("failed to write config: %w", werr)
	}
	return nil
}

// historyName matches archived config versions, e.g.
// config-20260612-193045.123456789.json. The fixed-width fractional part
// keeps lexical order chronological even for saves within the same second.
var historyName = regexp.MustCompile(`^config-\d{8}-\d{6}\.\d{9}\.json$`)

func (e *Editor) historyDir() string {
	return filepath.Join(filepath.Dir(e.path), config.ConfigHistoryDir)
}

// archive stores the pre-save config bytes in the history directory and
// prunes old versions. Best-effort: a failed archive must not block the save
// (the .bak copy above still exists).
func (e *Editor) archive(original []byte) {
	dir := e.historyDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Printf("Config history: failed to create %s: %v", dir, err)
		return
	}

	// The Windows clock is coarse enough for two quick saves to get the same
	// timestamp — bump the nanoseconds until the name is free
	now := time.Now()
	var name string
	for i := 0; ; i++ {
		name = "config-" + now.Add(time.Duration(i)).Format("20060102-150405.000000000") + ".json"
		if _, err := os.Stat(filepath.Join(dir, name)); os.IsNotExist(err) {
			break
		}
	}
	if err := os.WriteFile(filepath.Join(dir, name), original, 0644); err != nil {
		log.Printf("Config history: failed to write %s: %v", name, err)
		return
	}

	// Prune the oldest versions beyond the cap (names sort chronologically)
	names, err := e.historyNames()
	if err != nil {
		log.Printf("Config history: failed to list for pruning: %v", err)
		return
	}
	for len(names) > config.ConfigHistoryKeep {
		if err := os.Remove(filepath.Join(dir, names[0])); err != nil {
			log.Printf("Config history: failed to prune %s: %v", names[0], err)
			return
		}
		names = names[1:]
	}
}

// historyNames returns archived version file names sorted oldest first
func (e *Editor) historyNames() ([]string, error) {
	entries, err := os.ReadDir(e.historyDir())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() && historyName.MatchString(entry.Name()) {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

// ListHistory returns the archived config versions, newest first
func (e *Editor) ListHistory() ([]domain.ConfigVersion, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	names, err := e.historyNames()
	if err != nil {
		return nil, fmt.Errorf("failed to list config history: %w", err)
	}
	versions := make([]domain.ConfigVersion, 0, len(names))
	for i := len(names) - 1; i >= 0; i-- {
		v := domain.ConfigVersion{Name: names[i]}
		if info, err := os.Stat(filepath.Join(e.historyDir(), names[i])); err == nil {
			v.Saved = info.ModTime()
			v.Size = info.Size()
		}
		versions = append(versions, v)
	}
	return versions, nil
}

// RestoreVersion replaces the current config with an archived version. The
// replaced config goes through the normal save path, so it is validated,
// backed up and archived itself — a rollback can be rolled back.
func (e *Editor) RestoreVersion(name string) error {
	if !historyName.MatchString(name) {
		return fmt.Errorf("unknown config version %q", name)
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	raw, err := os.ReadFile(filepath.Join(e.historyDir(), name))
	if err != nil {
		return fmt.Errorf("failed to read config version: %w", err)
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var cfg map[string]any
	if err := decoder.Decode(&cfg); err != nil {
		return fmt.Errorf("archived config is not valid JSON: %w", err)
	}

	_, original, err := e.load()
	if err != nil {
		return err
	}
	return e.save(cfg, original)
}

// AddOutbound inserts a single outbound into the config; see AddOutbounds.
func (e *Editor) AddOutbound(outbound map[string]any) error {
	_, err := e.AddOutbounds([]map[string]any{outbound}, nil)
	return err
}

// AddOutbounds inserts imported outbounds into the config in one pass. An
// existing outbound with the same tag is replaced (re-importing a server
// updates it, keeping a detour set on it) unless an import may not replace
// it (importReplaceable: direct, block, dns, a group, the DPI-bypass
// outbound, a subscription's node — reserved, also when the config lacks
// it); then the imported one is saved as "<tag> (N)" and listed in Renamed.
// New tags are registered in every selector/urltest group so they become
// selectable — not a relay of another node, and not in a group the node
// dials through (registerInGroups). Outbounds the config check refuses are
// left out and listed in Skipped (saveMerged); when it refuses every one
// nothing is saved. The previous config is kept as .bak.
func (e *Editor) AddOutbounds(newOutbounds []map[string]any, reserved []string) (*domain.AddResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	_, raw, err := e.load()
	if err != nil {
		return nil, err
	}
	if err := requireTags(newOutbounds); err != nil {
		return nil, err
	}

	reservedSet := setOf(reserved)
	replaceable := importReplaceable(reservedSet)
	var renamed []domain.TagRename
	outcome, err := e.saveMerged(raw, newOutbounds, func(cfg map[string]any, incoming, refused []map[string]any) error {
		// The refused ones are named along with the others, as a
		// subscription's are (syncMerge): the same batch gives the same
		// names whichever are refused, and a detour naming a refused one
		// under the name it would have been saved with is the batch's own
		// chain — a re-import decides it the same as with that node saved
		all := append(append(make([]map[string]any, 0, len(incoming)+len(refused)), incoming...), refused...)
		renames := suffixTaken(cfg, all, replaceable, reservedSet)
		saved := map[string]bool{}
		for _, o := range incoming {
			saved[tagString(o)] = true
		}
		renamed = nil
		for _, r := range renames {
			if saved[r.To] {
				renamed = append(renamed, r)
			}
		}
		return upsertOutbounds(cfg, incoming, refused, nil)
	})
	if err != nil {
		return nil, err
	}

	result := &domain.AddResult{Skipped: outcome.skipped, Changed: outcome.changed}
	if len(outcome.kept) > 0 {
		result.Renamed = renamed
	}
	for _, o := range outcome.kept {
		result.Tags = append(result.Tags, tagString(o))
	}
	return result, nil
}

// upsertOutbounds applies the AddOutbounds merge to a loaded config in place:
// replace by tag or append, then register the tags in selector/urltest groups
// (registerInGroups). refused are the outbounds of the same batch the checks
// refused, owned the other tags of the source (a subscription's nodes).
func upsertOutbounds(cfg map[string]any, newOutbounds, refused []map[string]any, owned map[string]bool) error {
	outbounds, _ := cfg["outbounds"].([]any)

	// The tags of the source: a detour naming one of them chains two of its
	// nodes, which only the source decides (a sing-box profile does)
	provider := map[string]bool{}
	for tag := range owned {
		provider[tag] = true
	}
	for _, o := range newOutbounds {
		provider[tagString(o)] = true
	}
	for _, o := range refused {
		provider[tagString(o)] = true
	}

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
				// A detour through an outbound of the user's (the DPI chain, a
				// hand-made chain) is a local routing choice: it outlives the
				// update. One through another node of the source was the
				// source's: without it now, the node dials directly.
				if detourOf(outbound) == "" {
					if detour := detourOf(existing); detour != "" && !provider[detour] {
						outbound["detour"] = detour
					}
				}
				outbounds[i] = any(outbound)
				replaced = true
				break
			}
		}
		if !replaced {
			outbounds = append(outbounds, any(outbound))
		}
	}

	cfg["outbounds"] = outbounds
	registerInGroups(cfg, newOutbounds, refused)
	return nil
}

// registerInGroups makes merged outbounds selectable: each is added, in
// order, to every selector/urltest group that lacks it — with two
// exceptions, decided on the config with all of them in place.
//
// Not an outbound another one names as its detour — another outbound of the
// config, or a node of the batch the checks refused. That is plumbing, not
// a server to choose: a ShadowTLS helper of a sing-box profile ignores the
// destination and works only as another node's detour — chosen as the
// active server, nothing connects. The providers' own profiles leave such
// helpers out of their groups too.
//
// Not in a group the outbound itself depends on — its detour, that one's
// detour, a group on the way and its members: the group would then depend
// on the outbound and the outbound on the group, a ring sing-box does not
// start with ("circular outbound dependency"). A re-imported server keeps a
// chain through a group the user set on it (upsertOutbounds), so this is an
// ordinary case: registered there, its import would be refused as a ring
// the user never made.
func registerInGroups(cfg map[string]any, merged, refused []map[string]any) {
	relays := relayTags(cfg, refused)
	edges := dependencyGraph(cfg)
	outbounds, _ := cfg["outbounds"].([]any)
	for _, o := range merged {
		tag := tagString(o)
		if relays[tag] {
			continue
		}
		upstream := dependsOn(edges, tag)
		for _, item := range outbounds {
			group, ok := item.(map[string]any)
			if !ok || !groupTypes[fmt.Sprint(group["type"])] || upstream[tagString(group)] {
				continue
			}
			members, _ := group["outbounds"].([]any)
			if !slices.Contains(members, any(tag)) {
				group["outbounds"] = append(members, any(tag))
				// Later outbounds of the batch may reach this group through
				// this one now
				edges[tagString(group)] = append(edges[tagString(group)], tag)
			}
		}
	}
}

// SyncOutbounds reconciles the set of outbounds owned by one subscription
// with a fresh fetch:
//   - an incoming name taken by an outbound the subscription does not own
//     gets a " (N)" suffix (suffixTaken), stable from one refresh to the next;
//   - an owned outbound the subscription renamed (the same server under a new
//     name — providers put live counters into the names) keeps its place,
//     the fields the app added and every reference, under the new tag
//     (pairRenamed, applyRenames);
//   - the other owned outbounds absent from newOutbounds are deleted,
//     including their selector/urltest registrations and detour references;
//     route references are repointed to a surviving outbound;
//   - the rest of newOutbounds are added or replaced as in AddOutbounds.
//
// Outbounds the config check refuses are left out (see saveMerged); an owned
// one whose update was refused stays as it is — its last working version,
// with the owned relays it dials through — and stays owned (listed in Tags).
// The file is only rewritten when the config actually changed; NeedsRestart
// is false when nothing but tags changed.
func (e *Editor) SyncOutbounds(ownedTags []string, newOutbounds []map[string]any) (*domain.SyncResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	_, raw, err := e.load()
	if err != nil {
		return nil, err
	}
	if err := requireTags(newOutbounds); err != nil {
		return nil, err
	}

	owned := setOf(ownedTags)
	mine := func(o map[string]any) bool {
		tag := tagString(o)
		typ, _ := o["type"].(string)
		return owned[tag] && !systemTypes[typ] && tag != config.DPIBypassTag
	}
	var result domain.SyncResult
	var held []string
	outcome, err := e.saveMerged(raw, newOutbounds, func(cfg map[string]any, incoming, refused []map[string]any) error {
		var err error
		result, held, err = syncMerge(cfg, incoming, refused, mine)
		return err
	})
	if err != nil {
		return nil, err
	}
	if len(newOutbounds) > 0 && len(outcome.kept) == 0 {
		// Every one refused: nothing saved, the owned outbounds stay
		return &domain.SyncResult{Skipped: outcome.skipped}, nil
	}

	for _, o := range outcome.kept {
		result.Tags = append(result.Tags, tagString(o))
	}
	result.Tags = append(result.Tags, held...)
	result.Skipped = outcome.skipped
	result.Changed = outcome.changed
	result.NeedsRestart = result.NeedsRestart && outcome.changed
	return &result, nil
}

// syncMerge applies a subscription's fresh outbounds to a loaded config in
// place (see SyncOutbounds); mine tells the outbounds the subscription owns
// and may replace or delete. refused are the fresh outbounds the checks
// refused (saveMerged): the owned outbound each would have updated is held —
// left as it is, not removed, nothing repointed, and so are the owned
// outbounds its detour chain runs through — and the held tags returned.
func syncMerge(cfg map[string]any, incoming, refused []map[string]any, mine func(map[string]any) bool) (domain.SyncResult, []string, error) {
	var result domain.SyncResult
	original, err := cloneConfig(cfg)
	if err != nil {
		return result, nil, err
	}

	// The refused ones are named along with the others — the same input
	// gives the same names, whichever are refused — to find the owned
	// outbound each would have updated
	all := append(append(make([]map[string]any, 0, len(incoming)+len(refused)), incoming...), refused...)
	suffixed := suffixTaken(cfg, all, mine, nil)
	newTags := map[string]bool{}
	for _, o := range incoming {
		newTags[tagString(o)] = true
	}
	for _, r := range suffixed {
		if newTags[r.To] {
			result.Suffixed = append(result.Suffixed, r)
		}
	}

	// Owned outbounds the subscription no longer lists, and the incoming ones
	// with a name the config does not know yet
	outbounds, _ := cfg["outbounds"].([]any)
	presentBefore := map[string]bool{}
	owned := map[string]bool{}
	var dropped []map[string]any
	for _, item := range outbounds {
		o, ok := item.(map[string]any)
		if !ok {
			continue
		}
		tag := tagString(o)
		presentBefore[tag] = true
		if mine(o) {
			owned[tag] = true
			if !newTags[tag] {
				dropped = append(dropped, o)
			}
		}
	}
	var appearing []map[string]any
	for _, o := range incoming {
		if !presentBefore[tagString(o)] {
			appearing = append(appearing, o)
		}
	}
	// The provider's tags, old and new: a detour naming one is its chain
	provider := map[string]bool{}
	for tag := range owned {
		provider[tag] = true
	}
	for _, o := range all {
		provider[tagString(o)] = true
	}

	// A refused update keeps the owned copy it would have replaced: the same
	// tag, or the same node under its previous name (pairRenamed)
	held := map[string]bool{}
	var refusedNew []map[string]any
	for _, o := range refused {
		if tag := tagString(o); owned[tag] {
			held[tag] = true
		} else {
			refusedNew = append(refusedNew, o)
		}
	}
	var candidates []map[string]any
	for _, o := range dropped {
		if !held[tagString(o)] {
			candidates = append(candidates, o)
		}
	}

	// A renamed node takes its new name everywhere first; replacing it by
	// tag (upsertOutbounds) then keeps its position and its detour. The
	// others are removed (their tags taken before the renaming changes the
	// outbounds in place)
	renames, renamed := pairRenamed(candidates, appearing, provider)
	var unpaired []map[string]any
	for _, o := range candidates {
		if renames[tagString(o)] == "" {
			unpaired = append(unpaired, o)
		}
	}
	heldRenames, _ := pairRenamed(unpaired, refusedNew, provider)
	removed := map[string]bool{}
	for _, o := range unpaired {
		if tag := tagString(o); heldRenames[tag] != "" {
			held[tag] = true
		} else {
			removed[tag] = true
		}
	}
	// A held copy keeps the relays it dials through (its detour, and theirs),
	// also the ones the provider no longer serves: removed, they would take
	// its detour along (pruneOutboundReferences), and the node reported as not
	// updated would dial its server directly, past the relay
	for changed := true; changed; {
		changed = false
		for _, o := range dropped {
			if relay := detourOf(o); held[tagString(o)] && removed[relay] {
				delete(removed, relay)
				held[relay] = true
				changed = true
			}
		}
	}
	heldTags := make([]string, 0, len(held))
	for tag := range held {
		heldTags = append(heldTags, tag)
	}
	sort.Strings(heldTags)
	applyRenames(cfg, renames)
	result.Renamed = renamed
	outbounds, _ = cfg["outbounds"].([]any)
	kept := make([]any, 0, len(outbounds))
	for _, item := range outbounds {
		if o, ok := item.(map[string]any); ok && removed[tagString(o)] {
			continue
		}
		kept = append(kept, item)
	}
	cfg["outbounds"] = kept

	if err := upsertOutbounds(cfg, incoming, refused, owned); err != nil {
		return result, nil, err
	}
	if len(removed) > 0 {
		pruneOutboundReferences(cfg, removed, incoming, refused)
	}

	renamedTo := map[string]bool{}
	for _, r := range renamed {
		renamedTo[r.To] = true
	}
	for _, o := range incoming {
		if tag := tagString(o); !presentBefore[tag] && !renamedTo[tag] {
			result.Added = append(result.Added, tag)
		}
	}
	for tag := range removed {
		result.Removed = append(result.Removed, tag)
	}
	sort.Strings(result.Removed)

	// Nothing but new names: the running sing-box works the same (the app
	// never addresses an outbound by tag at runtime), no restart needed
	applyRenames(original, renames)
	result.NeedsRestart = canonical(original) != canonical(cfg)
	return result, heldTags, nil
}

// ReadSection returns a config section as pretty-printed JSON text for
// display: every credential (password, uuid, private key...) is replaced by
// SecretPlaceholder, the file itself is not touched. WriteSection turns a kept
// placeholder back into the stored value (secrets.go).
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

	text, err := marshalIndent(maskSecrets(section))
	if err != nil {
		return "", fmt.Errorf("failed to serialize section %q: %w", name, err)
	}
	return string(bytes.TrimSpace(text)), nil
}

// WriteSection replaces a config section with user-provided JSON text. A
// SecretPlaceholder kept from ReadSection gets the stored value back, but only
// in an outbound that is otherwise unchanged (secrets.go); a placeholder that
// cannot be restored refuses the save.
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
	// The page shows the section masked: the placeholders it sends back
	// must turn into the stored credentials before anything else looks at
	// the config (the guard and sing-box check below see the real one)
	if err := restorePlaceholders(name, value, cfg[name]); err != nil {
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

// LocalProxyURL returns a proxy URL for the first local inbound usable as an
// HTTP client proxy (http/mixed preferred, socks as fallback), or "" when the
// config has none (e.g. TUN-only). Used by the connectivity check to send a
// probe through sing-box itself.
func (e *Editor) LocalProxyURL() (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	cfg, _, err := e.load()
	if err != nil {
		return "", err
	}

	socksURL := ""
	inbounds, _ := cfg["inbounds"].([]any)
	for _, item := range inbounds {
		in, ok := item.(map[string]any)
		if !ok {
			continue
		}
		port, ok := in["listen_port"].(json.Number)
		if !ok {
			continue
		}
		switch in["type"] {
		case "mixed", "http":
			return "http://127.0.0.1:" + port.String(), nil
		case "socks":
			if socksURL == "" {
				socksURL = "socks5://127.0.0.1:" + port.String()
			}
		}
	}
	return socksURL, nil
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
