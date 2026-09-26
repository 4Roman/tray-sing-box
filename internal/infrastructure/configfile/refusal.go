package configfile

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"tray-sing-box/internal/domain"
)

// mergeOutcome is what saveMerged did
type mergeOutcome struct {
	kept    []map[string]any     // the incoming outbounds saved, as saved (final tags)
	skipped []domain.SkippedNode // the ones refused, by their incoming names
	changed bool                 // whether the config file was rewritten
}

// saveMerged merges incoming outbounds into the config read from raw (merge
// works on copies of them) and saves the result when it differs. One outbound
// the checks refuse must not cost the others — a subscription would stop
// updating over one odd node of its provider, an import of ten servers fail
// over one. So when the checks refuse the merged config, the incoming
// outbounds to blame are left out (refusedBy) and the others merged again,
// until a merge passes; merge gets the ones left out as well (refused), a
// subscription keeps its current copy of each. A node chained through one
// left out (its detour) goes with it: it cannot work without it, and sing-box
// does not start with a detour to a missing outbound. When every one is
// refused nothing is saved; when none is to blame, the refusal is about the
// config around them and is returned.
func (e *Editor) saveMerged(raw []byte, incoming []map[string]any, merge func(cfg map[string]any, incoming, refused []map[string]any) error) (*mergeOutcome, error) {
	copies := func(list []map[string]any) []map[string]any {
		out := make([]map[string]any, len(list))
		for i, o := range list {
			out[i] = make(map[string]any, len(o))
			for k, v := range o {
				out[i][k] = v
			}
		}
		return out
	}
	attempt := func(list, refused []map[string]any) (work []map[string]any, updated []byte, changed bool, err error) {
		cfg, err := decodeConfig(raw)
		if err != nil {
			return nil, nil, false, fmt.Errorf("failed to parse config: %w", err)
		}
		before, err := marshalIndent(cfg)
		if err != nil {
			return nil, nil, false, fmt.Errorf("failed to serialize config: %w", err)
		}
		work = copies(list)
		if err := merge(cfg, work, copies(refused)); err != nil {
			return nil, nil, false, err
		}
		after, err := marshalIndent(cfg)
		if err != nil {
			return nil, nil, false, fmt.Errorf("failed to serialize config: %w", err)
		}
		if bytes.Equal(before, after) {
			return work, nil, false, nil
		}
		updated, err = e.check(cfg, raw)
		return work, updated, true, err
	}

	// Each pass leaves out at least one more, or ends
	reasons := map[int]string{} // by index in incoming
	for {
		var idx []int
		var list, refused []map[string]any
		for i, o := range incoming {
			if _, out := reasons[i]; out {
				refused = append(refused, o)
				continue
			}
			idx = append(idx, i)
			list = append(list, o)
		}
		skipped := skippedNodes(incoming, reasons)
		if len(incoming) > 0 && len(list) == 0 {
			return &mergeOutcome{skipped: skipped}, nil
		}

		work, updated, changed, err := attempt(list, refused)
		if err == nil {
			if changed {
				if err := e.write(updated, raw); err != nil {
					return nil, err
				}
			}
			return &mergeOutcome{kept: work, skipped: skipped, changed: changed}, nil
		}
		if !refusal(err) {
			return nil, err
		}
		blamed := e.refusedBy(err, work)
		if len(blamed) == 0 {
			return nil, err
		}
		for j, reason := range blamed {
			reasons[idx[j]] = reason
		}
		leaveOutChained(incoming, reasons)
	}
}

// skippedNodes lists the incoming outbounds left out, in their order, by
// their incoming names
func skippedNodes(incoming []map[string]any, reasons map[int]string) []domain.SkippedNode {
	var skipped []domain.SkippedNode
	for i, o := range incoming {
		if reason, out := reasons[i]; out {
			skipped = append(skipped, domain.SkippedNode{Name: tagString(o), Reason: reason})
		}
	}
	return skipped
}

// leaveOutChained leaves out, until nothing changes, every incoming outbound
// whose detour names one left out (reasons, by index). The detours of
// incoming outbounds name other incoming ones by their incoming tags (a
// sing-box profile chains its own nodes; see suffixTaken for the renames).
func leaveOutChained(incoming []map[string]any, reasons map[int]string) {
	for changed := true; changed; {
		changed = false
		out := map[string]bool{}
		for i := range reasons {
			out[tagString(incoming[i])] = true
		}
		for i, o := range incoming {
			if _, gone := reasons[i]; gone {
				continue
			}
			if detour := detourOf(o); out[detour] {
				reasons[i] = fmt.Sprintf("узел работает через «%s», а тот пропущен", detour)
				changed = true
			}
		}
	}
}

// refusal: the checks refused the config (not a failure to read or write it)
func refusal(err error) bool {
	var risky *riskyError
	var check *checkError
	var dependency *dependencyError
	return errors.As(err, &risky) || errors.As(err, &check) || errors.As(err, &dependency)
}

// refusedBy returns the outbounds of work (merged, with their final tags) a
// refusal is about, with the reason, by index: the ones a dependency problem
// names (the other outbounds it names are the config's), or the ones the
// guard or sing-box check refuse on their own (refusedAlone)
func (e *Editor) refusedBy(err error, work []map[string]any) map[int]string {
	var dependency *dependencyError
	if !errors.As(err, &dependency) {
		return e.refusedAlone(work)
	}
	byTag := map[string]int{}
	for j, o := range work {
		byTag[tagString(o)] = j
	}
	reasons := map[int]string{}
	for _, p := range dependency.problems {
		for _, tag := range p.tags {
			if j, ok := byTag[tag]; ok {
				if _, done := reasons[j]; !done {
					reasons[j] = p.reason(tag)
				}
			}
		}
	}
	return reasons
}

// refusedAlone checks outbounds without the config around them and returns
// the reason for each one refused, by index. The guard first (cheap); then
// sing-box check on all of them in one config (isolate) — a subscription with
// one odd node costs two checks, not one per node (each is a sing-box start,
// ~0.4 s).
func (e *Editor) refusedAlone(outbounds []map[string]any) map[int]string {
	reasons := map[int]string{}
	var pending []int
	for i, o := range outbounds {
		if err := checkNoNewRisky(nil, aloneConfig(o)); err != nil {
			reasons[i] = refusalReason(err, o)
			continue
		}
		pending = append(pending, i)
	}
	if e.validator != nil {
		e.isolate(outbounds, pending, reasons)
	}
	return reasons
}

// isolate finds the outbounds (the indexes pending) sing-box check refuses
// and records why in reasons. sing-box names only the first outbound it
// refuses, so each round leaves that one out and checks the rest again —
// together with the others of its type that carry the same unknown field
// (sameUnknownField): a provider serving a field of a newer sing-box in
// every node costs a round, not one per node. An answer that names no
// outbound (a crash) splits the list in halves, each checked on its own:
// a few rounds for one such node, never one per node.
func (e *Editor) isolate(outbounds []map[string]any, pending []int, reasons map[int]string) {
	for len(pending) > 0 {
		list := make([]any, len(pending))
		for j, i := range pending {
			list[j] = alone(outbounds[i])
		}
		err := e.validate(map[string]any{"outbounds": list})
		if err == nil {
			return
		}
		if len(pending) == 1 {
			reasons[pending[0]] = refusalReason(err, outbounds[pending[0]])
			return
		}
		j, ok := refusedIndex(err.Error())
		if !ok || j >= len(pending) {
			half := len(pending) / 2
			e.isolate(outbounds, append([]int(nil), pending[:half]...), reasons)
			e.isolate(outbounds, append([]int(nil), pending[half:]...), reasons)
			return
		}
		refused := outbounds[pending[j]]
		key := unknownField(err.Error())
		rest := pending[:0:0]
		for n, i := range pending {
			if n == j || (key != "" && sameUnknownField(outbounds[i], refused, key)) {
				reasons[i] = refusalReason(err, outbounds[i])
				continue
			}
			rest = append(rest, i)
		}
		pending = rest
	}
}

// unknownFieldMessage is sing-box's refusal of a key it does not know in an
// outbound itself (not in one of its objects): `outbounds[3].foo: json:
// unknown field "foo"`
var unknownFieldMessage = regexp.MustCompile(`^outbounds\[\d+\]\.([^.\s\[\]]+): json: unknown field "([^"]*)"$`)

// unknownField is the key of an outbound sing-box refused as unknown, ""
// for any other answer
func unknownField(output string) string {
	m := unknownFieldMessage.FindStringSubmatch(checkMessage(output))
	if m == nil || m[1] != m[2] {
		return ""
	}
	return m[1]
}

// sameUnknownField: o has the key sing-box refused in refused as unknown,
// spelled the same, and is of the same type. The options of an outbound are
// decoded by its type alone, so sing-box refuses the key in o just the same.
func sameUnknownField(o, refused map[string]any, key string) bool {
	if _, has := o[key]; !has {
		return false
	}
	typ, _ := o["type"].(string)
	refusedType, _ := refused["type"].(string)
	return typ != "" && typ == refusedType
}

// validate runs the validator on a config; a missing sing-box.exe is no
// refusal
func (e *Editor) validate(cfg map[string]any) error {
	body, err := marshalIndent(cfg)
	if err != nil {
		return nil
	}
	if err := e.validator(body); err != nil && !errors.Is(err, domain.ErrSingBoxMissing) {
		return err
	}
	return nil
}

// alone is an outbound as checked on its own: without a detour, which names
// an outbound of the config left out
func alone(o map[string]any) map[string]any {
	c := make(map[string]any, len(o))
	for k, v := range o {
		if k != "detour" {
			c[k] = v
		}
	}
	return c
}

func aloneConfig(o map[string]any) map[string]any {
	return map[string]any{"outbounds": []any{alone(o)}}
}

// refusalReason is why an outbound was left out, for the user: the guard's
// items or sing-box's message without the outbound's position, and without
// its credentials should sing-box quote one
func refusalReason(err error, o map[string]any) string {
	var risky *riskyError
	if errors.As(err, &risky) {
		return "приложение не добавляет в конфиг такие параметры (" + risky.listed() + ")"
	}
	message := aloneIndex.ReplaceAllString(checkMessage(err.Error()), "")
	return "sing-box не принимает: " + redactSecrets(message, o)
}

var (
	// logPrefix is the level and time of a sing-box log line
	logPrefix = regexp.MustCompile(`^(FATAL|ERROR)\[\d+\] `)
	// decodeAt names the file under check, a random name in the data dir
	decodeAt = regexp.MustCompile(`decode config at .*?\.json: `)
	// indexedEntry is how sing-box names a config entry: by its position
	indexedEntry = regexp.MustCompile(`\b(outbound|inbound|endpoint)s?\[(\d+)\]`)
	// aloneIndex is the position of the only outbound of a checked config
	aloneIndex = regexp.MustCompile(`(initialize )?outbounds?\[\d+\](: |\.)?`)
)

// checkMessage reduces the output of sing-box check to its message: the
// FATAL line — or the first line of a crash, not its stack — without the log
// prefix and the path of the file under check
func checkMessage(output string) string {
	output = strings.TrimPrefix(output, "sing-box check: ")
	var first, line string
	for _, l := range strings.Split(output, "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if first == "" {
			first = l
		}
		if strings.HasPrefix(l, "FATAL") || strings.HasPrefix(l, "ERROR") || strings.HasPrefix(l, "panic:") {
			line = l
			break
		}
	}
	if line == "" {
		line = first
	}
	line = logPrefix.ReplaceAllString(line, "")
	return decodeAt.ReplaceAllString(line, "")
}

// refusedIndex is the position of the outbound sing-box names in its answer
func refusedIndex(output string) (int, bool) {
	for _, m := range indexedEntry.FindAllStringSubmatch(checkMessage(output), -1) {
		if m[1] == "outbound" {
			n, err := strconv.Atoi(m[2])
			return n, err == nil
		}
	}
	return 0, false
}

// checkError is a refusal of sing-box check: its message, the entries named
// by tag instead of their position (which counts every outbound of the file,
// direct and the groups included — the user cannot tell which one it is)
type checkError struct {
	message string
}

func (e *checkError) Error() string {
	return "sing-box check не принял конфиг: " + e.message
}

func newCheckError(err error, cfg map[string]any) error {
	message := indexedEntry.ReplaceAllStringFunc(checkMessage(err.Error()), func(m string) string {
		sub := indexedEntry.FindStringSubmatch(m)
		list, _ := cfg[sub[1]+"s"].([]any)
		n, _ := strconv.Atoi(sub[2])
		if n < len(list) {
			if o, ok := list[n].(map[string]any); ok && tagString(o) != "" {
				return sub[1] + " «" + tagString(o) + "»"
			}
		}
		return m
	})
	return &checkError{message: redactSecrets(message, cfg)}
}

// redactSecrets replaces the credentials found in v (secretKeys) where a
// message quotes them: sing-box's errors pass into the log, the popups and
// the settings page. Very short values are left alone, they would match
// ordinary words.
func redactSecrets(message string, v any) string {
	var secrets []string
	var collect func(any)
	collect = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, child := range x {
				if !isSecret(k, child) {
					collect(child)
					continue
				}
				switch s := child.(type) {
				case string:
					secrets = append(secrets, s)
				case []any:
					for _, line := range s {
						if str, ok := line.(string); ok {
							secrets = append(secrets, str)
						}
					}
				}
			}
		case []any:
			for _, child := range x {
				collect(child)
			}
		}
	}
	collect(v)
	// Longest first: a secret containing another is replaced whole
	sort.Slice(secrets, func(i, j int) bool { return len(secrets[i]) > len(secrets[j]) })
	for _, s := range secrets {
		if len(s) >= 4 {
			message = strings.ReplaceAll(message, s, SecretPlaceholder)
		}
	}
	return message
}

// checkSelectorDefaults refuses a selector whose default is not one of its
// members: sing-box check passes such a config, and sing-box then does not
// start ("default outbound not found"). One the previous config already had
// stays allowed, like the guard does (a selection stored in the cache file
// can keep such a config running, and a save elsewhere must not fail on it).
func checkSelectorDefaults(previous []byte, cfg map[string]any) error {
	had := map[string]bool{}
	if old, err := decodeConfig(previous); err == nil {
		for _, d := range danglingDefaults(old) {
			had[d.tag+"\x00"+d.def] = true
		}
	}
	for _, d := range danglingDefaults(cfg) {
		if !had[d.tag+"\x00"+d.def] {
			return fmt.Errorf("селектор «%s»: default «%s» не входит в его outbounds — с таким конфигом sing-box не запустится", d.tag, d.def)
		}
	}
	return nil
}

type danglingDefault struct{ tag, def string }

// danglingDefaults lists the selectors whose default is not a member. Keys
// are matched the way sing-box matches them (foldKey).
func danglingDefaults(cfg map[string]any) []danglingDefault {
	var found []danglingDefault
	outbounds, _ := field(cfg, "outbounds")
	list, _ := outbounds.([]any)
	for _, item := range list {
		o, ok := item.(map[string]any)
		if !ok {
			continue
		}
		typ, _ := field(o, "type")
		defValue, _ := field(o, "default")
		def, _ := defValue.(string)
		if typ != "selector" || def == "" {
			continue
		}
		membersValue, _ := field(o, "outbounds")
		members, _ := membersValue.([]any)
		member := false
		for _, m := range members {
			if m == any(def) {
				member = true
				break
			}
		}
		if !member {
			tagValue, _ := field(o, "tag")
			tag, _ := tagValue.(string)
			found = append(found, danglingDefault{tag: tag, def: def})
		}
	}
	return found
}
