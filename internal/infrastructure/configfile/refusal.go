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
// over one. So when the guard or sing-box check refuses the merged config,
// the incoming outbounds are checked without the rest of the config
// (refusedAlone); the ones refused there are left out and the others merged
// and saved in one more pass. When every one is refused nothing is saved;
// when none is refused on its own, the refusal is about the config around
// them and is returned.
func (e *Editor) saveMerged(raw []byte, incoming []map[string]any, merge func(cfg map[string]any, incoming []map[string]any) error) (*mergeOutcome, error) {
	attempt := func(list []map[string]any) (work []map[string]any, updated []byte, changed bool, err error) {
		cfg, err := decodeConfig(raw)
		if err != nil {
			return nil, nil, false, fmt.Errorf("failed to parse config: %w", err)
		}
		before, err := marshalIndent(cfg)
		if err != nil {
			return nil, nil, false, fmt.Errorf("failed to serialize config: %w", err)
		}
		work = make([]map[string]any, len(list))
		for i, o := range list {
			work[i] = make(map[string]any, len(o))
			for k, v := range o {
				work[i][k] = v
			}
		}
		if err := merge(cfg, work); err != nil {
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

	work, updated, changed, err := attempt(incoming)
	var skipped []domain.SkippedNode
	if refusal(err) && len(incoming) > 0 {
		reasons := e.refusedAlone(work)
		if len(reasons) == 0 {
			return nil, err
		}
		var rest []map[string]any
		for i, o := range incoming {
			if reason, refused := reasons[i]; refused {
				skipped = append(skipped, domain.SkippedNode{Name: tagString(o), Reason: reason})
				continue
			}
			rest = append(rest, o)
		}
		if len(rest) == 0 {
			return &mergeOutcome{skipped: skipped}, nil
		}
		work, updated, changed, err = attempt(rest)
	}
	if err != nil {
		return nil, err
	}
	if changed {
		if err := e.write(updated, raw); err != nil {
			return nil, err
		}
	}
	return &mergeOutcome{kept: work, skipped: skipped, changed: changed}, nil
}

// refusal: the guard or sing-box check refused the config (not a failure to
// read or write it)
func refusal(err error) bool {
	var risky *riskyError
	var check *checkError
	return errors.As(err, &risky) || errors.As(err, &check)
}

// refusedAlone checks outbounds without the config around them and returns
// the reason for each one refused, by index. The guard first (cheap); then
// sing-box check on all of them in one config, dropping the one it names
// until it passes — a subscription with one odd node costs two checks, not
// one per node (each is a sing-box start, ~0.4 s). An answer that names no
// outbound (a crash) leaves the rest to one check each.
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
	if e.validator == nil {
		return reasons
	}

	for len(pending) > 0 {
		list := make([]any, len(pending))
		for j, i := range pending {
			list[j] = alone(outbounds[i])
		}
		err := e.validate(map[string]any{"outbounds": list})
		if err == nil {
			return reasons
		}
		j, ok := refusedIndex(err.Error())
		if !ok || j >= len(pending) {
			break
		}
		reasons[pending[j]] = refusalReason(err, outbounds[pending[j]])
		pending = append(pending[:j:j], pending[j+1:]...)
	}
	for _, i := range pending {
		if err := e.validate(aloneConfig(outbounds[i])); err != nil {
			reasons[i] = refusalReason(err, outbounds[i])
		}
	}
	return reasons
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
