package domain

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// Subscription is one saved subscription URL and the outbound tags it owns.
// The JSON names are the format of subscriptions.json and stay as they are.
type Subscription struct {
	URL     string    `json:"url"`
	Tags    []string  `json:"tags"`
	Updated time.Time `json:"updated"`
	// Reported ("reported"): the kinds of problem the user has been told
	// about for this subscription (problemKinds), each as a short hash — the
	// text may name nodes, and the file needs none of it. An unattended
	// refresh reports only a kind not in it (SubscriptionUpdate.NewProblem):
	// a provider that switches between two problems, or between a problem
	// and a clean list, is reported once, not at every refresh. Forgotten
	// once the subscription has had no problem for problemMemory; the
	// failure of a stage of the refresh (the download, the parse, the
	// config, a usable node) as soon as that stage works again. Least
	// recently seen first.
	Reported []string `json:"reported,omitempty"`
	// ProblemSeen ("problem_seen"): when a refresh last found a problem;
	// what measures problemMemory
	ProblemSeen time.Time `json:"problem_seen,omitzero"`
}

// SyncResult describes how SubscriptionConfigStore.SyncOutbounds changed the
// config
type SyncResult struct {
	Tags     []string      // tags of the subscription's outbounds in the config now
	Added    []string      // tags that did not exist before
	Removed  []string      // owned tags deleted because the subscription dropped them
	Renamed  []TagRename   // owned outbounds the subscription renamed, kept in place under the new tag
	Suffixed []TagRename   // incoming names taken by outbounds the subscription does not own
	Skipped  []SkippedNode // refused by the config check, left out
	Changed  bool          // whether the config file was rewritten
	// NeedsRestart: the change matters to a running sing-box. Renamed tags
	// alone do not (the app never addresses outbounds by tag at runtime)
	NeedsRestart bool
}

// SubscriptionStore persists the subscription list (implemented by
// infrastructure/subscription as a JSON file next to the exe)
type SubscriptionStore interface {
	Load() ([]Subscription, error)
	Save([]Subscription) error
}

// SubscriptionFetcher downloads the subscription body (share links or a
// base64 blob) from its URL
type SubscriptionFetcher func(url string) (string, error)

// SubscriptionConfigStore reconciles the outbounds owned by a subscription
// with a freshly fetched set (implemented by configfile.Editor). An outbound
// the subscription renamed keeps its place and every reference to it; an
// incoming name taken by an outbound the subscription does not own gets a
// " (N)" suffix; outbounds the config check refuses are left out (when it
// refuses every one, nothing is saved and Tags is empty).
type SubscriptionConfigStore interface {
	SyncOutbounds(ownedTags []string, outbounds []map[string]any) (*SyncResult, error)
}

// SubscriptionUpdate is the outcome of refreshing one subscription. URL is
// the saved URL itself — it carries the provider's access token, so it is
// shown (logged, put into a popup or a response) only through RedactURL.
type SubscriptionUpdate struct {
	URL      string
	Tags     []string
	Added    []string
	Removed  []string
	Renamed  []TagRename   // nodes the provider renamed, kept under the new name
	Suffixed []TagRename   // nodes saved as "<name> (N)": the name was taken
	Skipped  []SkippedNode // nodes of the body left out, with the reason
	Err      error
	// NewProblem: Err or Skipped show a kind of problem the user has not
	// been told about for this subscription (Subscription.Reported) — an
	// unattended refresh reports only these. A refresh that saved nothing
	// has one only once the subscription is stale (noteFailure).
	NewProblem bool

	changedConfig bool // the sync changed config.json in a way sing-box sees
}

// SubscriptionResult describes a finished subscription operation
type SubscriptionResult struct {
	Updates   []SubscriptionUpdate
	Restarted bool // whether the VPN was restarted to apply config changes
	// RestartErr: the operation itself was done and saved, only the VPN
	// restart that applies it failed. The operation returns the same error,
	// with this result: its problems are already recorded as reported
	// (NewProblem), so whoever shows the error shows the result with it —
	// otherwise the user would never hear of them.
	RestartErr error
}

// Applied reports whether the operation that returned this result and err
// was done: err is nil, or it is only the failed VPN restart after it (then
// the result is shown together with the error)
func (r *SubscriptionResult) Applied(err error) bool {
	return err == nil || (r != nil && r.RestartErr != nil)
}

// SubscriptionService manages proxy subscriptions: a saved URL whose nodes
// are kept in the config and refreshed on demand or on a timer. Refreshing
// replaces the subscription's outbounds (stale ones are deleted), keeps the
// active server when it survived, and restarts the VPN once when the config
// actually changed.
type SubscriptionService struct {
	store  SubscriptionStore
	fetch  SubscriptionFetcher
	parser OutboundParser
	config SubscriptionConfigStore
	vpn    *VPNService

	mu sync.Mutex // serializes subscription operations
}

// NewSubscriptionService creates a new subscription service
func NewSubscriptionService(store SubscriptionStore, fetch SubscriptionFetcher, parser OutboundParser, config SubscriptionConfigStore, vpn *VPNService) *SubscriptionService {
	return &SubscriptionService{
		store:  store,
		fetch:  fetch,
		parser: parser,
		config: config,
		vpn:    vpn,
	}
}

// IsSubscriptionURL reports whether text looks like a subscription URL
// rather than share-link content
func IsSubscriptionURL(text string) bool {
	t := strings.TrimSpace(text)
	if !strings.HasPrefix(t, "http://") && !strings.HasPrefix(t, "https://") {
		return false
	}
	if strings.ContainsAny(t, " \n\r\t") {
		return false
	}
	u, err := url.Parse(t)
	return err == nil && u.Host != ""
}

// subscriptionKey keys SubscriptionID. A plain hash of the URL would let
// whoever sees an ID (the settings page, the log) confirm a guessed URL
// offline, and provider tokens are often short or predictable. Random per
// process: the IDs only need to hold while the app runs (the page lists the
// subscriptions again after a restart).
var subscriptionKey = func() []byte {
	key := make([]byte, 32)
	rand.Read(key)
	return key
}()

// SubscriptionID identifies a subscription without revealing its URL: the
// first 16 hex digits of a keyed hash (HMAC-SHA-256) of the URL. The settings
// page addresses subscriptions by it — the URL carries the provider's access
// token and never leaves the elevated process.
func SubscriptionID(rawURL string) string {
	mac := hmac.New(sha256.New, subscriptionKey)
	mac.Write([]byte(rawURL))
	return hex.EncodeToString(mac.Sum(nil)[:8])
}

// RedactURL is how a subscription is named in logs, popups, errors and on
// the settings page: "scheme://host/… (abcdef)". Userinfo, path, query and
// fragment — where providers put the access token — are dropped; the six hex
// digits (a prefix of SubscriptionID) tell two subscriptions of one host
// apart. A string that is not an absolute URL becomes "(подписка abcdef)".
func RedactURL(rawURL string) string {
	short := SubscriptionID(rawURL)[:6]
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Sprintf("(подписка %s)", short)
	}
	name := u.Scheme + "://" + u.Host
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		name += "/…"
	}
	return fmt.Sprintf("%s (%s)", name, short)
}

// List returns the saved subscriptions
func (s *SubscriptionService) List() ([]Subscription, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.store.Load()
}

// Add registers a subscription URL and imports its nodes. Adding an already
// known URL refreshes it.
func (s *SubscriptionService) Add(rawURL string) (*SubscriptionResult, error) {
	rawURL = strings.TrimSpace(rawURL)
	if !IsSubscriptionURL(rawURL) {
		return nil, fmt.Errorf("не похоже на ссылку подписки: %s", RedactURL(rawURL))
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	subs, err := s.store.Load()
	if err != nil {
		return nil, err
	}
	if indexOfSubscription(subs, rawURL) < 0 {
		subs = append(subs, Subscription{URL: rawURL})
	}
	return s.refresh(subs, rawURL)
}

// Update refreshes one subscription by URL
func (s *SubscriptionService) Update(rawURL string) (*SubscriptionResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	subs, err := s.store.Load()
	if err != nil {
		return nil, err
	}
	if indexOfSubscription(subs, rawURL) < 0 {
		return nil, fmt.Errorf("подписка не найдена: %s", RedactURL(rawURL))
	}
	return s.refresh(subs, rawURL)
}

// UpdateAll refreshes every saved subscription. One failing subscription
// does not block the others; per-subscription errors are reported in the
// result. The VPN is restarted at most once, only when something changed.
func (s *SubscriptionService) UpdateAll() (*SubscriptionResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	subs, err := s.store.Load()
	if err != nil {
		return nil, err
	}
	return s.refresh(subs, "")
}

// Remove deletes a subscription and all outbounds it owns from the config
func (s *SubscriptionService) Remove(rawURL string) (*SubscriptionResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	subs, err := s.store.Load()
	if err != nil {
		return nil, err
	}
	i := indexOfSubscription(subs, rawURL)
	if i < 0 {
		return nil, fmt.Errorf("подписка не найдена: %s", RedactURL(rawURL))
	}

	sync, err := s.config.SyncOutbounds(subs[i].Tags, nil)
	if err != nil {
		return nil, fmt.Errorf("не удалось удалить серверы подписки: %w", err)
	}

	subs = append(subs[:i], subs[i+1:]...)
	if err := s.store.Save(subs); err != nil {
		return nil, err
	}
	log.Printf("Subscription removed: %s (deleted outbounds: %v)", RedactURL(rawURL), sync.Removed)

	result := &SubscriptionResult{
		Updates: []SubscriptionUpdate{{URL: rawURL, Removed: sync.Removed}},
	}
	if sync.NeedsRestart {
		restarted, err := s.vpn.RestartIfRunning()
		if err != nil {
			result.RestartErr = fmt.Errorf("подписка удалена, но VPN %w", err)
			return result, result.RestartErr
		}
		result.Restarted = restarted
	}
	return result, nil
}

// refresh re-fetches the given subscription (or all of them when onlyURL is
// empty), syncs the config and saves the updated subscription list.
// Callers must hold s.mu.
func (s *SubscriptionService) refresh(subs []Subscription, onlyURL string) (*SubscriptionResult, error) {
	result := &SubscriptionResult{}
	changed := false

	for i := range subs {
		if onlyURL != "" && subs[i].URL != onlyURL {
			continue
		}
		update := s.refreshOne(&subs[i])
		if update.Err == nil && update.changedConfig {
			changed = true
		}
		result.Updates = append(result.Updates, update)
	}

	// No config yet (a fresh install): nothing could be synced. A targeted add
	// or update must not be kept as if it had worked (an added subscription
	// would sit there without servers until the next refresh)
	if onlyURL != "" {
		for _, u := range result.Updates {
			if errors.Is(u.Err, ErrConfigMissing) {
				return result, withSetupHint(u.Err)
			}
		}
	}

	if err := s.store.Save(subs); err != nil {
		return result, err
	}

	if changed {
		restarted, err := s.vpn.RestartIfRunning()
		if err != nil {
			// The problems found are saved as reported by now: the result
			// goes with the error (see RestartErr)
			result.RestartErr = fmt.Errorf("подписки обновлены, но VPN %w", err)
			return result, result.RestartErr
		}
		result.Restarted = restarted
	}

	// A single targeted operation should fail loudly, not via Updates[i].Err
	if onlyURL != "" {
		for _, u := range result.Updates {
			if u.Err != nil {
				return result, u.Err
			}
		}
	}
	return result, nil
}

// refreshOne fetches, parses and syncs a single subscription in place
func (s *SubscriptionService) refreshOne(sub *Subscription) SubscriptionUpdate {
	update := SubscriptionUpdate{URL: sub.URL}

	body, err := s.fetch(sub.URL)
	if err != nil {
		update.Err = fmt.Errorf("%s: %w", fetchFailed, &oneLineError{err})
		noteFailure(sub, &update)
		return update
	}
	// A stage that works again forgets its own failure: when it fails for
	// good later on (the provider took the link away, switched to a format
	// the app cannot read), that is news even if an earlier outage of the
	// same stage was reported — a failure counts only after a day without a
	// refresh that saved the servers anyway (noteFailure)
	forgetKind(sub, "error: "+fetchFailed)
	outbounds, skipped, err := s.parser.Parse(body)
	update.Skipped = skipped
	for _, sk := range skipped {
		log.Printf("Subscription %s: skipped %q: %s", RedactURL(sub.URL), sk.Name, sk.Reason)
	}
	if err != nil {
		update.Err = noneUsable(parseFailed, skipped, err)
		noteFailure(sub, &update)
		return update
	}
	forgetKind(sub, "error: "+parseFailed)
	outbounds = withoutInfoNodes(sub.URL, outbounds)
	if len(outbounds) == 0 {
		// Nothing but the provider's info entries (and nodes left out): not
		// synced — an empty set would delete every server of the
		// subscription. The servers of the last refresh stay (and stay
		// owned), as when the config check refuses every node.
		update.Err = errOnlyInfoNodes
		if len(skipped) > 0 {
			update.Err = noneUsable(noneFit, skipped, nil)
		}
		noteFailure(sub, &update)
		return update
	}

	sync, err := s.config.SyncOutbounds(sub.Tags, outbounds)
	if err != nil {
		update.Err = fmt.Errorf("%s: %w", configFailed, &oneLineError{err})
		// Every message of this refresh shows the error alone, not the nodes
		// the parser left out (subscriptionLine, the settings page): only its
		// kind is recorded as reported. The nodes are news at the refresh
		// that lists them — recorded now, they never would be.
		shown := SubscriptionUpdate{Err: update.Err}
		noteFailure(sub, &shown)
		update.NewProblem = shown.NewProblem
		return update
	}
	forgetKind(sub, "error: "+configFailed)
	for _, sk := range sync.Skipped {
		log.Printf("Subscription %s: %q refused by the config check: %s", RedactURL(sub.URL), sk.Name, sk.Reason)
	}
	update.Skipped = append(update.Skipped, sync.Skipped...)
	if len(sync.Tags) == 0 {
		// Every node refused: nothing was saved, the servers of the last
		// refresh stay (and stay owned)
		update.Err = noneUsable(noneFit, update.Skipped, nil)
		noteFailure(sub, &update)
		return update
	}
	forgetKind(sub, "error: "+noneFit)
	forgetKind(sub, "error: "+onlyInfoNodes)

	tags := append([]string(nil), sync.Tags...)
	sort.Strings(tags)
	sub.Tags = tags
	sub.Updated = time.Now()

	update.Tags = tags
	update.Added = sync.Added
	update.Removed = sync.Removed
	update.Renamed = sync.Renamed
	update.Suffixed = sync.Suffixed
	update.changedConfig = sync.NeedsRestart
	noteProblem(sub, &update)
	for _, r := range sync.Suffixed {
		log.Printf("Subscription %s: %q saved as %q (the name is taken)", RedactURL(sub.URL), r.From, r.To)
	}
	log.Printf("Subscription refreshed: %s (%d nodes, +%d -%d, renamed %d, skipped %d, changed=%v, restart=%v)",
		RedactURL(sub.URL), len(tags), len(sync.Added), len(sync.Removed), len(sync.Renamed),
		len(update.Skipped), sync.Changed, sync.NeedsRestart)
	return update
}

// oneLineError is an error from outside the app's own words — the download,
// the config editor — put on one line of at most lineLimit characters (see
// clipLine). Its text can quote the provider's: a node's tag in a config
// refusal (sing-box check's answer, a detour to a node that is not there),
// the server's status line; and a line break in a tag would show in a
// message as a line of the app's own text — in the popup of an unattended
// refresh too. These errors are one line by design, nothing is lost; the
// error itself stays reachable (errors.Is: ErrConfigMissing).
type oneLineError struct{ err error }

func (e *oneLineError) Error() string { return clipLine(e.err.Error(), lineLimit) }
func (e *oneLineError) Unwrap() error { return e.err }

// subscriptionStaleAfter: a subscription whose refresh has saved nothing for
// this long is reported by the unattended refresh (a failed refresh of a
// fresh one is not: the next one usually makes it)
const subscriptionStaleAfter = 24 * time.Hour

// problemMemory: the kinds of problem reported for a subscription are
// forgotten once it has had none for this long, and one that comes back
// after that is news again. Not sooner: a provider whose list goes back and
// forth between a problem and none (a node that fails every other day) would
// otherwise have the unattended popup reappear every few refreshes.
const problemMemory = 7 * 24 * time.Hour

// The leading words of the error of a refresh that saved nothing, each its
// kind (problemKind): the download failed, the body could not be read, the
// config could not be changed, no node could be used, the body holds no
// server at all. Each is forgotten as soon as its stage works again
// (refreshOne).
const (
	fetchFailed   = "не удалось скачать подписку"
	parseFailed   = "не удалось разобрать подписку"
	configFailed  = "не удалось обновить конфиг"
	noneFit       = "ни один сервер подписки не подошёл"
	onlyInfoNodes = "в подписке нет серверов"
)

// errOnlyInfoNodes: the body holds nothing but the provider's info entries.
// 3x-ui sends just its info entry to a client whose subscription has expired
// or whose traffic is used up.
var errOnlyInfoNodes = errors.New(onlyInfoNodes + ": только сведения провайдера (так бывает, когда подписка истекла или закончился трафик)")

// withoutInfoNodes leaves out the provider's info entries: nodes whose
// server is this computer or no address at all. 3x-ui ("sub info node")
// puts a socks://127.0.0.1:1080 link named with the traffic and the days
// left at the top of every subscription body. Imported, it would be a proxy
// to whatever listens on that local port — and, as the body's first node,
// the server the routing falls back to when the provider drops the chosen
// one. Not a problem and not a node left out: nothing to tell the user.
// A link to a local proxy imported by hand is kept (ImportService): there
// it is the user's own.
func withoutInfoNodes(rawURL string, outbounds []map[string]any) []map[string]any {
	kept := make([]map[string]any, 0, len(outbounds))
	for _, o := range outbounds {
		server, _ := o["server"].(string)
		if isLocalServer(server) {
			tag, _ := o["tag"].(string)
			log.Printf("Subscription %s: %q left out: a provider's info entry (server %s), not a server", RedactURL(rawURL), tag, server)
			continue
		}
		kept = append(kept, o)
	}
	return kept
}

// isLocalServer reports whether a node's server is this computer (a
// loopback address, localhost) or the unspecified address
func isLocalServer(server string) bool {
	host := strings.TrimSuffix(strings.ToLower(strings.Trim(server, "[]")), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i] // an IPv6 zone
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsUnspecified())
}

// noteFailure is noteProblem for a refresh that saved nothing: a problem
// only once the subscription is stale (subscriptionStaleAfter). Often it is
// a moment's trouble the next refresh no longer has — no network right after
// logon, a page of the provider's served in place of the list, config.json
// held by another program —, and a provider whose list fails every other
// refresh must not bring the popup back each time: its kind is forgotten at
// the refresh that works. What lasts for a day is news: the servers are
// getting old.
func noteFailure(sub *Subscription, update *SubscriptionUpdate) {
	if sub.Updated.IsZero() || time.Since(sub.Updated) > subscriptionStaleAfter {
		noteProblem(sub, update)
	}
}

// reportedLimit bounds the kinds remembered for a subscription; the ones
// least recently seen go first, never one the current refresh found (it
// would be news again at the next one). The parser alone has a few dozen
// reasons to leave a node out; this only keeps the file small should the
// leading words of a message carry a value after all.
const reportedLimit = 128

// problemKinds lists what went wrong in a refresh — the kind of the error
// and of each reason nodes were left out for, each once, sorted; none when
// nothing did. The kinds only: the rest of a message is the provider's to
// vary — node names carry live counters (3x-ui's default remark ends with
// the traffic and days left), sing-box's refusal quotes the node's own field
// names and values, and the number of nodes left out changes with the
// provider's list — and none of that may make the same problem new at every
// refresh (a hostile provider could otherwise have the unattended popup
// appear every few hours).
func problemKinds(update SubscriptionUpdate) []string {
	seen := map[string]bool{}
	var kinds []string
	add := func(kind string) {
		if !seen[kind] {
			seen[kind] = true
			kinds = append(kinds, kind)
		}
	}
	if update.Err != nil {
		add("error: " + problemKind(update.Err.Error()))
	}
	for _, sk := range update.Skipped {
		add("skipped: " + problemKind(sk.Reason))
	}
	sort.Strings(kinds)
	return kinds
}

// problemKind is the kind of problem a message describes: its leading words,
// up to the first colon, quote or bracket. Every message of the app starts
// with its own words ("sing-box не принимает", "тип", "не удалось обновить
// конфиг") and names or quotes the node's values after them.
func problemKind(message string) string {
	if i := strings.IndexAny(message, ":«\"(\n"); i >= 0 {
		message = message[:i]
	}
	return strings.TrimSpace(message)
}

// noteProblem records the kinds of problem of this refresh as reported for
// the subscription (Subscription.Reported) and flags the refresh as bringing
// a new problem when one of them was not recorded yet. Only a kind not seen
// before counts: when the set of kinds merely changed — one of two went
// away, or all of them and then came back — the user has heard of every one
// already. A refresh without a problem forgets them once the last problem is
// problemMemory old.
func noteProblem(sub *Subscription, update *SubscriptionUpdate) {
	kinds := problemKinds(*update)
	now := time.Now()
	if len(kinds) == 0 {
		if len(sub.Reported) > 0 && now.Sub(sub.ProblemSeen) >= problemMemory {
			sub.Reported, sub.ProblemSeen = nil, time.Time{}
		}
		return
	}
	sub.ProblemSeen = now
	reported := append([]string(nil), sub.Reported...)
	for _, kind := range kinds {
		id := kindID(kind)
		if i := slices.Index(reported, id); i >= 0 {
			// Seen again: to the recent end, out of reach of the trim below
			reported = slices.Delete(reported, i, i+1)
		} else {
			update.NewProblem = true
		}
		reported = append(reported, id)
	}
	// This refresh's kinds are the last len(kinds): the trim takes older ones
	if extra := len(reported) - max(reportedLimit, len(kinds)); extra > 0 {
		reported = reported[extra:]
	}
	sub.Reported = reported
}

// forgetKind drops a kind of problem from the ones reported for the
// subscription: when it comes back, it is news again
func forgetKind(sub *Subscription, kind string) {
	if i := slices.Index(sub.Reported, kindID(kind)); i >= 0 {
		sub.Reported = slices.Delete(append([]string(nil), sub.Reported...), i, i+1)
	}
}

// kindID is how a kind of problem is remembered (Subscription.Reported)
func kindID(kind string) string {
	sum := sha256.Sum256([]byte(kind))
	return hex.EncodeToString(sum[:8])
}

func indexOfSubscription(subs []Subscription, rawURL string) int {
	for i := range subs {
		if subs[i].URL == rawURL {
			return i
		}
	}
	return -1
}
