package domain

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Subscription is one saved subscription URL and the outbound tags it owns
type Subscription struct {
	URL     string    `json:"url"`
	Tags    []string  `json:"tags"`
	Updated time.Time `json:"updated"`
	// Problem identifies what went wrong at the last refresh (a hash of the
	// error and the reasons nodes were skipped; empty: nothing): an
	// unattended refresh tells the user about a problem only when it differs
	// from this one (SubscriptionUpdate.NewProblem)
	Problem string `json:"problem,omitempty"`
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
	// NewProblem: Err or Skipped differ from what the previous refresh of
	// this subscription found — an unattended refresh reports only these
	NewProblem bool

	changedConfig bool // the sync changed config.json in a way sing-box sees
}

// SubscriptionResult describes a finished subscription operation
type SubscriptionResult struct {
	Updates   []SubscriptionUpdate
	Restarted bool // whether the VPN was restarted to apply config changes
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
			return result, fmt.Errorf("подписка удалена, но VPN %w", err)
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
			return result, fmt.Errorf("подписки обновлены, но VPN %w", err)
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
		update.Err = fmt.Errorf("не удалось скачать подписку: %w", err)
		// Often a moment without network (right after logon): a problem
		// only once the servers are getting old
		if stale := sub.Updated.IsZero() || time.Since(sub.Updated) > subscriptionStaleAfter; stale {
			noteProblem(sub, &update, "fetch")
		}
		return update
	}
	outbounds, skipped, err := s.parser.Parse(body)
	update.Skipped = skipped
	for _, sk := range skipped {
		log.Printf("Subscription %s: skipped %q: %s", RedactURL(sub.URL), sk.Name, sk.Reason)
	}
	if err != nil {
		update.Err = noneUsable("не удалось разобрать подписку", skipped, err)
		noteProblem(sub, &update, problemKey(update))
		return update
	}

	sync, err := s.config.SyncOutbounds(sub.Tags, outbounds)
	if err != nil {
		update.Err = fmt.Errorf("не удалось обновить конфиг: %w", err)
		noteProblem(sub, &update, problemKey(update))
		return update
	}
	for _, sk := range sync.Skipped {
		log.Printf("Subscription %s: %q refused by the config check: %s", RedactURL(sub.URL), sk.Name, sk.Reason)
	}
	update.Skipped = append(update.Skipped, sync.Skipped...)
	if len(sync.Tags) == 0 {
		// Every node refused: nothing was saved, the servers of the last
		// refresh stay (and stay owned)
		update.Err = noneUsable("ни один сервер подписки не подошёл", update.Skipped, nil)
		noteProblem(sub, &update, problemKey(update))
		return update
	}

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
	noteProblem(sub, &update, problemKey(update))
	for _, r := range sync.Suffixed {
		log.Printf("Subscription %s: %q saved as %q (the name is taken)", RedactURL(sub.URL), r.From, r.To)
	}
	log.Printf("Subscription refreshed: %s (%d nodes, +%d -%d, renamed %d, skipped %d, changed=%v, restart=%v)",
		RedactURL(sub.URL), len(tags), len(sync.Added), len(sync.Removed), len(sync.Renamed),
		len(update.Skipped), sync.Changed, sync.NeedsRestart)
	return update
}

// subscriptionStaleAfter: a subscription that has not been downloaded for
// this long is reported by the unattended refresh (a failed download of a
// fresh one is not: the next refresh usually makes it)
const subscriptionStaleAfter = 24 * time.Hour

// quotedNames matches the node names in a message: they may carry live
// counters (3x-ui's default remark ends with the traffic and days left),
// which must not make the same problem look new at every refresh
var quotedNames = regexp.MustCompile(`«[^»]*»`)

// problemKey sums up what went wrong in a refresh — the error and the
// reasons of the skipped nodes, without node names; "" when nothing did
func problemKey(update SubscriptionUpdate) string {
	var parts []string
	if update.Err != nil {
		parts = append(parts, "error: "+quotedNames.ReplaceAllString(update.Err.Error(), "«»"))
	}
	reasons := make([]string, 0, len(update.Skipped))
	for _, sk := range update.Skipped {
		reasons = append(reasons, quotedNames.ReplaceAllString(sk.Reason, "«»"))
	}
	sort.Strings(reasons)
	return strings.Join(append(parts, reasons...), "\n")
}

// noteProblem records the problem of this refresh in the subscription and
// flags it as new when it differs from the one recorded before. Stored as a
// hash: the text may name nodes, and the file needs none of it.
func noteProblem(sub *Subscription, update *SubscriptionUpdate, key string) {
	if key == "" {
		sub.Problem = ""
		return
	}
	sum := sha256.Sum256([]byte(key))
	id := hex.EncodeToString(sum[:8])
	update.NewProblem = id != sub.Problem
	sub.Problem = id
}

func indexOfSubscription(subs []Subscription, rawURL string) int {
	for i := range subs {
		if subs[i].URL == rawURL {
			return i
		}
	}
	return -1
}
