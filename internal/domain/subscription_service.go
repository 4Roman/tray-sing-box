package domain

import (
	"fmt"
	"log"
	"net/url"
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
}

// SyncResult describes how SubscriptionConfigStore.SyncOutbounds changed the
// config
type SyncResult struct {
	Added   []string // tags that did not exist before
	Removed []string // owned tags deleted because the subscription dropped them
	Changed bool     // whether the config file was rewritten
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
// with a freshly fetched set (implemented by configfile.Editor)
type SubscriptionConfigStore interface {
	SyncOutbounds(ownedTags []string, outbounds []map[string]any) (*SyncResult, error)
}

// SubscriptionUpdate is the outcome of refreshing one subscription
type SubscriptionUpdate struct {
	URL     string
	Tags    []string
	Added   []string
	Removed []string
	Err     error

	changedConfig bool // the sync rewrote config.json
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
		return nil, fmt.Errorf("не похоже на ссылку подписки: %q", rawURL)
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
		return nil, fmt.Errorf("подписка не найдена: %q", rawURL)
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
		return nil, fmt.Errorf("подписка не найдена: %q", rawURL)
	}

	sync, err := s.config.SyncOutbounds(subs[i].Tags, nil)
	if err != nil {
		return nil, fmt.Errorf("не удалось удалить серверы подписки: %w", err)
	}

	subs = append(subs[:i], subs[i+1:]...)
	if err := s.store.Save(subs); err != nil {
		return nil, err
	}
	log.Printf("Subscription removed: %s (deleted outbounds: %v)", rawURL, sync.Removed)

	result := &SubscriptionResult{
		Updates: []SubscriptionUpdate{{URL: rawURL, Removed: sync.Removed}},
	}
	if sync.Changed {
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
		return update
	}
	outbounds, err := s.parser.Parse(body)
	if err != nil {
		update.Err = fmt.Errorf("не удалось разобрать подписку: %w", err)
		return update
	}

	sync, err := s.config.SyncOutbounds(sub.Tags, outbounds)
	if err != nil {
		update.Err = fmt.Errorf("не удалось обновить конфиг: %w", err)
		return update
	}

	tags := make([]string, 0, len(outbounds))
	for _, o := range outbounds {
		if tag, _ := o["tag"].(string); tag != "" {
			tags = append(tags, tag)
		}
	}
	sort.Strings(tags)
	sub.Tags = tags
	sub.Updated = time.Now()

	update.Tags = tags
	update.Added = sync.Added
	update.Removed = sync.Removed
	update.changedConfig = sync.Changed
	log.Printf("Subscription refreshed: %s (%d nodes, +%d -%d, changed=%v)",
		sub.URL, len(tags), len(sync.Added), len(sync.Removed), sync.Changed)
	return update
}

func indexOfSubscription(subs []Subscription, rawURL string) int {
	for i := range subs {
		if subs[i].URL == rawURL {
			return i
		}
	}
	return -1
}
