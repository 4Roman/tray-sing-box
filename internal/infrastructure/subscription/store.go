// Package subscription persists the saved subscription list as a JSON file
// next to the exe and downloads subscription bodies over HTTP.
package subscription

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"tray-sing-box/internal/domain"
)

// Store keeps subscriptions in a JSON file (an array of domain.Subscription)
type Store struct {
	path string
	mu   sync.Mutex
}

// NewStore creates a store backed by the given file path; the file is
// created on first save
func NewStore(path string) *Store {
	return &Store{path: path}
}

// Load reads the subscription list; a missing file is an empty list
func (s *Store) Load() ([]domain.Subscription, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	raw, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read subscriptions: %w", err)
	}

	var subs []domain.Subscription
	if err := json.Unmarshal(raw, &subs); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", s.path, err)
	}
	return subs, nil
}

// Save writes the subscription list
func (s *Store) Save(subs []domain.Subscription) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if subs == nil {
		subs = []domain.Subscription{}
	}
	raw, err := json.MarshalIndent(subs, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize subscriptions: %w", err)
	}
	if err := os.WriteFile(s.path, raw, 0644); err != nil {
		return fmt.Errorf("failed to write subscriptions: %w", err)
	}
	return nil
}
