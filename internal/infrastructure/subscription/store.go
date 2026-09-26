// Package subscription persists the saved subscription list as a JSON file
// next to the exe and downloads subscription bodies over HTTP.
package subscription

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

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

// Save writes the subscription list. The file is replaced, never rewritten
// in place: an interrupted write (a crash, a power loss during a refresh)
// must leave the previous list, not an empty or partial file — every
// subscription operation fails on an unreadable one, and in the installed
// layout only an administrator could repair it.
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
	if err := replaceFile(s.path, raw); err != nil {
		return fmt.Errorf("failed to write subscriptions: %w", err)
	}
	return nil
}

// replaceFile writes data to a new file in the same directory and renames it
// over path. The new file gets the directory's inheritable permissions, as a
// file created in place would (the installed data dir: administrators only);
// on Windows the rename replaces the old file (MoveFileEx with
// MOVEFILE_REPLACE_EXISTING). Flushed before the rename, so the name never
// points at data still in the cache.
func replaceFile(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".new-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // after a successful rename: nothing there
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return renameRetrying(tmp.Name(), path)
}

// renameRetries and renameRetryDelay: an on-access scanner may hold the file
// just written for a moment, and a rename fails meanwhile — the reason Go's
// own tool retries renames on Windows (cmd/go/internal/robustio)
const (
	renameRetries    = 10
	renameRetryDelay = 100 * time.Millisecond
)

// rename is os.Rename; a variable so a test can make it fail
var rename = os.Rename

func renameRetrying(from, to string) error {
	var err error
	for attempt := 0; attempt < renameRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(renameRetryDelay)
		}
		if err = rename(from, to); err == nil {
			return nil
		}
	}
	return err
}
