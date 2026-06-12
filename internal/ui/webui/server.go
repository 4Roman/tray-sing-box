// Package webui serves the local settings interface: raw JSON editing of
// config sections, outbound switching and share-link import. The server
// listens on localhost only and every request must carry a per-run token.
package webui

import (
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"sync"

	"tray-sing-box/internal/domain"
)

//go:embed page.html
var pageHTML string

// TextSource produces text to import an outbound from
type TextSource func() (string, error)

// Sources groups the outbound import sources available to the UI
type Sources struct {
	Clipboard TextSource
	ScreenQR  TextSource
}

// LogFile identifies one log file the UI can show
type LogFile struct {
	ID   string // "app" or "singbox"
	Path string
}

// LogAccess lists the known log files and reads their tails
// (implemented by infrastructure/logtail; either func may be nil)
type LogAccess struct {
	Files func() []LogFile
	Tail  func(path string, maxBytes int64) (string, error)
}

// Server is the local settings web server
type Server struct {
	settings *domain.SettingsService
	importer *domain.ImportService
	updater  *domain.UpdateService
	dpi      *domain.DPIBypassService
	subs     *domain.SubscriptionService
	sources  Sources
	logs     LogAccess

	mu    sync.Mutex
	opMu  sync.Mutex // serializes config/binary mutations
	url   string
	token string
	page  *template.Template
}

// New creates the settings server (not yet listening)
func New(settings *domain.SettingsService, importer *domain.ImportService, updater *domain.UpdateService, dpi *domain.DPIBypassService, subs *domain.SubscriptionService, sources Sources, logs LogAccess) *Server {
	return &Server{
		settings: settings,
		importer: importer,
		updater:  updater,
		dpi:      dpi,
		subs:     subs,
		sources:  sources,
		logs:     logs,
	}
}

// Open starts the server if needed and opens the settings page in the browser
func (s *Server) Open() error {
	url, err := s.start()
	if err != nil {
		return err
	}
	return openBrowser(url)
}

// start launches the HTTP listener once and returns the tokenized page URL
func (s *Server) start() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.url != "" {
		return s.url, nil
	}

	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}
	s.token = hex.EncodeToString(tokenBytes)

	page, err := template.New("page").Parse(pageHTML)
	if err != nil {
		return "", fmt.Errorf("failed to parse settings page: %w", err)
	}
	s.page = page

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("failed to listen: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.handlePage)
	mux.HandleFunc("GET /api/config", s.auth(s.handleConfig))
	mux.HandleFunc("POST /api/section", s.auth(s.handleSaveSection))
	mux.HandleFunc("POST /api/switch", s.auth(s.handleSwitch))
	mux.HandleFunc("POST /api/import", s.auth(s.handleImport))
	mux.HandleFunc("POST /api/update", s.auth(s.handleUpdate))
	mux.HandleFunc("GET /api/logs", s.auth(s.handleLogs))
	mux.HandleFunc("GET /api/history", s.auth(s.handleHistory))
	mux.HandleFunc("POST /api/history/restore", s.auth(s.handleHistoryRestore))
	mux.HandleFunc("GET /api/subscriptions", s.auth(s.handleSubscriptions))
	mux.HandleFunc("POST /api/subscriptions/add", s.auth(s.handleSubscriptionAdd))
	mux.HandleFunc("POST /api/subscriptions/update", s.auth(s.handleSubscriptionUpdate))
	mux.HandleFunc("POST /api/subscriptions/remove", s.auth(s.handleSubscriptionRemove))
	mux.HandleFunc("GET /api/dpi", s.auth(s.handleDPIStatus))
	mux.HandleFunc("POST /api/dpi/chain", s.auth(s.handleDPIChain))
	mux.HandleFunc("POST /api/dpi/direct", s.auth(s.handleDPIDirect))

	go func() {
		if err := http.Serve(listener, mux); err != nil {
			log.Printf("Settings server stopped: %v", err)
		}
	}()

	s.url = fmt.Sprintf("http://%s/?t=%s", listener.Addr().String(), s.token)
	log.Printf("Settings server listening on %s", listener.Addr())
	return s.url, nil
}

// auth requires the per-run token in the X-Token header
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Token") != s.token {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func (s *Server) handlePage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.URL.Query().Get("t") != s.token {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.page.Execute(w, map[string]string{"Token": s.token}); err != nil {
		log.Printf("Settings page render failed: %v", err)
	}
}

// writeJSON sends a JSON response
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// fail sends an error message the page shows to the user
func fail(w http.ResponseWriter, err error) {
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	outbounds, err := s.settings.Section("outbounds")
	if err != nil {
		fail(w, err)
		return
	}
	route, err := s.settings.Section("route")
	if err != nil {
		fail(w, err)
		return
	}
	list, active, err := s.settings.Outbounds()
	if err != nil {
		fail(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"outbounds": outbounds,
		"route":     route,
		"list":      list,
		"active":    active,
		"running":   s.settings.IsVPNRunning(),
	})
}

func (s *Server) handleSaveSection(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name    string `json:"name"`
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, fmt.Errorf("bad request: %w", err))
		return
	}

	restarted, err := s.settings.SaveSection(req.Name, []byte(req.Content))
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"restarted": restarted})
}

func (s *Server) handleSwitch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Tag string `json:"tag"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, fmt.Errorf("bad request: %w", err))
		return
	}

	restarted, err := s.settings.UseOutbound(req.Tag)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"restarted": restarted})
}

func (s *Server) handleUpdate(w http.ResponseWriter, r *http.Request) {
	if s.updater == nil {
		fail(w, fmt.Errorf("update service is not available"))
		return
	}

	s.opMu.Lock()
	defer s.opMu.Unlock()

	result, err := s.updater.Update()
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"current":   result.CurrentVersion,
		"latest":    result.LatestVersion,
		"updated":   result.Updated,
		"restarted": result.Restarted,
	})
}

// handleLogs returns the tails of the known log files. A file that cannot be
// read is reported as missing rather than failing the whole response.
func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	const maxTail = 64 * 1024

	type logEntry struct {
		ID      string `json:"id"`
		Path    string `json:"path"`
		Content string `json:"content"`
		Missing bool   `json:"missing"`
	}
	entries := []logEntry{}
	if s.logs.Files != nil && s.logs.Tail != nil {
		for _, f := range s.logs.Files() {
			e := logEntry{ID: f.ID, Path: f.Path}
			content, err := s.logs.Tail(f.Path, maxTail)
			if err != nil {
				e.Missing = true
			} else {
				e.Content = content
			}
			entries = append(entries, e)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"files": entries})
}

func (s *Server) handleDPIStatus(w http.ResponseWriter, r *http.Request) {
	if s.dpi == nil {
		fail(w, fmt.Errorf("обход DPI недоступен"))
		return
	}
	status, err := s.dpi.Status()
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) handleDPIChain(w http.ResponseWriter, r *http.Request) {
	if s.dpi == nil {
		fail(w, fmt.Errorf("обход DPI недоступен"))
		return
	}
	var req struct {
		Enable bool `json:"enable"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, fmt.Errorf("bad request: %w", err))
		return
	}

	s.opMu.Lock()
	defer s.opMu.Unlock()

	var (
		status *domain.DPIBypassStatus
		err    error
	)
	if req.Enable {
		status, err = s.dpi.EnableChain()
	} else {
		status, err = s.dpi.DisableChain()
	}
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) handleDPIDirect(w http.ResponseWriter, r *http.Request) {
	if s.dpi == nil {
		fail(w, fmt.Errorf("обход DPI недоступен"))
		return
	}
	var req struct {
		Enable bool `json:"enable"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, fmt.Errorf("bad request: %w", err))
		return
	}
	if !req.Enable {
		fail(w, fmt.Errorf("чтобы отключить прямой обход, выберите другой активный сервер в списке"))
		return
	}

	s.opMu.Lock()
	defer s.opMu.Unlock()

	status, err := s.dpi.EnableDirect()
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	versions, err := s.settings.History()
	if err != nil {
		fail(w, err)
		return
	}
	if versions == nil {
		versions = []domain.ConfigVersion{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"versions": versions})
}

func (s *Server) handleHistoryRestore(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, fmt.Errorf("bad request: %w", err))
		return
	}

	s.opMu.Lock()
	defer s.opMu.Unlock()

	restarted, err := s.settings.Rollback(req.Name)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"restarted": restarted})
}

// subscriptionResponse converts a domain result into the JSON shape the page
// renders (errors become strings)
func subscriptionResponse(result *domain.SubscriptionResult) map[string]any {
	updates := make([]map[string]any, 0, len(result.Updates))
	for _, u := range result.Updates {
		entry := map[string]any{
			"url":     u.URL,
			"count":   len(u.Tags),
			"added":   len(u.Added),
			"removed": len(u.Removed),
		}
		if u.Err != nil {
			entry["error"] = u.Err.Error()
		}
		updates = append(updates, entry)
	}
	return map[string]any{"updates": updates, "restarted": result.Restarted}
}

func (s *Server) handleSubscriptions(w http.ResponseWriter, r *http.Request) {
	if s.subs == nil {
		fail(w, fmt.Errorf("подписки недоступны"))
		return
	}
	subs, err := s.subs.List()
	if err != nil {
		fail(w, err)
		return
	}
	list := make([]map[string]any, 0, len(subs))
	for _, sub := range subs {
		entry := map[string]any{"url": sub.URL, "count": len(sub.Tags)}
		if !sub.Updated.IsZero() {
			entry["updated"] = sub.Updated
		}
		list = append(list, entry)
	}
	writeJSON(w, http.StatusOK, map[string]any{"subscriptions": list})
}

func (s *Server) handleSubscriptionAdd(w http.ResponseWriter, r *http.Request) {
	if s.subs == nil {
		fail(w, fmt.Errorf("подписки недоступны"))
		return
	}
	var req struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, fmt.Errorf("bad request: %w", err))
		return
	}

	s.opMu.Lock()
	defer s.opMu.Unlock()

	result, err := s.subs.Add(req.URL)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, subscriptionResponse(result))
}

// handleSubscriptionUpdate refreshes one subscription (url set) or all
func (s *Server) handleSubscriptionUpdate(w http.ResponseWriter, r *http.Request) {
	if s.subs == nil {
		fail(w, fmt.Errorf("подписки недоступны"))
		return
	}
	var req struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, fmt.Errorf("bad request: %w", err))
		return
	}

	s.opMu.Lock()
	defer s.opMu.Unlock()

	var (
		result *domain.SubscriptionResult
		err    error
	)
	if req.URL == "" {
		result, err = s.subs.UpdateAll()
	} else {
		result, err = s.subs.Update(req.URL)
	}
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, subscriptionResponse(result))
}

func (s *Server) handleSubscriptionRemove(w http.ResponseWriter, r *http.Request) {
	if s.subs == nil {
		fail(w, fmt.Errorf("подписки недоступны"))
		return
	}
	var req struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, fmt.Errorf("bad request: %w", err))
		return
	}

	s.opMu.Lock()
	defer s.opMu.Unlock()

	result, err := s.subs.Remove(req.URL)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, subscriptionResponse(result))
}

func (s *Server) handleImport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Source string `json:"source"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, fmt.Errorf("bad request: %w", err))
		return
	}

	var source TextSource
	switch req.Source {
	case "clipboard":
		source = s.sources.Clipboard
	case "qr":
		source = s.sources.ScreenQR
	default:
		fail(w, fmt.Errorf("unknown import source %q", req.Source))
		return
	}
	if source == nil {
		fail(w, fmt.Errorf("import source %q is not available", req.Source))
		return
	}

	text, err := source()
	if err != nil {
		fail(w, err)
		return
	}

	// A bare http(s) URL is a subscription: register it instead of a one-off
	// import (same behavior as the tray import items)
	if s.subs != nil && domain.IsSubscriptionURL(text) {
		result, err := s.subs.Add(text)
		if err != nil {
			fail(w, err)
			return
		}
		resp := subscriptionResponse(result)
		resp["subscription"] = true
		writeJSON(w, http.StatusOK, resp)
		return
	}

	result, err := s.importer.ImportFromText(text)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tags":      result.Tags,
		"restarted": result.Restarted,
	})
}
