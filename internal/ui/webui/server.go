// Package webui serves the local settings interface: raw JSON editing of
// config sections, outbound switching and share-link import. The server
// listens on 127.0.0.1 only; the browser gets in with a one-time login code
// and then carries a session secret in a request header (see handleLogin).
package webui

import (
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"slices"
	"sync"
	"time"

	"tray-sing-box/internal/config"
	"tray-sing-box/internal/domain"
)

//go:embed page.html
var pageHTML string

// settingsPage is page.html; its only variable is the session secret of a
// page served by /login ("" for GET /)
var settingsPage = template.Must(template.New("page").Parse(pageHTML))

const (
	// sessionHeader carries the session secret on every API request
	sessionHeader = "X-Session"

	maxPendingCodes = 4 // unused login codes kept; another one drops the oldest
	maxSessions     = 8 // live sessions; another login evicts the one idle longest
)

// contentSecurityPolicy goes out with every response. The page is static,
// renders everything it fetches through textContent and uses inline script,
// styles and onclick attributes — allowed explicitly; nothing else loads,
// fetch reaches this server only, and nothing may frame the page.
const contentSecurityPolicy = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; " +
	"connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"

// loginCode is an issued login code that has not been used yet
type loginCode struct {
	hash   string // hashSecret of the code
	issued time.Time
}

// session is a browser tab that logged in with a code
type session struct {
	code     string // hashSecret of the login code that created it
	created  time.Time
	lastSeen time.Time
}

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
	app      *domain.AppUpdateService // nil: self-update not configured
	relaunch func()                   // quits into the installed version
	dpi      *domain.DPIBypassService
	subs     *domain.SubscriptionService
	conn     *domain.ConnectivityService
	sources  Sources
	logs     LogAccess

	mu       sync.Mutex
	opMu     *sync.Mutex         // serializes config/binary mutations, see ShareOpLock
	base     string              // "http://127.0.0.1:<port>" once listening
	now      func() time.Time    // the clock of codes and sessions (tests move it)
	codes    []loginCode         // pending login codes, oldest first
	sessions map[string]*session // by hashSecret of the session secret
}

// New creates the settings server (not yet listening)
func New(settings *domain.SettingsService, importer *domain.ImportService, updater *domain.UpdateService, dpi *domain.DPIBypassService, subs *domain.SubscriptionService, conn *domain.ConnectivityService, sources Sources, logs LogAccess) *Server {
	return &Server{
		settings: settings,
		importer: importer,
		updater:  updater,
		dpi:      dpi,
		subs:     subs,
		conn:     conn,
		sources:  sources,
		logs:     logs,
		opMu:     &sync.Mutex{},
		now:      time.Now,
		sessions: map[string]*session{},
	}
}

// SetAppUpdater enables self-update of the application from the page.
// relaunch is called (from a goroutine, after the response) when the user
// asks to restart into an installed update.
func (s *Server) SetAppUpdater(svc *domain.AppUpdateService, relaunch func()) {
	s.app = svc
	s.relaunch = relaunch
}

// ShareOpLock makes the server serialize its long operations with another
// entry point (the tray handlers): an import from the browser and a binary
// update from the tray must not interleave. Call before Open.
func (s *Server) ShareOpLock(mu *sync.Mutex) {
	s.opMu = mu
}

// Open starts the server if needed and opens the settings page in the browser
// with a new one-time login code. Every call issues its own: the URL is
// readable by any program of the user (the command lines of rundll32 and
// the browser, the browser history), so it must be worthless once used.
func (s *Server) Open() error {
	base, err := s.start()
	if err != nil {
		return err
	}
	code, err := s.issueCode()
	if err != nil {
		return err
	}
	return openBrowser(base + "/login?code=" + code)
}

// start launches the HTTP listener once and returns its base URL
func (s *Server) start() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.base != "" {
		return s.base, nil
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("failed to listen: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.handlePage)
	mux.HandleFunc("GET /login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.handleLogout)
	mux.HandleFunc("GET /api/session", s.auth(s.handleSession))
	mux.HandleFunc("GET /api/config", s.auth(s.handleConfig))
	mux.HandleFunc("POST /api/section", s.auth(s.handleSaveSection))
	mux.HandleFunc("POST /api/switch", s.auth(s.handleSwitch))
	mux.HandleFunc("POST /api/vpn", s.auth(s.handleVPN))
	mux.HandleFunc("POST /api/import", s.auth(s.handleImport))
	mux.HandleFunc("POST /api/update", s.auth(s.handleUpdate))
	mux.HandleFunc("GET /api/app-update", s.auth(s.handleAppUpdateCheck))
	mux.HandleFunc("POST /api/app-update", s.auth(s.handleAppUpdate))
	mux.HandleFunc("POST /api/app-update/relaunch", s.auth(s.handleAppRelaunch))
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

	addr := listener.Addr().String()
	handler := guard(addr, mux)
	go func() {
		if err := http.Serve(listener, handler); err != nil {
			log.Printf("Settings server stopped: %v", err)
		}
	}()

	s.base = "http://" + addr
	log.Printf("Settings server listening on %s", addr)
	return s.base, nil
}

// guard wraps every request: security headers on every response, and the
// Host check. A web site whose name resolves to 127.0.0.1 (DNS rebinding)
// would reach this server as its own origin; its requests name that site in
// Host, while the settings page's name 127.0.0.1:<port>.
func guard(addr string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		if r.Host != addr {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// issueCode creates a one-time login code, valid for
// config.WebLoginCodeSeconds. At most maxPendingCodes wait for their use.
func (s *Server) issueCode() (string, error) {
	code, err := randomHex()
	if err != nil {
		return "", fmt.Errorf("failed to generate a login code: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
	if len(s.codes) >= maxPendingCodes {
		s.codes = slices.Delete(s.codes, 0, 1)
	}
	s.codes = append(s.codes, loginCode{hash: hashSecret(code), issued: s.now()})
	return code, nil
}

// loginErrorPage explains a refused login code
var loginErrorPage = template.Must(template.New("login-error").Parse(`<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8"><title>Настройки sing-box</title></head>
<body style="background:#16181d;color:#e4e6eb;font-family:'Segoe UI',system-ui,sans-serif;max-width:680px;margin:40px auto;padding:0 24px;line-height:1.5">
<h1 style="font-size:22px">Настройки sing-box</h1>
<p>{{.}}</p>
</body></html>`))

const (
	loginUsedMsg = "Эта ссылка для входа уже была использована. Если вы не открывали её дважды, " +
		"её могла перехватить другая программа — сеанс, открытый по ней, закрыт. " +
		"Откройте «Настройки» из меню значка в трее заново."
	loginExpiredMsg = "Ссылка для входа устарела или недействительна. " +
		"Откройте «Настройки» из меню значка в трее заново."
)

// handleLogin trades a login code for a session: the answer is the settings
// page itself with the session secret in a script variable. It lives only in
// that page's memory and travels in the X-Session header. Not in a cookie:
// cookies are not port-scoped, a cookie for 127.0.0.1 would be sent to every
// local server, one run by any program of the user included. Not in
// sessionStorage or localStorage either: browsers write both into the
// profile on disk within seconds (Chromium's "Session Storage" LevelDB, in
// plain text), where any program of the user reads it — and a session taken
// from there would never trip the replay check below. The page takes
// /login?code= out of the address bar (history.replaceState); a reload shows
// the "open from the tray" notice, and closing the page ends the session
// (/api/logout).
//
// A code that arrives a second time was in two hands — read off a command
// line or the history, it raced the browser. Which of the two came first
// cannot be known, so the session created with it is closed and the user is
// told to open the settings again.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	// A speculative load (the browser prefetching or prerendering an address
	// from its history) must neither use a code nor count as its replay —
	// that would close the session of the tab the user is working in
	if r.Header.Get("Sec-Purpose") != "" || r.Header.Get("Purpose") == "prefetch" || r.Header.Get("X-Moz") == "prefetch" {
		http.Error(w, "no speculative loads", http.StatusServiceUnavailable)
		return
	}

	code := r.URL.Query().Get("code")
	secret, err := randomHex()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	var ok, replayed bool
	s.mu.Lock()
	s.pruneLocked()
	if code != "" {
		hash := hashSecret(code)
		if i := slices.IndexFunc(s.codes, func(c loginCode) bool { return c.hash == hash }); i >= 0 {
			s.codes = slices.Delete(s.codes, i, i+1)
			s.addSessionLocked(hashSecret(secret), hash)
			ok = true
		} else {
			for id, sess := range s.sessions {
				if sess.code == hash {
					delete(s.sessions, id)
					replayed = true
				}
			}
		}
	}
	s.mu.Unlock()

	switch {
	case ok:
		renderPage(w, secret)
	case replayed:
		log.Printf("Settings: a login link was used a second time, the session opened with it is closed (another program may have read the link)")
		loginError(w, loginUsedMsg)
	default:
		loginError(w, loginExpiredMsg)
	}
}

// loginError answers a refused login code
func loginError(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	if err := loginErrorPage.Execute(w, message); err != nil {
		log.Printf("Settings login error page render failed: %v", err)
	}
}

// auth requires a live session in the X-Session header. A missing or ended
// one gets 401 with a JSON error: the page then tells the user to open the
// settings from the tray again.
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.touchSession(r.Header.Get(sessionHeader)) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "сессия завершена — откройте «Настройки» из трея заново",
			})
			return
		}
		next(w, r)
	}
}

// touchSession reports whether secret belongs to a live session and marks
// that session as used now
func (s *Server) touchSession(secret string) bool {
	if secret == "" {
		return false
	}
	id := hashSecret(secret)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
	sess, ok := s.sessions[id]
	if ok {
		sess.lastSeen = s.now()
	}
	return ok
}

// addSessionLocked registers a session; at maxSessions the one idle longest
// is evicted. Callers hold s.mu.
func (s *Server) addSessionLocked(id, codeHash string) {
	if len(s.sessions) >= maxSessions {
		oldest := ""
		for k, sess := range s.sessions {
			if oldest == "" || sess.lastSeen.Before(s.sessions[oldest].lastSeen) {
				oldest = k
			}
		}
		delete(s.sessions, oldest)
	}
	now := s.now()
	s.sessions[id] = &session{code: codeHash, created: now, lastSeen: now}
}

// pruneLocked drops expired login codes and sessions (idle for
// config.WebSessionIdleMinutes, or older than config.WebSessionMaxHours).
// Callers hold s.mu.
func (s *Server) pruneLocked() {
	now := s.now()
	s.codes = slices.DeleteFunc(s.codes, func(c loginCode) bool {
		return now.Sub(c.issued) >= config.WebLoginCodeSeconds*time.Second
	})
	for id, sess := range s.sessions {
		if now.Sub(sess.lastSeen) >= config.WebSessionIdleMinutes*time.Minute ||
			now.Sub(sess.created) >= config.WebSessionMaxHours*time.Hour {
			delete(s.sessions, id)
		}
	}
}

// randomHex returns 32 random bytes as hex: a login code or a session secret
func randomHex() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// hashSecret is the form codes and secrets are kept and looked up in: the
// map lookups and comparisons then never run over the secret itself, so
// their timing tells nothing about it
func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// handlePage serves the settings page without a session (a reload, a
// bookmark): it tells the user to open the settings from the tray
func (s *Server) handlePage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	renderPage(w, "")
}

// renderPage writes the settings page with the given session secret
func renderPage(w http.ResponseWriter, session string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := settingsPage.Execute(w, map[string]string{"Session": session}); err != nil {
		log.Printf("Settings page render failed: %v", err)
	}
}

// handleLogout ends the session whose secret is the request body. The page
// sends it when it goes away (navigator.sendBeacon cannot set headers): a
// session outlives no page. Knowing the secret is the authority to end it.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	secret, err := io.ReadAll(io.LimitReader(r.Body, 256))
	if err == nil && len(secret) > 0 {
		id := hashSecret(string(secret))
		s.mu.Lock()
		delete(s.sessions, id)
		s.mu.Unlock()
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleSession answers the page's keep-alive: typing into the editors makes
// no other request, and the idle expiry must not end a session the user is
// working in (auth has already marked it as used)
func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
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

	// One observation for both fields. "status" adds "starting" (the app is
	// still bringing the VPN up) to what the boolean can say.
	status := s.settings.VPNStatus()
	resp := map[string]any{
		"outbounds": outbounds,
		"route":     route,
		"list":      list,
		"active":    active,
		"running":   status.IsRunning(),
		"status":    status.String(),
	}
	if s.conn != nil {
		resp["connectivity"] = s.conn.Status()
	}
	writeJSON(w, http.StatusOK, resp)
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

	// Config edits take the operation lock too: a save from the browser must
	// not interleave with a binary update or a subscription sync started from
	// the tray (the lock is shared, see ShareOpLock)
	s.opMu.Lock()
	defer s.opMu.Unlock()

	restarted, err := s.settings.SaveSection(req.Name, []byte(req.Content))
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"restarted": restarted})
}

// handleVPN starts or stops the VPN as asked. Like the tray toggle it takes
// no opMu: the process life cycle is serialized inside VPNService, and a
// "stop" must not queue behind a long download.
func (s *Server) handleVPN(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Running bool `json:"running"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, fmt.Errorf("bad request: %w", err))
		return
	}

	if err := s.settings.SetVPN(req.Running); err != nil {
		fail(w, err)
		return
	}
	status := s.settings.VPNStatus()
	writeJSON(w, http.StatusOK, map[string]any{
		"running": status.IsRunning(),
		"status":  status.String(),
	})
}

func (s *Server) handleSwitch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Tag string `json:"tag"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, fmt.Errorf("bad request: %w", err))
		return
	}

	s.opMu.Lock()
	defer s.opMu.Unlock()

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

// handleAppUpdateCheck reports the running version and the latest release
func (s *Server) handleAppUpdateCheck(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{"version": config.Version, "configured": s.app != nil}
	if s.app == nil {
		writeJSON(w, http.StatusOK, resp)
		return
	}
	// A pending relaunch is reported even when GitHub is unreachable: the
	// page must still offer the "restart into the new version" button
	resp["installed"] = s.app.Installed()
	if v := s.app.InstalledVersion(); v != "" {
		resp["latest"] = v
		resp["available"] = true
		writeJSON(w, http.StatusOK, resp)
		return
	}
	result, err := s.app.Check()
	if err != nil {
		resp["error"] = err.Error()
		writeJSON(w, http.StatusOK, resp)
		return
	}
	resp["latest"] = result.LatestVersion
	resp["available"] = result.Available
	resp["notes"] = result.Notes
	writeJSON(w, http.StatusOK, resp)
}

// handleAppUpdate downloads and installs the latest release; the relaunch
// is a separate call so the page can ask first
func (s *Server) handleAppUpdate(w http.ResponseWriter, r *http.Request) {
	if s.app == nil {
		fail(w, fmt.Errorf("автообновление приложения не настроено в этой сборке"))
		return
	}

	s.opMu.Lock()
	defer s.opMu.Unlock()

	result, err := s.app.Update()
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":   result.CurrentVersion,
		"latest":    result.LatestVersion,
		"available": result.Available,
		"installed": result.Installed,
	})
}

// handleAppRelaunch restarts the application into an installed update. The
// response goes out first; the process then exits and the page loses its
// server (new port and a new login on the next start).
func (s *Server) handleAppRelaunch(w http.ResponseWriter, r *http.Request) {
	if s.app == nil || s.relaunch == nil {
		fail(w, fmt.Errorf("автообновление приложения не настроено в этой сборке"))
		return
	}
	if !s.app.Installed() {
		fail(w, fmt.Errorf("обновление ещё не установлено"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"relaunching": true})
	go func() {
		time.Sleep(500 * time.Millisecond) // let the response reach the page
		s.relaunch()
	}()
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

// subscriptionEntry names a subscription on the page: by its ID and the
// redacted URL. The URL itself carries the provider's access token and never
// leaves the elevated process — a program of the user can drive this API.
func subscriptionEntry(rawURL string) map[string]any {
	return map[string]any{"id": domain.SubscriptionID(rawURL), "display": domain.RedactURL(rawURL)}
}

// subscriptionResponse converts a domain result into the JSON shape the page
// renders (errors become strings)
func subscriptionResponse(result *domain.SubscriptionResult) map[string]any {
	updates := make([]map[string]any, 0, len(result.Updates))
	for _, u := range result.Updates {
		entry := subscriptionEntry(u.URL)
		entry["count"] = len(u.Tags)
		entry["added"] = len(u.Added)
		entry["removed"] = len(u.Removed)
		if u.Err != nil {
			entry["error"] = u.Err.Error()
		}
		updates = append(updates, entry)
	}
	return map[string]any{"updates": updates, "restarted": result.Restarted}
}

// subscriptionURL finds the saved URL behind a subscription ID. Callers hold
// opMu, which every subscription change takes: the list cannot change
// between this lookup and the operation.
func (s *Server) subscriptionURL(id string) (string, error) {
	subs, err := s.subs.List()
	if err != nil {
		return "", err
	}
	for _, sub := range subs {
		if domain.SubscriptionID(sub.URL) == id {
			return sub.URL, nil
		}
	}
	return "", fmt.Errorf("подписка не найдена — обновите страницу")
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
		entry := subscriptionEntry(sub.URL)
		entry["count"] = len(sub.Tags)
		if !sub.Updated.IsZero() {
			entry["updated"] = sub.Updated
		}
		list = append(list, entry)
	}
	writeJSON(w, http.StatusOK, map[string]any{"subscriptions": list})
}

// handleSubscriptionAdd registers the URL the user typed; the answer names
// it only in the redacted form
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

// handleSubscriptionUpdate refreshes one subscription (id set) or all
func (s *Server) handleSubscriptionUpdate(w http.ResponseWriter, r *http.Request) {
	if s.subs == nil {
		fail(w, fmt.Errorf("подписки недоступны"))
		return
	}
	var req struct {
		ID string `json:"id"`
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
	if req.ID == "" {
		result, err = s.subs.UpdateAll()
	} else {
		var rawURL string
		if rawURL, err = s.subscriptionURL(req.ID); err == nil {
			result, err = s.subs.Update(rawURL)
		}
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
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, fmt.Errorf("bad request: %w", err))
		return
	}

	s.opMu.Lock()
	defer s.opMu.Unlock()

	rawURL, err := s.subscriptionURL(req.ID)
	if err != nil {
		fail(w, err)
		return
	}
	result, err := s.subs.Remove(rawURL)
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

	s.opMu.Lock()
	defer s.opMu.Unlock()

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
