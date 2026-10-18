package webui

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"tray-sing-box/internal/domain"
)

// errNoLatency: the server runs without the latency test (SetLatency)
var errNoLatency = errors.New("проверка задержки недоступна")

// maxLatencyRequest bounds the body of POST /api/latency (two booleans)
const maxLatencyRequest = 1024

// SetLatency enables the latency test and "select the fastest" on the page.
// The service takes the operation lock itself, for the switch only: the
// handlers take none (a check runs up to half a minute, and it only reads).
func (s *Server) SetLatency(svc *domain.LatencyService) {
	s.latency = svc
}

// handleLatency runs a latency check, and with "select" the switch to the
// fastest server (with "confirm": the answer to the question it asked about
// a selector group). The page going away (the tab closed) ends the check:
// r.Context. The test URL is the app's constant — the request names nothing
// but the two choices, and a field it does not know is refused: a session
// holder (any program of the user may have one) must not have the elevated
// test instance fetch an address of its choosing. Nothing in the answer
// names the test instance's port or secret, or a server's address: the
// report carries tags, types, delays and notes.
func (s *Server) handleLatency(w http.ResponseWriter, r *http.Request) {
	if s.latency == nil {
		fail(w, errNoLatency)
		return
	}
	var req struct {
		Select  bool `json:"select"`
		Confirm bool `json:"confirm"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxLatencyRequest))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		fail(w, fmt.Errorf("bad request: %w", err))
		return
	}
	// Nothing may follow the request. Read to its end, the body also lets
	// the server watch the connection: r.Context ends when the client goes
	// away (a tab closed during the half-minute check) only once the body
	// is consumed — a body of a known length already is by Decode
	if _, err := dec.Token(); err != io.EOF {
		fail(w, errors.New("bad request: data after the request"))
		return
	}

	if !req.Select {
		report, err := s.latency.Test(r.Context())
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"report": report, "fastest": nil})
		return
	}
	report, outcome, err := s.latency.SelectFastest(r.Context(), req.Confirm)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"report": report, "fastest": outcome})
}

// handleLatencyLast answers the last report, whether the page or the tray
// asked for it (null before the first check)
func (s *Server) handleLatencyLast(w http.ResponseWriter, r *http.Request) {
	if s.latency == nil {
		fail(w, errNoLatency)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"report": s.latency.Last()})
}
