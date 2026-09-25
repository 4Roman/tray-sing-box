package domain

import (
	"bytes"
	"errors"
	"log"
	"strconv"
	"strings"
	"testing"
)

// refusingStore refuses every write, as the guard or `sing-box check` would
type refusingStore struct{ err error }

func (f refusingStore) ReadSection(string) (string, error)     { return "", nil }
func (f refusingStore) WriteSection(string, []byte) error      { return f.err }
func (f refusingStore) ListOutbounds() ([]OutboundInfo, error) { return nil, nil }
func (f refusingStore) ActiveOutbound() (string, error)        { return "", nil }
func (f refusingStore) SwitchOutbound(string) error            { return f.err }
func (f refusingStore) ListHistory() ([]ConfigVersion, error)  { return nil, nil }
func (f refusingStore) RestoreVersion(string) error            { return f.err }
func (f refusingStore) CreateConfig([]byte) error              { return f.err }

// A refused change leaves a trace in the log: the settings page is reachable
// by any program of the user, and the page is the only other place the
// refusal shows
func TestRefusedConfigChangesAreLogged(t *testing.T) {
	var logs bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(prev)

	refusal := errors.New("уберите из конфига: clash_api.external_controller")
	svc := NewSettingsService(refusingStore{err: refusal}, NewVPNService(&fakeProcessManager{}, &fakeStorage{}))

	if _, err := svc.SaveSection("route", []byte(`{}`)); !errors.Is(err, refusal) {
		t.Fatalf("SaveSection: %v", err)
	}
	if _, err := svc.UseOutbound("proxy"); !errors.Is(err, refusal) {
		t.Fatalf("UseOutbound: %v", err)
	}
	if err := svc.CreateConfig([]byte(`{}`)); !errors.Is(err, refusal) {
		t.Fatalf("CreateConfig: %v", err)
	}
	if _, err := svc.Rollback("config-1.json"); !errors.Is(err, refusal) {
		t.Fatalf("Rollback: %v", err)
	}
	for _, want := range []string{
		`Settings: section "route" not saved: ` + refusal.Error(),
		`Settings: switch to "proxy" not saved: `,
		`Settings: initial config.json not saved: `,
		`Settings: rollback to "config-1.json" not saved: `,
	} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("log lacks %q:\n%s", want, logs.String())
		}
	}
	if strings.Contains(logs.String(), " saved"+eol) || strings.Contains(logs.String(), "switched active outbound") {
		t.Errorf("a refused change is logged as made:%s%s", eol, logs.String())
	}
}

const eol = string(rune(10))

// A key name in a refusal comes from the refused config: a line break in it
// must not start a line of its own in the log
func TestRefusalReasonStaysOnOneLine(t *testing.T) {
	var logs bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(prev)

	forged := "x" + eol + "2026/09/25 10:00:00 settings_service.go:67: Settings: section " + strconv.Quote("route") + " saved" + eol + "y_path"
	svc := NewSettingsService(refusingStore{err: errors.New("уберите из конфига: route.rules[0]." + forged)}, NewVPNService(&fakeProcessManager{}, &fakeStorage{}))
	if _, err := svc.SaveSection("route", []byte(`{}`)); err == nil {
		t.Fatal("SaveSection: no error")
	}
	if n := strings.Count(logs.String(), eol); n != 1 {
		t.Fatalf("one refusal made %d log lines:%s%s", n, eol, logs.String())
	}
	if !strings.Contains(logs.String(), "route.rules[0].x'") {
		t.Fatalf("the line break is not shown quoted: %s", logs.String())
	}
}
