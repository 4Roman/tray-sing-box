package app

import (
	"errors"
	"strings"
	"testing"

	"tray-sing-box/internal/domain"
)

// A refresh after which only the VPN restart failed has recorded its new
// problems as reported: the popups — the unattended one and the one of a
// refresh from the tray — show them with the error. A refresh that failed
// itself shows its error alone (tray) or nothing (unattended).
func TestSubscriptionPopupsAfterAFailedRestart(t *testing.T) {
	restartErr := errors.New("подписки обновлены, но VPN restart failed on start: TUN setup failed")
	result := &domain.SubscriptionResult{
		Updates: []domain.SubscriptionUpdate{{
			URL: "https://p.example/sub", Tags: []string{"a"}, NewProblem: true,
			Skipped: []domain.SkippedNode{{Name: "bad", Reason: "тип «tor» не поддерживается"}},
		}},
		RestartErr: restartErr,
	}

	report := autoRefreshText(result, restartErr)
	if !strings.Contains(report, "«bad» — тип «tor» не поддерживается") || !strings.Contains(report, "TUN setup failed") {
		t.Fatalf("unattended report = %q", report)
	}
	text, failed := subscriptionOutcome(result, restartErr)
	if !failed || !strings.Contains(text, "«bad» — тип «tor» не поддерживается") || !strings.Contains(text, "TUN setup failed") {
		t.Fatalf("tray popup = %q (error: %v)", text, failed)
	}

	// The refresh itself failed (the list could not be saved): nothing of
	// it was recorded, the next refresh reports it
	saveErr := errors.New("failed to write subscriptions: disk full")
	result.RestartErr = nil
	if report := autoRefreshText(result, saveErr); report != "" {
		t.Fatalf("unattended report of a failed refresh = %q", report)
	}
	if text, failed := subscriptionOutcome(result, saveErr); !failed || text != saveErr.Error() {
		t.Fatalf("tray popup of a failed refresh = %q (error: %v)", text, failed)
	}
	if report := autoRefreshText(nil, errors.New("broken file")); report != "" {
		t.Fatalf("unattended report without a result = %q", report)
	}

	// Done: the result, not an error
	if text, failed := subscriptionOutcome(result, nil); failed || !strings.Contains(text, "«bad»") {
		t.Fatalf("tray popup = %q (error: %v)", text, failed)
	}
}

// The active server may be a subscription's node, named by its provider:
// the name stays on one line of the popup
func TestDPIMessageNamesTheServerOnOneLine(t *testing.T) {
	got := dpiMessage(&domain.DPIBypassStatus{ChainActive: true, ChainTarget: "DE-1\n\nПодписка истекла"})
	if strings.Contains(got, "\n") || !strings.Contains(got, "«DE-1  Подписка истекла»") {
		t.Fatalf("message = %q", got)
	}
}
