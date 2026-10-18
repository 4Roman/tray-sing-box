package domain

import (
	"encoding/json"
	"testing"
	"time"
)

// The report and the outcome reach the settings page as JSON: the names the
// page reads, and nothing for what is not there (no delay without an answer)
func TestLatencyJSON(t *testing.T) {
	report := LatencyReport{
		Tested:   time.Date(2026, 10, 18, 12, 30, 0, 0, time.UTC),
		Answered: 1,
		Total:    2,
		Active:   "de-1",
		Fastest:  "de-1",
		Results: []LatencyResult{
			{Tag: "de-1", Type: "vless", DelayMs: 84, Status: LatencyOK, Eligible: true},
			{Tag: "relay", Type: "trojan", Status: LatencyTimeout, Note: "промежуточный узел"},
		},
	}
	got, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"tested":"2026-10-18T12:30:00Z","answered":1,"total":2,"active":"de-1","fastest":"de-1","results":[` +
		`{"tag":"de-1","type":"vless","delay_ms":84,"status":"ok","eligible":true},` +
		`{"tag":"relay","type":"trojan","status":"timeout","eligible":false,"note":"промежуточный узел"}]}`
	if string(got) != want {
		t.Errorf("report JSON\n got %s\nwant %s", got, want)
	}

	outcome := FastestOutcome{Tag: "nl-2", Previous: "de-1", DelayMs: 40, PrevMs: 120, Switched: true, DPIWas: "de-1", Message: "Выбран"}
	got, err = json.Marshal(outcome)
	if err != nil {
		t.Fatal(err)
	}
	want = `{"tag":"nl-2","previous":"de-1","delay_ms":40,"prev_ms":120,"switched":true,"restarted":false,"needs_confirm":false,"dpi_was":"de-1","message":"Выбран"}`
	if string(got) != want {
		t.Errorf("outcome JSON\n got %s\nwant %s", got, want)
	}
	got, err = json.Marshal(FastestOutcome{NeedsConfirm: true, Message: "Продолжить?"})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"switched":false,"restarted":false,"needs_confirm":true,"message":"Продолжить?"}`; string(got) != want {
		t.Errorf("outcome JSON\n got %s\nwant %s", got, want)
	}
}
