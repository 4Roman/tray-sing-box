package domain

import (
	"errors"
	"testing"
)

type fakeParser struct {
	tags []string
	err  error
}

func (f *fakeParser) Parse(text string) ([]map[string]any, error) {
	if f.err != nil {
		return nil, f.err
	}
	outbounds := make([]map[string]any, len(f.tags))
	for i, tag := range f.tags {
		outbounds[i] = map[string]any{"tag": tag, "type": "vless"}
	}
	return outbounds, nil
}

type fakeEditor struct {
	added []map[string]any
	err   error
}

func (f *fakeEditor) AddOutbounds(outbounds []map[string]any) error {
	if f.err != nil {
		return f.err
	}
	f.added = append(f.added, outbounds...)
	return nil
}

func TestImportFromTextStoppedVPNNoRestart(t *testing.T) {
	pm := &fakeProcessManager{}
	svc := NewVPNService(pm, &fakeStorage{})
	editor := &fakeEditor{}
	imp := NewImportService(&fakeParser{tags: []string{"node-1", "node-2"}}, editor, svc)

	result, err := imp.ImportFromText("vless://...")
	if err != nil {
		t.Fatalf("ImportFromText: %v", err)
	}
	if len(result.Tags) != 2 || result.Tags[0] != "node-1" || result.Restarted {
		t.Fatalf("result = %+v", result)
	}
	if len(editor.added) != 2 {
		t.Fatalf("outbounds not added: %v", editor.added)
	}
	if pm.IsRunning() {
		t.Fatal("VPN must stay stopped")
	}
}

func TestImportFromTextRunningVPNRestarts(t *testing.T) {
	pm := &fakeProcessManager{running: true}
	svc := NewVPNService(pm, &fakeStorage{state: true})
	imp := NewImportService(&fakeParser{tags: []string{"node-2"}}, &fakeEditor{}, svc)

	result, err := imp.ImportFromText("vless://...")
	if err != nil {
		t.Fatalf("ImportFromText: %v", err)
	}
	if !result.Restarted {
		t.Fatal("VPN was not restarted")
	}
	if !pm.IsRunning() {
		t.Fatal("VPN must be running after restart")
	}
}

func TestImportFromTextParserErrorDoesNotTouchConfig(t *testing.T) {
	editor := &fakeEditor{}
	imp := NewImportService(&fakeParser{err: errors.New("bad link")}, editor, NewVPNService(&fakeProcessManager{}, &fakeStorage{}))

	if _, err := imp.ImportFromText("garbage"); err == nil {
		t.Fatal("expected parse error")
	}
	if len(editor.added) != 0 {
		t.Fatal("config must not be modified on parse error")
	}
}

func TestImportFromTextEditorError(t *testing.T) {
	imp := NewImportService(&fakeParser{tags: []string{"x"}}, &fakeEditor{err: errors.New("disk full")}, NewVPNService(&fakeProcessManager{}, &fakeStorage{}))

	if _, err := imp.ImportFromText("vless://..."); err == nil {
		t.Fatal("expected editor error")
	}
}
