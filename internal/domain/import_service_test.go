package domain

import (
	"bytes"
	"errors"
	"log"
	"reflect"
	"strings"
	"testing"
)

type fakeParser struct {
	tags    []string
	skipped []SkippedNode
	err     error
}

func (f *fakeParser) Parse(text string) ([]map[string]any, []SkippedNode, error) {
	if f.err != nil {
		return nil, f.skipped, f.err
	}
	outbounds := make([]map[string]any, len(f.tags))
	for i, tag := range f.tags {
		outbounds[i] = map[string]any{"tag": tag, "type": "vless"}
	}
	return outbounds, f.skipped, nil
}

type fakeEditor struct {
	added     []map[string]any
	reserved  []string
	refuse    map[string]string // tag -> reason: left out as the config check would
	rename    map[string]string // tag -> tag it is saved under
	unchanged bool              // the config already held exactly these
	err       error
}

func (f *fakeEditor) AddOutbounds(outbounds []map[string]any, reserved []string) (*AddResult, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.reserved = reserved
	result := &AddResult{}
	for _, o := range outbounds {
		tag, _ := o["tag"].(string)
		if reason, refused := f.refuse[tag]; refused {
			result.Skipped = append(result.Skipped, SkippedNode{Name: tag, Reason: reason})
			continue
		}
		if to, ok := f.rename[tag]; ok {
			result.Renamed = append(result.Renamed, TagRename{From: tag, To: to})
			tag = to
		}
		f.added = append(f.added, o)
		result.Tags = append(result.Tags, tag)
	}
	result.Changed = len(result.Tags) > 0 && !f.unchanged
	return result, nil
}

func TestImportFromTextStoppedVPNNoRestart(t *testing.T) {
	pm := &fakeProcessManager{}
	svc := NewVPNService(pm, &fakeStorage{})
	editor := &fakeEditor{}
	imp := NewImportService(&fakeParser{tags: []string{"node-1", "node-2"}}, editor, nil, svc)

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
	imp := NewImportService(&fakeParser{tags: []string{"node-2"}}, &fakeEditor{}, nil, svc)

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
	imp := NewImportService(&fakeParser{err: errors.New("bad link")}, editor, nil, NewVPNService(&fakeProcessManager{}, &fakeStorage{}))

	if _, err := imp.ImportFromText("garbage"); err == nil {
		t.Fatal("expected parse error")
	}
	if len(editor.added) != 0 {
		t.Fatal("config must not be modified on parse error")
	}
}

func TestImportFromTextEditorError(t *testing.T) {
	imp := NewImportService(&fakeParser{tags: []string{"x"}}, &fakeEditor{err: errors.New("disk full")}, nil, NewVPNService(&fakeProcessManager{}, &fakeStorage{}))

	if _, err := imp.ImportFromText("vless://..."); err == nil {
		t.Fatal("expected editor error")
	}
}

// The result names what was left out (by the parser and by the config
// check) and what was saved under another name; the tags are the saved ones
func TestImportReportsSkippedAndRenamed(t *testing.T) {
	parser := &fakeParser{
		tags:    []string{"ok", "direct", "bad"},
		skipped: []SkippedNode{{Name: "ss-obfs", Reason: "плагин obfs-local не поддерживается"}},
	}
	editor := &fakeEditor{
		refuse: map[string]string{"bad": "sing-box не принимает: unsupported flow: x"},
		rename: map[string]string{"direct": "direct (2)"},
	}
	imp := NewImportService(parser, editor, nil, NewVPNService(&fakeProcessManager{}, &fakeStorage{}))

	result, err := imp.ImportFromText("…")
	if err != nil {
		t.Fatalf("ImportFromText: %v", err)
	}
	if !reflect.DeepEqual(result.Tags, []string{"ok", "direct (2)"}) {
		t.Fatalf("tags = %v", result.Tags)
	}
	if !reflect.DeepEqual(result.Renamed, []TagRename{{From: "direct", To: "direct (2)"}}) {
		t.Fatalf("renamed = %v", result.Renamed)
	}
	want := []SkippedNode{
		{Name: "ss-obfs", Reason: "плагин obfs-local не поддерживается"},
		{Name: "bad", Reason: "sing-box не принимает: unsupported flow: x"},
	}
	if !reflect.DeepEqual(result.Skipped, want) {
		t.Fatalf("skipped = %v", result.Skipped)
	}
}

// The nodes of the subscriptions are reserved: an import never replaces them
func TestImportReservesSubscriptionNodes(t *testing.T) {
	store := &fakeSubStore{subs: []Subscription{
		{URL: "https://a.example/sub", Tags: []string{"a-1", "a-2"}},
		{URL: "https://b.example/sub", Tags: []string{"b-1"}},
	}}
	editor := &fakeEditor{}
	imp := NewImportService(&fakeParser{tags: []string{"x"}}, editor, store, NewVPNService(&fakeProcessManager{}, &fakeStorage{}))
	if _, err := imp.ImportFromText("…"); err != nil {
		t.Fatalf("ImportFromText: %v", err)
	}
	if !reflect.DeepEqual(editor.reserved, []string{"a-1", "a-2", "b-1"}) {
		t.Fatalf("reserved = %v", editor.reserved)
	}

	// An unreadable list (subscriptions.json damaged) does not block an
	// import: the worst it can do is replace a subscription's node, which
	// the next refresh puts back
	var logs bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(prev)
	store.loadErr = errors.New("unexpected end of JSON input")
	result, err := imp.ImportFromText("…")
	if err != nil || !reflect.DeepEqual(result.Tags, []string{"x"}) {
		t.Fatalf("import with an unreadable subscription list: %+v, %v", result, err)
	}
	if editor.reserved != nil {
		t.Fatalf("reserved = %v", editor.reserved)
	}
	if !strings.Contains(logs.String(), "the subscription list is unreadable") {
		t.Fatalf("not logged: %s", logs.String())
	}
}

// Nothing usable: the error lists every link with its reason, in Russian
func TestImportNothingUsable(t *testing.T) {
	parser := &fakeParser{
		err: errors.New("no link could be parsed"),
		skipped: []SkippedNode{
			{Name: "hy2-hop", Reason: "список портов не поддерживается"},
			{Name: "ссылка 2", Reason: "ссылка повреждена"},
		},
	}
	editor := &fakeEditor{}
	imp := NewImportService(parser, editor, nil, NewVPNService(&fakeProcessManager{}, &fakeStorage{}))
	_, err := imp.ImportFromText("…")
	if err == nil {
		t.Fatal("expected an error")
	}
	want := "ни один сервер не импортирован:\n«hy2-hop» — список портов не поддерживается\n«ссылка 2» — ссылка повреждена"
	if err.Error() != want {
		t.Fatalf("error = %q, want %q", err, want)
	}
	if editor.reserved != nil || len(editor.added) != 0 {
		t.Fatal("the config was touched")
	}

	// The config check refused every one: the same, and no restart
	pm := &fakeProcessManager{running: true}
	imp = NewImportService(&fakeParser{tags: []string{"a"}}, &fakeEditor{refuse: map[string]string{"a": "sing-box не принимает: x"}},
		nil, NewVPNService(pm, &fakeStorage{state: true}))
	_, err = imp.ImportFromText("…")
	if err == nil || !strings.Contains(err.Error(), "«a» — sing-box не принимает: x") {
		t.Fatalf("error = %v", err)
	}
	if pm.startCount() != 0 {
		t.Fatal("VPN restarted although nothing was imported")
	}
}

// Importing what the config already holds restarts nothing
func TestImportUnchangedDoesNotRestart(t *testing.T) {
	pm := &fakeProcessManager{running: true}
	imp := NewImportService(&fakeParser{tags: []string{"a"}}, &fakeEditor{unchanged: true}, nil, NewVPNService(pm, &fakeStorage{state: true}))
	result, err := imp.ImportFromText("…")
	if err != nil || result.Restarted || pm.startCount() != 0 {
		t.Fatalf("result %+v, err %v, starts %d", result, err, pm.startCount())
	}
}

func TestDescribeSkippedLimit(t *testing.T) {
	var skipped []SkippedNode
	for _, name := range []string{"a", "b", "c"} {
		skipped = append(skipped, SkippedNode{Name: name, Reason: "r"})
	}
	if got := DescribeSkipped(skipped, 2); got != "«a» — r\n«b» — r\n…и ещё 1" {
		t.Fatalf("DescribeSkipped = %q", got)
	}
	if got := DescribeSkipped(skipped, 0); strings.Count(got, "\n") != 2 {
		t.Fatalf("DescribeSkipped without a limit = %q", got)
	}
}
