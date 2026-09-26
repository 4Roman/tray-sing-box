package domain_test

import (
	"encoding/base64"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"tray-sing-box/internal/domain"
	"tray-sing-box/internal/infrastructure/sharelink"
)

// memSubStore keeps the subscription list in memory
type memSubStore struct{ subs []domain.Subscription }

func (m *memSubStore) Load() ([]domain.Subscription, error) {
	return append([]domain.Subscription(nil), m.subs...), nil
}

func (m *memSubStore) Save(subs []domain.Subscription) error {
	m.subs = subs
	return nil
}

// recordingSync saves every node it is given and records their tags
type recordingSync struct{ synced [][]string }

func (r *recordingSync) SyncOutbounds(owned []string, outbounds []map[string]any) (*domain.SyncResult, error) {
	var tags []string
	for _, o := range outbounds {
		tag, _ := o["tag"].(string)
		tags = append(tags, tag)
	}
	r.synced = append(r.synced, tags)
	return &domain.SyncResult{Tags: tags, Added: tags, Changed: true, NeedsRestart: true}, nil
}

// stoppedVPN: a VPN that is not running (nothing to restart)
type stoppedVPN struct{}

func (stoppedVPN) Start() error                { return nil }
func (stoppedVPN) Stop() error                 { return nil }
func (stoppedVPN) IsRunning() bool             { return false }
func (stoppedVPN) SaveVPNState(bool) error     { return nil }
func (stoppedVPN) LoadVPNState() (bool, error) { return false, nil }

// infoLink is 3x-ui's info entry ("sub info node", internal/sub/service.go
// getSubs): socks://127.0.0.1:1080 named with the client's traffic and days
// left, escaped as 3x-ui escapes it
func infoLink(remark string) string {
	return "socks://127.0.0.1:1080#" + strings.ReplaceAll(url.QueryEscape(remark), "+", "%20")
}

const (
	xuiUUID = "11111111-2222-4333-8444-555555555555"
	xuiPBK  = "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0"
)

func realityLink(host, name string) string {
	return "vless://" + xuiUUID + "@" + host + ":443?type=tcp&security=reality&pbk=" + xuiPBK +
		"&fp=chrome&sni=www.example.com&sid=6ba85179&spx=%2F&flow=xtls-rprx-vision&encryption=none#" + url.PathEscape(name)
}

// The bodies 3x-ui serves with its info entry on, through the real parser:
// the info entry never reaches the config, and an expired client's body — the
// info entry alone — saves nothing, keeps the servers and says why
func TestSubscription3xuiInfoNode(t *testing.T) {
	const subURL = "https://panel.example/sub/abcdef"
	var body string
	fetch := func(string) (string, error) { return body, nil }
	store := &memSubStore{}
	sync := &recordingSync{}
	svc := domain.NewSubscriptionService(store, fetch, sharelink.Parser{}, sync, domain.NewVPNService(stoppedVPN{}, stoppedVPN{}))

	// A working client: base64 of the links, the info entry first
	body = base64.StdEncoding.EncodeToString([]byte(strings.Join([]string{
		infoLink("user-📊97.35GB/100GB-⏳29D"),
		realityLink("192.0.2.10", "DE-user"),
		realityLink("192.0.2.20", "NL-user"),
	}, "\n")))
	result, err := svc.Add(subURL)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if len(sync.synced) != 1 || !reflect.DeepEqual(sync.synced[0], []string{"DE-user", "NL-user"}) {
		t.Fatalf("synced %q", sync.synced)
	}
	if u := result.Updates[0]; len(u.Skipped) != 0 || u.NewProblem {
		t.Fatalf("update %+v", u)
	}

	// Expired: the info entry alone
	body = base64.StdEncoding.EncodeToString([]byte(infoLink("⛔ user | Expired")))
	_, err = svc.Update(subURL)
	if err == nil || !strings.HasPrefix(err.Error(), "в подписке нет серверов: ") || strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("expired body: %v", err)
	}
	if len(sync.synced) != 1 || !reflect.DeepEqual(store.subs[0].Tags, []string{"DE-user", "NL-user"}) {
		t.Fatalf("expired body synced %q, servers %q", sync.synced, store.subs[0].Tags)
	}

	// Renewed: the servers come back, still without the info entry
	body = base64.StdEncoding.EncodeToString([]byte(infoLink("user-📊100GB-⏳30D") + "\n" + realityLink("192.0.2.10", "DE-user")))
	if _, err := svc.Update(subURL); err != nil || len(sync.synced) != 2 || !reflect.DeepEqual(sync.synced[1], []string{"DE-user"}) {
		t.Fatalf("renewed: %v, synced %q", err, sync.synced)
	}

	// A plain import keeps a link to a local proxy: there it is the user's own
	outbounds, skipped, err := sharelink.Parser{}.Parse(infoLink("my local proxy"))
	if err != nil || len(skipped) != 0 || len(outbounds) != 1 || outbounds[0]["server"] != "127.0.0.1" {
		t.Fatalf("parsed %v, skipped %v, err %v", outbounds, skipped, err)
	}
}
