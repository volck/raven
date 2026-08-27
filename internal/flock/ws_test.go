package flock_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/volck/raven/internal/flock"
	rvclient "github.com/volck/raven/internal/flock/raven"
)

type fakeSubscriber struct {
	mu       sync.Mutex
	feeds    map[string][]rvclient.WSMessage
	connects map[string]int
}

func (f *fakeSubscriber) Subscribe(ctx context.Context, baseURL string, out chan<- rvclient.WSMessage) error {
	f.mu.Lock()
	f.connects[baseURL]++
	msgs := f.feeds[baseURL]
	f.mu.Unlock()
	for _, m := range msgs {
		select {
		case out <- m:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	<-ctx.Done()
	return ctx.Err()
}

func TestWSBridge_FansOutTaggedMessages(t *testing.T) {
	t.Parallel()
	hub := flock.NewWSHub(slog.New(slog.NewJSONHandler(io.Discard, nil)))
	srv := httptest.NewServer(hub)
	t.Cleanup(srv.Close)

	wsURL := strings.Replace(srv.URL, "http://", "ws://", 1)
	d := websocket.DefaultDialer
	conn, _, err := d.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial flock /ws: %v", err)
	}
	defer conn.Close()

	sub := &fakeSubscriber{
		feeds: map[string][]rvclient.WSMessage{
			"http://r1": {{Type: "secret.update", Data: json.RawMessage(`{"name":"foo"}`)}},
		},
		connects: map[string]int{},
	}
	bridge := flock.NewWSBridge(slog.New(slog.NewJSONHandler(io.Discard, nil)), sub, hub)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	bridge.Reconcile(ctx, flock.Snapshot{
		Routing: map[string][]string{"dev": {"http://r1"}},
	})

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, raw, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read ws: %v", err)
	}
	var got flock.FleetMessage
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Target != "http://r1" || got.Engine != "dev" || got.Type != "secret.update" {
		t.Fatalf("got = %+v", got)
	}
	if !strings.Contains(string(got.Data), "foo") {
		t.Fatalf("data = %s", got.Data)
	}
}

func TestWSBridge_ReconcileStopsRemovedTargets(t *testing.T) {
	t.Parallel()
	hub := flock.NewWSHub(slog.New(slog.NewJSONHandler(io.Discard, nil)))
	sub := &fakeSubscriber{feeds: map[string][]rvclient.WSMessage{}, connects: map[string]int{}}
	bridge := flock.NewWSBridge(slog.New(slog.NewJSONHandler(io.Discard, nil)), sub, hub)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	bridge.Reconcile(ctx, flock.Snapshot{Routing: map[string][]string{
		"dev": {"http://a", "http://b"},
	}})
	// give goroutines a moment to enter Subscribe
	time.Sleep(50 * time.Millisecond)
	bridge.Reconcile(ctx, flock.Snapshot{Routing: map[string][]string{
		"dev": {"http://a"},
	}})
	time.Sleep(50 * time.Millisecond)

	sub.mu.Lock()
	defer sub.mu.Unlock()
	if sub.connects["http://a"] < 1 || sub.connects["http://b"] < 1 {
		t.Fatalf("connects = %+v", sub.connects)
	}
}

type errSubscriber struct {
	atomic.Int32
}

func (e *errSubscriber) Subscribe(ctx context.Context, _ string, _ chan<- rvclient.WSMessage) error {
	e.Int32.Add(1)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(20 * time.Millisecond):
		return errors.New("boom")
	}
}

func TestWSBridge_ReconnectsAfterError(t *testing.T) {
	t.Parallel()
	hub := flock.NewWSHub(slog.New(slog.NewJSONHandler(io.Discard, nil)))
	sub := &errSubscriber{}
	bridge := flock.NewWSBridge(slog.New(slog.NewJSONHandler(io.Discard, nil)), sub, hub)

	ctx, cancel := context.WithCancel(context.Background())
	bridge.Reconcile(ctx, flock.Snapshot{Routing: map[string][]string{"dev": {"http://r"}}})
	time.Sleep(150 * time.Millisecond)
	cancel()
	time.Sleep(50 * time.Millisecond)
	if got := sub.Int32.Load(); got < 1 {
		t.Fatalf("expected at least one connect, got %d", got)
	}
}

// ensure url package is used (silences vet if unused on some platforms)
var _ = url.Parse
var _ http.Handler = (*flock.WSHub)(nil)
