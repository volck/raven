package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/volck/raven/internal/flock"
	rvclient "github.com/volck/raven/internal/flock/raven"
)

type fakeSnap struct {
	snap  flock.Snapshot
	ready bool
}

func (f *fakeSnap) Snapshot() flock.Snapshot { return f.snap }
func (f *fakeSnap) Ready() bool              { return f.ready }

type fakeHealth struct {
	h map[string]flock.Health
}

func (f *fakeHealth) Health() map[string]flock.Health { return f.h }
func (f *fakeHealth) HealthFor(t string) (flock.Health, bool) {
	h, ok := f.h[t]
	return h, ok
}

type fakeEvents struct {
	all      []flock.TargetEvent
	byEngine map[string][]flock.TargetEvent
	byTarget map[string][]rvclient.Event
}

func (f *fakeEvents) All() []flock.TargetEvent { return f.all }
func (f *fakeEvents) ForEngine(name string, _ flock.Snapshot) []flock.TargetEvent {
	return f.byEngine[name]
}
func (f *fakeEvents) EventsForTarget(t string) []rvclient.Event {
	return f.byTarget[t]
}

type fakeStatus struct {
	all      []flock.TargetStatus
	byEngine map[string][]flock.TargetStatus
	byTarget map[string]flock.TargetStatus
	inv      []flock.InventoryEntry
	invByEng map[string][]flock.InventoryEntry
	bySecret map[string][]flock.InventoryEntry // key = engine+"/"+secret
}

func (f *fakeStatus) All() []flock.TargetStatus { return f.all }
func (f *fakeStatus) ForEngine(name string, _ flock.Snapshot) []flock.TargetStatus {
	return f.byEngine[name]
}
func (f *fakeStatus) StatusForTarget(t string) (flock.TargetStatus, bool) {
	s, ok := f.byTarget[t]
	return s, ok
}
func (f *fakeStatus) Inventory() []flock.InventoryEntry { return f.inv }
func (f *fakeStatus) InventoryForEngine(name string, _ flock.Snapshot) []flock.InventoryEntry {
	return f.invByEng[name]
}
func (f *fakeStatus) SecretDetail(engine, secret string, _ flock.Snapshot) []flock.InventoryEntry {
	return f.bySecret[engine+"/"+secret]
}

func newRoutedServer(t *testing.T, snap *fakeSnap, health *fakeHealth) http.Handler {
	t.Helper()
	return newRoutedServerWith(t, snap, health, &fakeEvents{})
}

func newRoutedServerWith(t *testing.T, snap *fakeSnap, health *fakeHealth, events *fakeEvents) http.Handler {
	t.Helper()
	return newRoutedServerFull(t, snap, health, events, &fakeStatus{})
}

func newRoutedServerFull(t *testing.T, snap *fakeSnap, health *fakeHealth, events *fakeEvents, status *fakeStatus) http.Handler {
	t.Helper()
	return newRoutedServerFullPipeline(t, snap, health, events, status, nil)
}

func newRoutedServerFullPipeline(t *testing.T, snap *fakeSnap, health *fakeHealth, events *fakeEvents, status *fakeStatus, pipeline PipelineSnapshotter) http.Handler {
	t.Helper()
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	ready := new(atomic.Bool)
	if snap.ready {
		ready.Store(true)
	}
	mux := http.NewServeMux()
	if pipeline == nil {
		pipeline = emptyPipeline{}
	}
	addRoutes(mux, logger, ready, snap, health, events, status, nil, pipeline)
	return mux
}

func TestListRavens_OK(t *testing.T) {
	t.Parallel()
	snap := &fakeSnap{ready: true, snap: flock.Snapshot{Engines: []string{"dev", "prod01"}}}
	srv := newRoutedServer(t, snap, &fakeHealth{})
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/ravens", nil))
	if rec.Code != 200 {
		t.Fatalf("status=%d", rec.Code)
	}
	var got []string
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 2 || got[0] != "dev" {
		t.Fatalf("got %v", got)
	}
}

func TestListRavens_NotReady(t *testing.T) {
	t.Parallel()
	snap := &fakeSnap{ready: false}
	srv := newRoutedServer(t, snap, &fakeHealth{})
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/ravens", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want 503", rec.Code)
	}
}

func TestGetRaven_OKAndNotFound(t *testing.T) {
	t.Parallel()
	snap := &fakeSnap{ready: true, snap: flock.Snapshot{
		Engines: []string{"dev"},
		Routing: map[string][]string{"dev": {"https://r1"}},
	}}
	srv := newRoutedServer(t, snap, &fakeHealth{})

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/ravens/dev", nil))
	if rec.Code != 200 {
		t.Fatalf("dev status=%d", rec.Code)
	}

	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/ravens/missing", nil))
	if rec.Code != 404 {
		t.Fatalf("missing status=%d want 404", rec.Code)
	}
}

func TestGetRavenHealth(t *testing.T) {
	t.Parallel()
	snap := &fakeSnap{ready: true, snap: flock.Snapshot{
		Routing: map[string][]string{"dev": {"https://r1", "https://r2"}},
	}}
	now := time.Now()
	health := &fakeHealth{h: map[string]flock.Health{
		"https://r1": {Healthy: true, CheckedAt: now},
		"https://r2": {Healthy: false, Error: "boom", CheckedAt: now},
	}}
	srv := newRoutedServer(t, snap, health)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/ravens/dev/health", nil))
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var got []map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d entries: %+v", len(got), got)
	}
}

func TestGetAllHealth(t *testing.T) {
	t.Parallel()
	snap := &fakeSnap{ready: true}
	now := time.Now()
	health := &fakeHealth{h: map[string]flock.Health{
		"https://r1": {Healthy: true, CheckedAt: now},
	}}
	srv := newRoutedServer(t, snap, health)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil))
	if rec.Code != 200 {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestGetAll(t *testing.T) {
	t.Parallel()
	snap := &fakeSnap{ready: true, snap: flock.Snapshot{
		Engines: []string{"dev"},
		Routing: map[string][]string{"dev": {"https://r1"}},
	}}
	now := time.Now()
	health := &fakeHealth{h: map[string]flock.Health{
		"https://r1": {Healthy: true, CheckedAt: now},
	}}
	srv := newRoutedServer(t, snap, health)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/all", nil))
	if rec.Code != 200 {
		t.Fatalf("status=%d", rec.Code)
	}
	var got map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := got["engines"]; !ok {
		t.Fatalf("missing engines: %+v", got)
	}
	if _, ok := got["routing"]; !ok {
		t.Fatalf("missing routing")
	}
	if _, ok := got["health"]; !ok {
		t.Fatalf("missing health")
	}
}

// E6 — wrong method returns 405 (handled by ServeMux from Go 1.22).
func TestPostNotAllowed(t *testing.T) {
	t.Parallel()
	snap := &fakeSnap{ready: true}
	srv := newRoutedServer(t, snap, &fakeHealth{})
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/ravens", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d want 405", rec.Code)
	}
}

func TestAllEvents_OK(t *testing.T) {
	t.Parallel()
	now := time.Now()
	snap := &fakeSnap{ready: true}
	events := &fakeEvents{
		all: []flock.TargetEvent{
			{Target: "https://r1", Event: rvclient.Event{Time: now, Path: "kv/a", Operation: "update"}},
			{Target: "https://r2", Event: rvclient.Event{Time: now.Add(-time.Minute), Path: "kv/b", Operation: "delete"}},
		},
	}
	srv := newRoutedServerWith(t, snap, &fakeHealth{}, events)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/events", nil))
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var got []map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 2 || got[0]["target"] != "https://r1" {
		t.Fatalf("got = %+v", got)
	}
}

func TestAllEvents_NotReady(t *testing.T) {
	t.Parallel()
	srv := newRoutedServer(t, &fakeSnap{ready: false}, &fakeHealth{})
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/events", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want 503", rec.Code)
	}
}

func TestGetRavenEvents_OKAndNotFound(t *testing.T) {
	t.Parallel()
	now := time.Now()
	snap := &fakeSnap{ready: true, snap: flock.Snapshot{
		Engines: []string{"dev"},
		Routing: map[string][]string{"dev": {"https://r1"}},
	}}
	events := &fakeEvents{
		byEngine: map[string][]flock.TargetEvent{
			"dev": {{Target: "https://r1", Event: rvclient.Event{Time: now, Path: "kv/a"}}},
		},
	}
	srv := newRoutedServerWith(t, snap, &fakeHealth{}, events)

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/ravens/dev/events", nil))
	if rec.Code != 200 {
		t.Fatalf("dev events status=%d body=%s", rec.Code, rec.Body.String())
	}
	var got []map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d entries", len(got))
	}

	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/ravens/missing/events", nil))
	if rec.Code != 404 {
		t.Fatalf("missing status=%d want 404", rec.Code)
	}
}
