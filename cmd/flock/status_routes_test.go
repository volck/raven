package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/volck/raven/internal/flock"
	rvclient "github.com/volck/raven/internal/flock/raven"
)

func devSnapWithTargets(targets ...string) *fakeSnap {
	return &fakeSnap{ready: true, snap: flock.Snapshot{
		Engines: []string{"dev"},
		Routing: map[string][]string{"dev": targets},
	}}
}

func TestAllStatus_OK(t *testing.T) {
	t.Parallel()
	snap := &fakeSnap{ready: true}
	status := &fakeStatus{
		all: []flock.TargetStatus{
			{Target: "https://r1", Status: rvclient.Status{Engine: "dev", SecretCount: 3}},
		},
	}
	srv := newRoutedServerFull(t, snap, &fakeHealth{}, &fakeEvents{}, status)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var got []map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&got)
	if len(got) != 1 || got[0]["target"] != "https://r1" {
		t.Fatalf("got=%+v", got)
	}
}

func TestGetRavenStatus_OKAndNotFound(t *testing.T) {
	t.Parallel()
	snap := devSnapWithTargets("https://r1")
	status := &fakeStatus{
		byEngine: map[string][]flock.TargetStatus{
			"dev": {{Target: "https://r1", Status: rvclient.Status{Engine: "dev", SecretCount: 4}}},
		},
	}
	srv := newRoutedServerFull(t, snap, &fakeHealth{}, &fakeEvents{}, status)

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/ravens/dev/status", nil))
	if rec.Code != 200 {
		t.Fatalf("dev status=%d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/ravens/missing/status", nil))
	if rec.Code != 404 {
		t.Fatalf("missing status=%d want 404", rec.Code)
	}
}

func TestInventory_OK(t *testing.T) {
	t.Parallel()
	snap := &fakeSnap{ready: true}
	status := &fakeStatus{
		inv: []flock.InventoryEntry{
			{Engine: "dev", Target: "https://r1", Name: "foo.yaml", SecretName: "foo"},
			{Engine: "dev", Target: "https://r1", Name: "bar.yaml", SecretName: "bar"},
		},
	}
	srv := newRoutedServerFull(t, snap, &fakeHealth{}, &fakeEvents{}, status)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/inventory", nil))
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var got []map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&got)
	if len(got) != 2 {
		t.Fatalf("got %d", len(got))
	}
}

func TestGetRavenInventory_OKAndNotFound(t *testing.T) {
	t.Parallel()
	snap := devSnapWithTargets("https://r1")
	status := &fakeStatus{
		invByEng: map[string][]flock.InventoryEntry{
			"dev": {{Engine: "dev", Target: "https://r1", Name: "foo.yaml", SecretName: "foo"}},
		},
	}
	srv := newRoutedServerFull(t, snap, &fakeHealth{}, &fakeEvents{}, status)

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/ravens/dev/inventory", nil))
	if rec.Code != 200 {
		t.Fatalf("dev inv=%d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/ravens/missing/inventory", nil))
	if rec.Code != 404 {
		t.Fatalf("missing=%d want 404", rec.Code)
	}
}

func TestGetRavenSecret_OKAndNotFound(t *testing.T) {
	t.Parallel()
	snap := devSnapWithTargets("https://r1")
	status := &fakeStatus{
		bySecret: map[string][]flock.InventoryEntry{
			"dev/foo": {{Engine: "dev", Target: "https://r1", Name: "foo.yaml", SecretName: "foo"}},
		},
	}
	srv := newRoutedServerFull(t, snap, &fakeHealth{}, &fakeEvents{}, status)

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/ravens/dev/secrets/foo", nil))
	if rec.Code != 200 {
		t.Fatalf("found=%d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/ravens/dev/secrets/nope", nil))
	if rec.Code != 404 {
		t.Fatalf("missing secret=%d want 404", rec.Code)
	}

	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/ravens/missing/secrets/foo", nil))
	if rec.Code != 404 {
		t.Fatalf("missing engine=%d want 404", rec.Code)
	}
}
