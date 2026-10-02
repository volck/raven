package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/volck/raven/internal/flock"
	wrclient "github.com/volck/raven/internal/flock/wrangler"
)

type fakeRollouts struct {
	all      []wrclient.Rollout
	byEngine map[string][]wrclient.Rollout
}

func (f *fakeRollouts) Rollouts() []wrclient.Rollout { return f.all }
func (f *fakeRollouts) RolloutsForEngine(engine string) []wrclient.Rollout {
	return f.byEngine[engine]
}

func testRollout(engine, raven string, ok bool) wrclient.Rollout {
	return wrclient.Rollout{
		Time:      time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC),
		Raven:     raven,
		Engine:    engine,
		Namespace: "ssg",
		Succeeded: ok,
		Stages:    []wrclient.Stage{{Stage: "cluster", Status: "done"}},
	}
}

func rolloutServer(t *testing.T, rollouts RolloutSnapshotter) http.Handler {
	t.Helper()

	mux := http.NewServeMux()
	ready := &atomic.Bool{}
	ready.Store(true)

	snap := &fakeSnap{
		snap:  flock.Snapshot{Engines: []string{"kv"}, Routing: map[string][]string{"kv": {"https://ssg-dev"}}},
		ready: true,
	}
	addRolloutRoutes(mux, slog.New(slog.NewTextHandler(io.Discard, nil)), snap, rollouts)
	return mux
}

func TestHandleListRollouts(t *testing.T) {
	t.Parallel()

	rollouts := &fakeRollouts{all: []wrclient.Rollout{
		testRollout("kv", "ssg-dev", true),
		testRollout("prod01", "ssg-prod01", false),
	}}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/rollouts", nil)
	rec := httptest.NewRecorder()
	rolloutServer(t, rollouts).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var body struct {
		Rollouts []wrclient.Rollout `json:"rollouts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Rollouts) != 2 {
		t.Errorf("got %d rollouts, want 2", len(body.Rollouts))
	}
}

func TestHandleGetRavenRollouts(t *testing.T) {
	t.Parallel()

	rollouts := &fakeRollouts{byEngine: map[string][]wrclient.Rollout{
		"kv": {testRollout("kv", "ssg-dev", true)},
	}}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/ravens/kv/rollouts", nil)
	rec := httptest.NewRecorder()
	rolloutServer(t, rollouts).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var body struct {
		Rollouts []wrclient.Rollout `json:"rollouts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Rollouts) != 1 || body.Rollouts[0].Raven != "ssg-dev" {
		t.Errorf("unexpected body: %+v", body.Rollouts)
	}
}

// An engine flock does not know about is a 404, not an empty 200.
func TestHandleGetRavenRollouts_UnknownEngine(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/ravens/nope/rollouts", nil)
	rec := httptest.NewRecorder()
	rolloutServer(t, &fakeRollouts{}).ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

// Wrangler is optional; flock must still answer when it is not configured.
func TestHandleListRollouts_NotConfigured(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/rollouts", nil)
	rec := httptest.NewRecorder()
	rolloutServer(t, nil).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"rollouts":[]`) {
		t.Errorf("want an empty array, got %s", rec.Body)
	}
}

// Nil slices must serialise as [] so clients can iterate without a nil check.
func TestHandleListRollouts_EmptyIsAnArray(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/rollouts", nil)
	rec := httptest.NewRecorder()
	rolloutServer(t, &fakeRollouts{}).ServeHTTP(rec, req)

	if !strings.Contains(rec.Body.String(), `"rollouts":[]`) {
		t.Errorf("want an empty array, got %s", rec.Body)
	}
}
