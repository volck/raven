package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/volck/raven/cmd/flock/ui"
	"github.com/volck/raven/internal/flock"
	rvclient "github.com/volck/raven/internal/flock/raven"
)

func newUIServer(t *testing.T, snap Snapshotter, health HealthSnapshotter, status StatusSnapshotter, pipeline PipelineSnapshotter) http.Handler {
	t.Helper()
	return newUIServerFull(t, snap, health, status, pipeline, &fakeEvents{})
}

func newUIServerFull(t *testing.T, snap Snapshotter, health HealthSnapshotter, status StatusSnapshotter, pipeline PipelineSnapshotter, events EventSnapshotter) http.Handler {
	t.Helper()
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	renderer, err := ui.NewRenderer()
	if err != nil {
		t.Fatalf("renderer: %v", err)
	}
	mux := http.NewServeMux()
	addUIRoutes(mux, logger, renderer, snap, health, status, pipeline, events)
	return mux
}

type readySnap struct {
	routing map[string][]string
}

func (r readySnap) Snapshot() flock.Snapshot { return flock.Snapshot{Routing: r.routing} }
func (r readySnap) Ready() bool              { return true }

type noHealth struct{}

func (noHealth) Health() map[string]flock.Health             { return nil }
func (noHealth) HealthFor(string) (flock.Health, bool)       { return flock.Health{}, false }

func TestUIDashboard_OK(t *testing.T) {
	t.Parallel()
	snap := readySnap{routing: map[string][]string{"dev": {"http://a"}}}
	srv := newUIServer(t, snap, noHealth{}, emptyStatus{}, emptyPipeline{})

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("content-type = %q", ct)
	}
	body := rec.Body.String()
	for _, want := range []string{"flock", "Fleet", "dev"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
}

func TestUIEngine_404Unknown(t *testing.T) {
	t.Parallel()
	snap := readySnap{routing: map[string][]string{"dev": {"http://a"}}}
	srv := newUIServer(t, snap, noHealth{}, emptyStatus{}, emptyPipeline{})

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ui/engines/nope", nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestUIEngine_OK(t *testing.T) {
	t.Parallel()
	snap := readySnap{routing: map[string][]string{"dev": {"http://a"}}}
	srv := newUIServer(t, snap, noHealth{}, emptyStatus{}, emptyPipeline{})

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ui/engines/dev", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "engine: dev") {
		t.Errorf("body missing engine heading; got: %s", rec.Body.String()[:200])
	}
}

func TestUIStatic_CSS(t *testing.T) {
	t.Parallel()
	snap := readySnap{}
	srv := newUIServer(t, snap, noHealth{}, emptyStatus{}, emptyPipeline{})

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/static/app.css", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), ":root") {
		t.Errorf("css body unexpected")
	}
}

func TestUINotReady_503(t *testing.T) {
	t.Parallel()
	srv := newUIServer(t, notReadySnap{}, noHealth{}, emptyStatus{}, emptyPipeline{})

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "starting") {
		t.Errorf("body missing 'starting'")
	}
}

// notReadySnap is local to this test file; the API tests have their own
// fakeSnap with different fields.
type notReadySnap struct{}

func (notReadySnap) Snapshot() flock.Snapshot { return flock.Snapshot{} }
func (notReadySnap) Ready() bool              { return false }

// Ensure atomic.Bool import is used somewhere in this file's transitive
// closure (silence unused-import warnings if test set shrinks). The var
// is also referenced from helpers below.
var _ atomic.Bool

func TestUIEngine_RendersEvents(t *testing.T) {
	t.Parallel()
	snap := readySnap{routing: map[string][]string{"dev": {"http://a"}}}
	evs := &fakeEvents{
		byEngine: map[string][]flock.TargetEvent{
			"dev": {{
				Target: "http://a",
				Event: rvclient.Event{
					Time:      time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC),
					Operation: "update",
					Engine:    "dev",
					Path:      "kv/data/foo",
					Status:    "ok",
					Message:   "applied",
				},
			}},
		},
	}
	srv := newUIServerFull(t, snap, noHealth{}, emptyStatus{}, emptyPipeline{}, evs)

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ui/engines/dev", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"Recent activity (1)", "kv/data/foo", "applied", "update"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
}

func TestUIEngine_NoEvents(t *testing.T) {
	t.Parallel()
	snap := readySnap{routing: map[string][]string{"dev": {"http://a"}}}
	srv := newUIServer(t, snap, noHealth{}, emptyStatus{}, emptyPipeline{})

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ui/engines/dev", nil))

	body := rec.Body.String()
	if !strings.Contains(body, "no recent events") {
		t.Errorf("body missing empty-events placeholder; got: %s", body)
	}
}
