package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/volck/raven/internal/auditlog"
)

// stubSnapshotter returns a fixed RoutingConfig for tests.
type stubSnapshotter struct{ cfg auditlog.RoutingConfig }

func (s stubSnapshotter) Snapshot() auditlog.RoutingConfig { return s.cfg }

// stubReady reports a configurable readiness state.
type stubReady struct{ ready bool }

func (s *stubReady) Ready() bool { return s.ready }

func TestHealthzReturnsOK(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))

	srv := NewServer(logger, stubSnapshotter{}, &stubReady{ready: true})

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if got := rec.Body.String(); got != "ok\n" && got != "ok" {
		t.Errorf("expected body 'ok', got %q", got)
	}
}

// TestSSGsEndpointReturnsSecretEngines is the RED test for cycle G1:
// GET /api/v1/ssgs returns the snapshot's SecretEngines as a JSON array.
func TestSSGsEndpointReturnsSecretEngines(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	snap := stubSnapshotter{cfg: auditlog.RoutingConfig{
		SecretEngines: []string{"kv", "ssg"},
		Routing:       map[string][]string{"kv": {"http://x"}, "ssg": {"http://y"}},
	}}

	srv := NewServer(logger, snap, &stubReady{ready: true})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/ssgs", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}
	var got []string
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v\nbody=%s", err, rec.Body.String())
	}
	if len(got) != 2 || got[0] != "kv" || got[1] != "ssg" {
		t.Errorf("expected [kv ssg], got %v", got)
	}
}

// TestSSGsGetEndpoint is the RED test for cycle G2:
// GET /api/v1/ssgs/{name} returns the routing targets for a known engine
// and 404 for an unknown one.
func TestSSGsGetEndpoint(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	snap := stubSnapshotter{cfg: auditlog.RoutingConfig{
		SecretEngines: []string{"kv"},
		Routing:       map[string][]string{"kv": {"http://a", "http://b"}},
	}}
	srv := NewServer(logger, snap, &stubReady{ready: true})

	t.Run("known", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/ssgs/kv", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
		}
		var got []string
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(got) != 2 || got[0] != "http://a" || got[1] != "http://b" {
			t.Errorf("expected [http://a http://b], got %v", got)
		}
	})

	t.Run("unknown", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/ssgs/missing", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("expected 404, got %d body=%s", rec.Code, rec.Body.String())
		}
	})
}

// TestReadyzReflectsLoadState is the RED test for cycle G3:
// GET /readyz returns 503 while the routing provider has not completed a
// successful load and 200 once it has.
func TestReadyzReflectsLoadState(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	ready := &stubReady{ready: false}
	srv := NewServer(logger, stubSnapshotter{}, ready)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("pre-load: expected 503, got %d", rec.Code)
	}

	ready.ready = true
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("post-load: expected 200, got %d", rec.Code)
	}
}

// TestMethodNotAllowed is the guard test for cycle G5:
// ServeMux's method patterns must respond 405 to non-GET requests on
// GET-only routes. This pins the framework behaviour the project depends on.
func TestMethodNotAllowed(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	srv := NewServer(logger, stubSnapshotter{}, &stubReady{ready: true})

	for _, path := range []string{"/healthz", "/readyz", "/api/v1/ssgs"} {
		path := path
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, path, nil)
			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, req)
			if rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s POST: expected 405, got %d", path, rec.Code)
			}
		})
	}
}
