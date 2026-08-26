package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func newTestServer(t *testing.T) (*Server, *atomic.Bool) {
	t.Helper()
	ready := new(atomic.Bool)
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	return NewServerBare(logger, ready), ready
}

func TestReadyz_503Until_MarkReady(t *testing.T) {
	t.Parallel()
	srv, _ := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("pre-ready status = %d, want 503", rec.Code)
	}

	srv.markReady()

	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("post-ready status = %d, want 200", rec.Code)
	}
}

func TestHealthz_AlwaysOK(t *testing.T) {
	t.Parallel()
	srv, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}
