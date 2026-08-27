package raven_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/volck/raven/internal/flock/raven"
)

func TestProbe_OK(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			t.Errorf("path = %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	c, err := raven.New(raven.WithRequestTimeout(2 * time.Second))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ok, err := c.Probe(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Probe err = %v", err)
	}
	if !ok {
		t.Fatalf("Probe ok = false, want true")
	}
}

func TestProbe_5xxReturnsFalse(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	c, _ := raven.New()
	ok, err := c.Probe(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("err = %v, want nil (5xx is healthy=false, not transport error)", err)
	}
	if ok {
		t.Fatal("ok = true, want false on 500")
	}
}

func TestProbe_TransportErrorReturnsErr(t *testing.T) {
	t.Parallel()
	c, _ := raven.New(raven.WithRequestTimeout(100 * time.Millisecond))
	_, err := c.Probe(context.Background(), "http://127.0.0.1:1")
	if err == nil {
		t.Fatal("want transport error")
	}
}

func TestProbe_BadBaseURL(t *testing.T) {
	t.Parallel()
	c, _ := raven.New()
	if _, err := c.Probe(context.Background(), "://broken"); err == nil {
		t.Fatal("want error on bad url")
	}
}
