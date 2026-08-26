package raven_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/volck/raven/internal/flock/raven"
)

func TestEvents_OK(t *testing.T) {
	t.Parallel()
	want := []raven.Event{
		{Time: time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC), Operation: "update", Engine: "dev", Path: "kv/foo", Status: "ok"},
		{Time: time.Date(2026, 5, 22, 11, 59, 0, 0, time.UTC), Operation: "delete", Engine: "dev", Path: "kv/bar", Status: "ok"},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/events" {
			t.Errorf("path = %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(want)
	}))
	t.Cleanup(srv.Close)

	c, _ := raven.New(raven.WithRequestTimeout(2 * time.Second))
	got, err := c.Events(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Events err = %v", err)
	}
	if len(got) != 2 || got[0].Path != "kv/foo" || got[1].Operation != "delete" {
		t.Fatalf("got = %+v", got)
	}
}

func TestEvents_Non2xxIsError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	c, _ := raven.New()
	if _, err := c.Events(context.Background(), srv.URL); err == nil {
		t.Fatal("want error on 500")
	}
}

func TestEvents_BadBaseURL(t *testing.T) {
	t.Parallel()
	c, _ := raven.New()
	if _, err := c.Events(context.Background(), "://broken"); err == nil {
		t.Fatal("want error on bad url")
	}
}

func TestEvents_GarbageBodyIsError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	t.Cleanup(srv.Close)

	c, _ := raven.New()
	if _, err := c.Events(context.Background(), srv.URL); err == nil {
		t.Fatal("want decode error")
	}
}
