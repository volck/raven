package logparser_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/volck/raven/internal/flock/logparser"
)

func TestClient_ListSSGs(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/ssgs" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if r.Header.Get("Accept") != "application/json" {
			t.Errorf("missing Accept header")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]string{"dev", "prod01"})
	}))
	t.Cleanup(srv.Close)

	c, err := logparser.New(srv.URL)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got, err := c.ListSSGs(context.Background())
	if err != nil {
		t.Fatalf("ListSSGs: %v", err)
	}
	if len(got) != 2 || got[0] != "dev" || got[1] != "prod01" {
		t.Fatalf("got %v, want [dev prod01]", got)
	}
}

func TestClient_GetSSG_OK(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/ssgs/dev" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]string{"https://r1.example", "https://r2.example"})
	}))
	t.Cleanup(srv.Close)

	c, _ := logparser.New(srv.URL)
	got, err := c.GetSSG(context.Background(), "dev")
	if err != nil {
		t.Fatalf("GetSSG: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %v, want 2 targets", got)
	}
}

func TestClient_GetSSG_NotFound(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	c, _ := logparser.New(srv.URL)
	_, err := c.GetSSG(context.Background(), "missing")
	if !errors.Is(err, logparser.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestClient_New_RejectsBadURL(t *testing.T) {
	t.Parallel()
	for _, in := range []string{"", "no-scheme", "://broken"} {
		if _, err := logparser.New(in); err == nil {
			t.Errorf("New(%q) returned nil err", in)
		}
	}
}

func TestClient_5xx_ReturnsError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusBadGateway)
	}))
	t.Cleanup(srv.Close)

	c, _ := logparser.New(srv.URL)
	_, err := c.ListSSGs(context.Background())
	if err == nil {
		t.Fatal("want error on 502")
	}
}

func TestClient_RespectsContextCancel(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	t.Cleanup(srv.Close)

	c, _ := logparser.New(srv.URL, logparser.WithRequestTimeout(100*time.Millisecond))
	_, err := c.ListSSGs(context.Background())
	if err == nil {
		t.Fatal("want timeout error")
	}
}
