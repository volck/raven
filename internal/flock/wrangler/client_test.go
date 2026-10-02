package wrangler_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/volck/raven/internal/flock/wrangler"
)

func rolloutsServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

func TestClient_Rollouts(t *testing.T) {
	t.Parallel()

	var gotPath, gotAccept string
	srv := rolloutsServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAccept = r.Header.Get("Accept")

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"rollouts": []map[string]any{{
				"time":      "2026-09-01T10:00:00Z",
				"raven":     "ssg-dev",
				"namespace": "ssg",
				"engine":    "kv",
				"actor":     "system:serviceaccount:ci:provisioner",
				"branch":    "raven/create-ssg-dev",
				"succeeded": true,
				"stages": []map[string]string{
					{"stage": "preflight", "status": "done"},
					{"stage": "cluster", "status": "done"},
				},
			}},
		})
	})

	client, err := wrangler.New(srv.URL)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rollouts, err := client.Rollouts(context.Background())
	if err != nil {
		t.Fatalf("Rollouts() error = %v", err)
	}

	if gotPath != "/api/v1/rollouts" {
		t.Errorf("path = %q", gotPath)
	}
	if gotAccept != "application/json" {
		t.Errorf("accept = %q", gotAccept)
	}
	if len(rollouts) != 1 {
		t.Fatalf("got %d rollouts, want 1", len(rollouts))
	}

	got := rollouts[0]
	if got.Raven != "ssg-dev" || got.Namespace != "ssg" || got.Engine != "kv" {
		t.Errorf("identity not decoded: %+v", got)
	}
	if !got.Succeeded {
		t.Error("succeeded not decoded")
	}
	if got.Branch != "raven/create-ssg-dev" {
		t.Errorf("branch = %q", got.Branch)
	}
	if want := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC); !got.Time.Equal(want) {
		t.Errorf("time = %v, want %v", got.Time, want)
	}
	if len(got.Stages) != 2 || got.Stages[0].Stage != "preflight" {
		t.Errorf("stages not decoded: %+v", got.Stages)
	}
}

func TestClient_RolloutsEmpty(t *testing.T) {
	t.Parallel()

	srv := rolloutsServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"rollouts":[]}`))
	})

	client, err := wrangler.New(srv.URL)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rollouts, err := client.Rollouts(context.Background())
	if err != nil {
		t.Fatalf("Rollouts() error = %v", err)
	}
	if len(rollouts) != 0 {
		t.Errorf("got %d rollouts, want none", len(rollouts))
	}
}

func TestClient_RolloutsServerError(t *testing.T) {
	t.Parallel()

	srv := rolloutsServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})

	client, err := wrangler.New(srv.URL)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if _, err := client.Rollouts(context.Background()); err == nil {
		t.Fatal("expected an error for a 500 response")
	} else if !strings.Contains(err.Error(), "500") {
		t.Errorf("error %q does not mention the status", err)
	}
}

func TestNew_RejectsUnusableURL(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"", "not-a-url", "://missing-scheme"} {
		if _, err := wrangler.New(raw); err == nil {
			t.Errorf("New(%q) was accepted", raw)
		}
	}
}

// A misbehaving or hostile upstream must not exhaust flock's memory.
func TestClient_RolloutsCapsBodySize(t *testing.T) {
	t.Parallel()

	srv := rolloutsServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"rollouts":[{"raven":"`))
		for i := 0; i < 9<<20; i += 1 << 10 {
			_, _ = w.Write([]byte(strings.Repeat("a", 1<<10)))
		}
		_, _ = w.Write([]byte(`"}]}`))
	})

	client, err := wrangler.New(srv.URL)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if _, err := client.Rollouts(context.Background()); err == nil {
		t.Error("an oversized body was accepted")
	}
}

func TestClient_RolloutsHonoursContext(t *testing.T) {
	t.Parallel()

	srv := rolloutsServer(t, func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	})

	client, err := wrangler.New(srv.URL, wrangler.WithRequestTimeout(50*time.Millisecond))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if _, err := client.Rollouts(context.Background()); err == nil {
		t.Error("a hung upstream did not time out")
	}
}
