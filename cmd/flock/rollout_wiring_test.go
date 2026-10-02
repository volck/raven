package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A configured wrangler must show up on flock's own rollout endpoint.
func TestRun_ServesWranglerRollouts(t *testing.T) {
	lp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/ssgs":
			_, _ = w.Write([]byte(`["kv"]`))
		case "/api/v1/ssgs/kv":
			_, _ = w.Write([]byte(`["http://127.0.0.1:1"]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer lp.Close()

	wr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/rollouts" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"rollouts":[{"raven":"ssg-dev","engine":"kv","succeeded":true}]}`))
	}))
	defer wr.Close()

	env := map[string]string{
		"LOGPARSER_URL":    lp.URL,
		"WRANGLER_URL":     wr.URL,
		"HTTP_ADDR":        "127.0.0.1:0",
		"ROLLOUT_INTERVAL": "50ms",
		"PROBE_INTERVAL":   "10s",
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var stderr safeBuffer
	done := make(chan error, 1)
	go func() { done <- run(ctx, nil, getenvFor(env), io.Discard, &stderr) }()

	addr := waitForAddr(t, &stderr, 3*time.Second)

	var body struct {
		Rollouts []struct {
			Raven string `json:"raven"`
		} `json:"rollouts"`
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + addr + "/api/v1/rollouts")
		if err == nil {
			if resp.StatusCode == http.StatusOK {
				_ = json.NewDecoder(resp.Body).Decode(&body)
			}
			resp.Body.Close()
			if len(body.Rollouts) > 0 {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}

	if len(body.Rollouts) != 1 || body.Rollouts[0].Raven != "ssg-dev" {
		t.Errorf("flock did not serve wrangler's rollouts: %+v", body.Rollouts)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("run() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not shut down")
	}
}

// A bad wrangler URL is a configuration error, not something to discover at
// the first poll.
func TestRun_RejectsBadWranglerURL(t *testing.T) {
	env := map[string]string{
		"LOGPARSER_URL": "http://127.0.0.1:1",
		"WRANGLER_URL":  "ftp://nope",
		"HTTP_ADDR":     "127.0.0.1:0",
	}

	err := run(context.Background(), nil, getenvFor(env), io.Discard, io.Discard)
	if err == nil {
		t.Fatal("expected a configuration error")
	}
	if !strings.Contains(err.Error(), "WRANGLER_URL") {
		t.Errorf("error %q does not name the setting", err)
	}
}

func getenvFor(env map[string]string) func(string) string {
	return func(k string) string { return env[k] }
}
