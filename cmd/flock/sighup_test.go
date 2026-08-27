package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// TestRun_SIGHUP_TriggersRefresh boots run() against a fake logparser whose
// engine list changes between requests. After SIGHUP the new engine list is
// reflected without waiting for the poll interval.
func TestRun_SIGHUP_TriggersRefresh(t *testing.T) {
	t.Parallel()

	var phase atomic.Int32
	lp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/ssgs":
			if phase.Load() < 2 {
				_ = json.NewEncoder(w).Encode([]string{"dev"})
			} else {
				_ = json.NewEncoder(w).Encode([]string{"dev", "prod01"})
			}
		case "/api/v1/ssgs/dev":
			_ = json.NewEncoder(w).Encode([]string{"http://127.0.0.1:1"})
		case "/api/v1/ssgs/prod01":
			_ = json.NewEncoder(w).Encode([]string{"http://127.0.0.1:2"})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(lp.Close)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	getenv := func(k string) string {
		switch k {
		case "HTTP_ADDR":
			return "127.0.0.1:0"
		case "LOGPARSER_URL":
			return lp.URL
		case "POLL_INTERVAL":
			return "10s" // big enough that only SIGHUP can cause a refresh
		case "PROBE_INTERVAL":
			return "10s"
		}
		return ""
	}

	var stderr safeBuffer
	done := make(chan error, 1)
	go func() { done <- run(ctx, []string{"flock"}, getenv, io.Discard, &stderr) }()

	addr := waitForAddr(t, &stderr, 2*time.Second)

	// Wait for initial readiness with engines=[dev].
	waitForBody(t, "http://"+addr+"/api/v1/ravens", "dev", 3*time.Second)

	// Flip the fake logparser and SIGHUP ourselves.
	phase.Store(2)
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatalf("kill SIGHUP: %v", err)
	}

	// Expect prod01 to appear quickly without waiting for the 10s poll.
	waitForBody(t, "http://"+addr+"/api/v1/ravens", "prod01", 3*time.Second)

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run err: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("run did not return")
	}
}

func waitForBody(t *testing.T, url, want string, timeout time.Duration) {
	t.Helper()
	deadline := time.After(timeout)
	for {
		resp, err := http.Get(url)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == 200 && strings.Contains(string(body), want) {
				return
			}
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for %q in %s", want, url)
		case <-time.After(50 * time.Millisecond):
		}
	}
}
