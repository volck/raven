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

// TestRun_E2E_AgainstFakeLogparser drives run() against a fake logparser and
// asserts that /api/v1/ssgs returns the engines once the Provider has loaded.
func TestRun_E2E_AgainstFakeLogparser(t *testing.T) {
	t.Parallel()

	lp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/ssgs":
			_ = json.NewEncoder(w).Encode([]string{"dev", "prod01"})
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
			return "50ms"
		case "PROBE_INTERVAL":
			return "500ms" // keep probes from spamming bogus targets
		}
		return ""
	}

	var stderr safeBuffer
	done := make(chan error, 1)
	go func() { done <- run(ctx, []string{"flock"}, getenv, io.Discard, &stderr) }()

	addr := waitForAddr(t, &stderr, 2*time.Second)

	// Poll /readyz until ready or timeout.
	deadline := time.After(3 * time.Second)
	for {
		resp, err := http.Get("http://" + addr + "/readyz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		select {
		case <-deadline:
			t.Fatalf("/readyz never returned 200; stderr=%s", stderr.String())
		case <-time.After(20 * time.Millisecond):
		}
	}

	resp, err := http.Get("http://" + addr + "/api/v1/ravens")
	if err != nil {
		t.Fatalf("GET /api/v1/ravens: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "dev") || !strings.Contains(string(body), "prod01") {
		t.Fatalf("body missing engines: %s", body)
	}

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
