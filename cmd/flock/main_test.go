package main

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// safeBuffer is a goroutine-safe bytes.Buffer for stderr capture during e2e tests.
type safeBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

var addrRE = regexp.MustCompile(`"addr":"([^"]+)"`)

// waitForAddr scans stderr for the "listening" log line and returns the addr.
func waitForAddr(t *testing.T, buf *safeBuffer, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		s := buf.String()
		if strings.Contains(s, `"msg":"listening"`) {
			if m := addrRE.FindStringSubmatch(s); len(m) == 2 {
				return m[1]
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for listening addr; stderr=%q", buf.String())
	return ""
}

func TestRun_HealthzOK_AndShutdown(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	getenv := func(k string) string {
		switch k {
		case "HTTP_ADDR":
			return "127.0.0.1:0"
		case "LOGPARSER_URL":
			return "http://127.0.0.1:1" // not exercised by /healthz
		default:
			return ""
		}
	}

	var stderr safeBuffer
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, []string{"flock"}, getenv, io.Discard, &stderr)
	}()

	addr := waitForAddr(t, &stderr, 2*time.Second)

	resp, err := http.Get("http://" + addr + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(body), "ok") {
		t.Fatalf("body = %q, want contains 'ok'", string(body))
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned err = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("run did not return within 3s after cancel")
	}
}

// ensure bufio is used somewhere (linter satisfaction for future cycles)
var _ = bufio.NewReader

// shutdownProbeHandler is registered when getenv("FLOCK_TEST_SLOW_HANDLER")=="1"
// so e2e tests can exercise the shutdown drain.
//
// Implemented in main.go.

func TestRun_ShutdownDrainsInFlight(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	getenv := func(k string) string {
		switch k {
		case "HTTP_ADDR":
			return "127.0.0.1:0"
		case "LOGPARSER_URL":
			return "http://127.0.0.1:1"
		case "FLOCK_TEST_SLOW_HANDLER":
			return "1"
		}
		return ""
	}

	var stderr safeBuffer
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, []string{"flock"}, getenv, io.Discard, &stderr)
	}()

	addr := waitForAddr(t, &stderr, 2*time.Second)

	// Issue a request to /slow that should keep running while we cancel.
	respCh := make(chan *http.Response, 1)
	errCh := make(chan error, 1)
	go func() {
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Get("http://" + addr + "/slow")
		if err != nil {
			errCh <- err
			return
		}
		respCh <- resp
	}()

	// Give the server time to actually receive the request.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case resp := <-respCh:
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("slow handler status = %d, want 200 (shutdown should drain)", resp.StatusCode)
		}
		_ = resp.Body.Close()
	case err := <-errCh:
		t.Fatalf("slow handler errored mid-shutdown (not drained): %v", err)
	case <-time.After(5 * time.Second):
		t.Fatalf("slow handler did not complete")
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned err = %v", err)
		}
	case <-time.After(6 * time.Second):
		t.Fatalf("run did not return within 6s after cancel")
	}
}
