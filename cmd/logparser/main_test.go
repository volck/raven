package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// writeConfig writes a minimal valid LogParserConfig JSON to a temp file and
// returns its path.
func writeConfig(t *testing.T, auditLogPath string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "logparser.json")
	body := `{
		"audit_log_path": "` + auditLogPath + `",
		"secret_engines": ["kv"],
		"routing": {"kv": ["http://example.invalid"]}
	}`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// safeBuffer is a goroutine-safe wrapper around bytes.Buffer for capturing
// concurrent writes from run() during e2e tests.
type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
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

// addrRE extracts "addr":"127.0.0.1:NNNN" from a JSON log line emitted by
// the "listening" log event.
var addrRE = regexp.MustCompile(`"msg":"listening"[^}]*"addr":"([^"]+)"`)

// waitForAddr polls the captured stderr buffer until run() logs its listening
// address, then returns it. Fails the test on timeout.
func waitForAddr(t *testing.T, stderr *safeBuffer) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if m := addrRE.FindStringSubmatch(stderr.String()); m != nil {
			return m[1]
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for listening address; stderr=%q", stderr.String())
	return ""
}

// waitForReady polls a /healthz endpoint until it responds 200 or the
// deadline passes. Fails the test on timeout.
func waitForReady(t *testing.T, addr string) {
	t.Helper()
	client := &http.Client{Timeout: 200 * time.Millisecond}
	deadline := time.Now().Add(2 * time.Second)
	url := "http://" + addr + "/healthz"
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s to be ready", url)
}

// TestRunReturnsErrorOnMissingConfig is the RED test for cycle A1:
// run() must exist with the canonical signature and surface config-load failures
// as an error return rather than os.Exit.
func TestRunReturnsErrorOnMissingConfig(t *testing.T) {
	t.Parallel()

	getenv := func(key string) string {
		if key == "LOGPARSER_CONFIG" {
			return "/nonexistent/does-not-exist.json"
		}
		return ""
	}

	var stdout, stderr bytes.Buffer
	err := run(context.Background(), []string{"logparser"}, getenv, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error from run() with missing config, got nil")
	}
	if !strings.Contains(err.Error(), "config") {
		t.Errorf("expected error to mention config, got: %v", err)
	}
}

// TestRunLogsToStderrWithSource is the RED test for cycle A2:
// the logger must write JSON to stderr (not stdout) and each line must
// include a "source" field (AddSource: true).
func TestRunLogsToStderrWithSource(t *testing.T) {
	t.Parallel()

	auditLog := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(auditLog, []byte(""), 0600); err != nil {
		t.Fatalf("write audit log: %v", err)
	}
	cfgPath := writeConfig(t, auditLog)

	getenv := func(key string) string {
		if key == "LOGPARSER_CONFIG" {
			return cfgPath
		}
		return ""
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var stdout, stderr bytes.Buffer
	if err := run(ctx, []string{"logparser"}, getenv, &stdout, &stderr); err != nil {
		t.Fatalf("run: %v", err)
	}

	if stdout.Len() != 0 {
		t.Errorf("expected stdout to be empty, got: %q", stdout.String())
	}
	if stderr.Len() == 0 {
		t.Fatal("expected stderr to contain logs, got empty")
	}

	// First log line must be valid JSON with a "source" field.
	line := strings.SplitN(strings.TrimSpace(stderr.String()), "\n", 2)[0]
	var rec map[string]any
	if err := json.Unmarshal([]byte(line), &rec); err != nil {
		t.Fatalf("expected JSON log line, got %q: %v", line, err)
	}
	if _, ok := rec["source"]; !ok {
		t.Errorf("expected log to have 'source' field (AddSource: true), got: %v", rec)
	}
}

// TestRunListensAndHealthzResponds is the RED test for cycle A4:
// run() must start an HTTP server on the address from HTTP_ADDR (defaulting
// to 127.0.0.1:0), log "listening" with the actual address, and respond to
// GET /healthz with 200.
func TestRunListensAndHealthzResponds(t *testing.T) {
	t.Parallel()

	auditLog := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(auditLog, []byte(""), 0600); err != nil {
		t.Fatalf("write audit log: %v", err)
	}
	cfgPath := writeConfig(t, auditLog)

	getenv := func(key string) string {
		switch key {
		case "LOGPARSER_CONFIG":
			return cfgPath
		case "HTTP_ADDR":
			return "127.0.0.1:0"
		}
		return ""
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	var stdout bytes.Buffer
	stderr := &safeBuffer{}

	runErr := make(chan error, 1)
	go func() {
		runErr <- run(ctx, []string{"logparser"}, getenv, &stdout, stderr)
	}()

	addr := waitForAddr(t, stderr)
	waitForReady(t, addr)

	cancel()

	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("run returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("run did not return within 3s of ctx cancel")
	}

	_ = fmt.Sprintf // keep import
}

// TestRunGracefulShutdownLogged is the RED test for cycle A5:
// after ctx cancellation, run() must perform an explicit graceful shutdown
// pass and log "shutting down" with reason=context_canceled before returning.
func TestRunGracefulShutdownLogged(t *testing.T) {
	t.Parallel()

	auditLog := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(auditLog, []byte(""), 0600); err != nil {
		t.Fatalf("write audit log: %v", err)
	}
	cfgPath := writeConfig(t, auditLog)

	getenv := func(key string) string {
		switch key {
		case "LOGPARSER_CONFIG":
			return cfgPath
		case "HTTP_ADDR":
			return "127.0.0.1:0"
		}
		return ""
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	var stdout bytes.Buffer
	stderr := &safeBuffer{}

	runErr := make(chan error, 1)
	go func() {
		runErr <- run(ctx, []string{"logparser"}, getenv, &stdout, stderr)
	}()

	_ = waitForAddr(t, stderr)
	cancel()

	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("run returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("run did not return within 3s of ctx cancel")
	}

	if !strings.Contains(stderr.String(), `"msg":"shutting down"`) {
		t.Errorf("expected shutdown log entry, got: %s", stderr.String())
	}
}
