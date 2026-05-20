package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// writeGitConfig writes a LogParserConfig pointing at a git-backed routing
// source. Returns the config file path.
func writeGitConfig(t *testing.T, auditLogPath, gitURL, branch, gitPath, pollInterval string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "logparser.json")
	body := fmt.Sprintf(`{
		"audit_log_path": %q,
		"git": {
			"url": %q,
			"branch": %q,
			"path": %q,
			"poll_interval": %q
		}
	}`, auditLogPath, gitURL, branch, gitPath, pollInterval)
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatalf("write git config: %v", err)
	}
	return path
}

// initGitRoutingRepo creates a git repo with the given JSON routing file
// committed on branch `main` at path `routing.json`. Returns its file:// URL
// and the on-disk directory.
func initGitRoutingRepo(t *testing.T, engines []string, routing map[string][]string) (url, dir string) {
	t.Helper()
	dir = t.TempDir()
	gitInTestDir := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	gitInTestDir("init", "-b", "main")
	body, _ := json.Marshal(map[string]any{
		"secret_engines": engines,
		"routing":        routing,
	})
	if err := os.WriteFile(filepath.Join(dir, "routing.json"), body, 0600); err != nil {
		t.Fatalf("write routing: %v", err)
	}
	gitInTestDir("add", "routing.json")
	gitInTestDir("commit", "-m", "initial")
	return "file://" + dir, dir
}

// TestRunGitRoutingEndToEnd is the RED test for cycle H1:
// run() wires GitSource → Provider → Server. After startup, GET /api/v1/ssgs
// returns the engines from the git-backed routing file.
func TestRunGitRoutingEndToEnd(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git binary not on PATH")
	}

	auditLog := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(auditLog, []byte(""), 0600); err != nil {
		t.Fatalf("write audit log: %v", err)
	}

	url, _ := initGitRoutingRepo(t,
		[]string{"kv", "ssg"},
		map[string][]string{
			"kv":  {"http://raven-a"},
			"ssg": {"http://raven-b"},
		})

	cfgPath := writeGitConfig(t, auditLog, url, "main", "routing.json", "1m")

	getenv := func(k string) string {
		switch k {
		case "LOGPARSER_CONFIG":
			return cfgPath
		case "HTTP_ADDR":
			return "127.0.0.1:0"
		}
		return ""
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	stderr := &safeBuffer{}
	runErr := make(chan error, 1)
	go func() {
		runErr <- run(ctx, []string{"logparser"}, getenv, io.Discard, stderr)
	}()

	addr := waitForAddr(t, stderr)
	waitForReadyz(t, addr)

	resp, err := http.Get("http://" + addr + "/api/v1/ssgs")
	if err != nil {
		t.Fatalf("GET /api/v1/ssgs: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var got []string
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 engines, got %v", got)
	}

	cancel()
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return after cancel")
	}

	_ = strings.Contains // retain import for future cycles
}

// TestRunGitRoutingDetectsCommit is the RED test for cycle H2:
// when a new commit lands on the configured branch, the poll loop loads
// it and emits a "routing.transition" log line; GET /api/v1/ssgs then
// reflects the new state.
func TestRunGitRoutingDetectsCommit(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git binary not on PATH")
	}

	auditLog := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(auditLog, []byte(""), 0600); err != nil {
		t.Fatalf("write audit log: %v", err)
	}

	url, dir := initGitRoutingRepo(t,
		[]string{"kv"},
		map[string][]string{"kv": {"http://a"}})

	// Aggressive poll so the new commit is observed quickly.
	cfgPath := writeGitConfig(t, auditLog, url, "main", "routing.json", "50ms")

	getenv := func(k string) string {
		switch k {
		case "LOGPARSER_CONFIG":
			return cfgPath
		case "HTTP_ADDR":
			return "127.0.0.1:0"
		}
		return ""
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	stderr := &safeBuffer{}
	runErr := make(chan error, 1)
	go func() {
		runErr <- run(ctx, []string{"logparser"}, getenv, io.Discard, stderr)
	}()

	addr := waitForAddr(t, stderr)
	waitForReadyz(t, addr)

	// Commit a new routing config adding "ssg" alongside "kv".
	newBody, _ := json.Marshal(map[string]any{
		"secret_engines": []string{"kv", "ssg"},
		"routing": map[string][]string{
			"kv":  {"http://a"},
			"ssg": {"http://b"},
		},
	})
	if err := os.WriteFile(filepath.Join(dir, "routing.json"), newBody, 0600); err != nil {
		t.Fatalf("write routing: %v", err)
	}
	gitRunInDir(t, dir, "add", "routing.json")
	gitRunInDir(t, dir, "commit", "-m", "add ssg")

	deadline := time.Now().Add(5 * time.Second)
	var got []string
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + addr + "/api/v1/ssgs")
		if err == nil && resp.StatusCode == http.StatusOK {
			_ = json.NewDecoder(resp.Body).Decode(&got)
			resp.Body.Close()
			if len(got) == 2 {
				break
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 engines after commit, got %v", got)
	}

	if !strings.Contains(stderr.String(), `"transition"`) {
		t.Errorf("expected transition log line, stderr=%s", stderr.String())
	}

	cancel()
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return after cancel")
	}
}

// TestRunPersistsOffsetOnShutdown is the RED test for cycle H4:
// when state_file is set, run() writes the current tailer offset to disk
// on graceful shutdown.
func TestRunPersistsOffsetOnShutdown(t *testing.T) {
	t.Parallel()

	auditLog := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(auditLog, []byte(""), 0600); err != nil {
		t.Fatalf("write audit log: %v", err)
	}
	stateFile := filepath.Join(t.TempDir(), "offset.state")

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "logparser.json")
	body := fmt.Sprintf(`{
		"audit_log_path": %q,
		"secret_engines": ["kv"],
		"routing": {"kv": ["http://example.invalid"]},
		"state_file": %q
	}`, auditLog, stateFile)
	if err := os.WriteFile(cfgPath, []byte(body), 0600); err != nil {
		t.Fatalf("write cfg: %v", err)
	}

	getenv := func(k string) string {
		switch k {
		case "LOGPARSER_CONFIG":
			return cfgPath
		case "HTTP_ADDR":
			return "127.0.0.1:0"
		}
		return ""
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	stderr := &safeBuffer{}
	runErr := make(chan error, 1)
	go func() {
		runErr <- run(ctx, []string{"logparser"}, getenv, io.Discard, stderr)
	}()
	addr := waitForAddr(t, stderr)
	_ = addr

	cancel()
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return after cancel")
	}

	if _, err := os.Stat(stateFile); err != nil {
		t.Fatalf("expected state file %s to exist: %v", stateFile, err)
	}
}

// TestRunFailsFastOnCloneError is the RED test for cycle H5:
// when the configured git URL is unreachable, run() must return an error
// (fail-fast at startup rather than running with an empty routing snapshot).
func TestRunFailsFastOnCloneError(t *testing.T) {
	t.Parallel()
	auditLog := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(auditLog, []byte(""), 0600); err != nil {
		t.Fatalf("write audit log: %v", err)
	}
	// file:// URL to a directory that is not a git repo.
	badURL := "file://" + t.TempDir()
	cfgPath := writeGitConfig(t, auditLog, badURL, "main", "routing.json", "1m")

	getenv := func(k string) string {
		if k == "LOGPARSER_CONFIG" {
			return cfgPath
		}
		return ""
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	err := run(ctx, []string{"logparser"}, getenv, io.Discard, io.Discard)
	if err == nil {
		t.Fatal("expected error from run() with unreachable git URL, got nil")
	}
	if !strings.Contains(err.Error(), "refresh") && !strings.Contains(err.Error(), "clone") {
		t.Errorf("expected error to mention refresh/clone, got: %v", err)
	}
}

// TestRunFailsFastOnParseError is the RED test for cycle H6:
// when the routing file in git fails to parse, run() must return an error
// at startup rather than serving an empty routing snapshot.
func TestRunFailsFastOnParseError(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git binary not on PATH")
	}

	auditLog := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(auditLog, []byte(""), 0600); err != nil {
		t.Fatalf("write audit log: %v", err)
	}

	// Init a repo whose routing.json is malformed.
	dir := t.TempDir()
	gitRunInDir(t, dir, "init", "-b", "main")
	if err := os.WriteFile(filepath.Join(dir, "routing.json"), []byte("not valid json{{"), 0600); err != nil {
		t.Fatalf("write routing: %v", err)
	}
	gitRunInDir(t, dir, "add", "routing.json")
	gitRunInDir(t, dir, "commit", "-m", "broken")
	url := "file://" + dir

	cfgPath := writeGitConfig(t, auditLog, url, "main", "routing.json", "1m")

	getenv := func(k string) string {
		if k == "LOGPARSER_CONFIG" {
			return cfgPath
		}
		return ""
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	err := run(ctx, []string{"logparser"}, getenv, io.Discard, io.Discard)
	if err == nil {
		t.Fatal("expected parse error from run(), got nil")
	}
	if !strings.Contains(err.Error(), "parse") && !strings.Contains(err.Error(), "refresh") {
		t.Errorf("expected error to mention parse/refresh, got: %v", err)
	}
}

// gitRunInDir runs a git command in the given directory with deterministic identity.
func gitRunInDir(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

// TestRunSIGHUPTriggersRefresh is the RED test for cycle H3:
// SIGHUP triggers an immediate refresh, even when the poll interval is far
// longer than the test timeout.
func TestRunSIGHUPTriggersRefresh(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git binary not on PATH")
	}
	// Deliberately not t.Parallel: this test sends SIGHUP to its own process
	// and any other concurrent run() in the same binary would also see it.

	auditLog := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(auditLog, []byte(""), 0600); err != nil {
		t.Fatalf("write audit log: %v", err)
	}

	url, dir := initGitRoutingRepo(t,
		[]string{"kv"},
		map[string][]string{"kv": {"http://a"}})
	// Long poll so only SIGHUP can trigger the refresh in the test window.
	cfgPath := writeGitConfig(t, auditLog, url, "main", "routing.json", "1h")

	getenv := func(k string) string {
		switch k {
		case "LOGPARSER_CONFIG":
			return cfgPath
		case "HTTP_ADDR":
			return "127.0.0.1:0"
		}
		return ""
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	stderr := &safeBuffer{}
	runErr := make(chan error, 1)
	go func() {
		runErr <- run(ctx, []string{"logparser"}, getenv, io.Discard, stderr)
	}()

	addr := waitForAddr(t, stderr)
	waitForReadyz(t, addr)

	// Add a second engine and commit.
	newBody, _ := json.Marshal(map[string]any{
		"secret_engines": []string{"kv", "ssg"},
		"routing": map[string][]string{
			"kv":  {"http://a"},
			"ssg": {"http://b"},
		},
	})
	if err := os.WriteFile(filepath.Join(dir, "routing.json"), newBody, 0600); err != nil {
		t.Fatalf("write routing: %v", err)
	}
	gitRunInDir(t, dir, "add", "routing.json")
	gitRunInDir(t, dir, "commit", "-m", "add ssg")

	// Send SIGHUP to ourselves to force a refresh.
	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("find process: %v", err)
	}
	if err := proc.Signal(syscall.SIGHUP); err != nil {
		t.Fatalf("send SIGHUP: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	var got []string
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + addr + "/api/v1/ssgs")
		if err == nil && resp.StatusCode == http.StatusOK {
			_ = json.NewDecoder(resp.Body).Decode(&got)
			resp.Body.Close()
			if len(got) == 2 {
				break
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	if len(got) != 2 {
		t.Fatalf("expected SIGHUP to trigger refresh, got engines=%v", got)
	}

	cancel()
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return after cancel")
	}
}

// waitForReadyz polls /readyz until 200 or 5s elapses.
func waitForReadyz(t *testing.T, addr string) {
	t.Helper()
	client := &http.Client{Timeout: 200 * time.Millisecond}
	deadline := time.Now().Add(5 * time.Second)
	url := "http://" + addr + "/readyz"
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", url)
}
