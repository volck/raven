package auditlog

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// gitRun runs git in dir with deterministic identity env. Fails the test on error.
func gitRun(t *testing.T, dir string, args ...string) {
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

// initGitRepoDir is like initGitRepo but also returns the on-disk path so
// the test can perform further git operations against it.
func initGitRepoDir(t *testing.T, branch, relPath, contents string) (url, dir string) {
	t.Helper()
	dir = t.TempDir()
	gitRun(t, dir, "init", "-b", branch)
	full := filepath.Join(dir, relPath)
	if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(full, []byte(contents), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	gitRun(t, dir, "add", relPath)
	gitRun(t, dir, "commit", "-m", "initial")
	return "file://" + dir, dir
}

// initGitRepo creates a temp git repo with the given file contents at relPath
// committed on the named branch. Returns the file:// URL of the repo.
func initGitRepo(t *testing.T, branch, relPath, contents string) string {
	t.Helper()
	url, _ := initGitRepoDir(t, branch, relPath, contents)
	return url
}

// TestGitSourceLoadClonesAndParses is the RED test for cycle F1:
// GitSource.Load clones the configured branch, reads the routing file at
// config.Git.Path, and returns the parsed RoutingConfig.
func TestGitSourceLoadClonesAndParses(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git binary not on PATH")
	}

	const routingPath = "logparser/routing.json"
	const routingJSON = `{
		"secret_engines": ["kv"],
		"routing": {"kv": ["http://raven.example"]}
	}`
	url := initGitRepo(t, "main", routingPath, routingJSON)

	src := NewGitSource(GitSourceConfig{
		URL:    url,
		Branch: "main",
		Path:   routingPath,
	})

	cfg, err := src.Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.SecretEngines) != 1 || cfg.SecretEngines[0] != "kv" {
		t.Errorf("expected SecretEngines=[kv], got %v", cfg.SecretEngines)
	}
	if got := cfg.Routing["kv"]; len(got) != 1 || got[0] != "http://raven.example" {
		t.Errorf("expected Routing.kv=[http://raven.example], got %v", got)
	}
}

// TestGitSourceLoadParsesYAML is the RED test for cycle F2:
// GitSource selects YAML or JSON parsing based on the file extension.
func TestGitSourceLoadParsesYAML(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git binary not on PATH")
	}

	const routingPath = "logparser/routing.yaml"
	const routingYAML = `secret_engines:
  - kv
  - ssg
routing:
  kv:
    - http://raven-a.example
    - http://raven-b.example
  ssg:
    - http://raven-c.example
`
	url := initGitRepo(t, "main", routingPath, routingYAML)

	src := NewGitSource(GitSourceConfig{
		URL:    url,
		Branch: "main",
		Path:   routingPath,
	})

	cfg, err := src.Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.SecretEngines) != 2 {
		t.Errorf("expected 2 engines, got %v", cfg.SecretEngines)
	}
	if got := cfg.Routing["kv"]; len(got) != 2 {
		t.Errorf("expected 2 targets for kv, got %v", got)
	}
}

// TestGitSourcePersistsClone is the RED test for cycle F3:
// GitSource keeps a persistent local clone between Loads so subsequent
// Loads fetch incrementally instead of re-cloning from scratch.
// The WorkDir() must remain identical and exist on disk across Loads.
func TestGitSourcePersistsClone(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git binary not on PATH")
	}

	const routingPath = "routing.json"
	const routingJSON = `{"secret_engines":["kv"],"routing":{"kv":["http://x"]}}`
	url := initGitRepo(t, "main", routingPath, routingJSON)

	src := NewGitSource(GitSourceConfig{URL: url, Branch: "main", Path: routingPath})
	if _, err := src.Load(context.Background()); err != nil {
		t.Fatalf("first Load: %v", err)
	}
	wd1 := src.WorkDir()
	if wd1 == "" {
		t.Fatal("expected WorkDir to be set after first Load")
	}
	if _, err := os.Stat(wd1); err != nil {
		t.Fatalf("expected WorkDir %q to exist on disk: %v", wd1, err)
	}

	if _, err := src.Load(context.Background()); err != nil {
		t.Fatalf("second Load: %v", err)
	}
	wd2 := src.WorkDir()
	if wd1 != wd2 {
		t.Errorf("expected persistent WorkDir, got %q then %q", wd1, wd2)
	}
}

// TestGitSourceForcePushHardReset is the RED test for cycle F4:
// When the upstream branch is force-pushed (history rewritten so the new
// tip is not a descendant of the previously seen commit), GitSource must
// hard-reset to the new tip, return the new RoutingConfig, and emit a WARN
// log "routing.force_reset".
func TestGitSourceForcePushHardReset(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git binary not on PATH")
	}

	const routingPath = "routing.json"
	const initJSON = `{"secret_engines":["kv"],"routing":{"kv":["http://old"]}}`
	url, dir := initGitRepoDir(t, "main", routingPath, initJSON)

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	src := NewGitSource(GitSourceConfig{URL: url, Branch: "main", Path: routingPath})
	src.SetLogger(logger)

	cfg1, err := src.Load(context.Background())
	if err != nil {
		t.Fatalf("first Load: %v", err)
	}
	if cfg1.Routing["kv"][0] != "http://old" {
		t.Fatalf("first Load got %v", cfg1.Routing)
	}

	// Rewrite history: amend the tip with new contents so the new commit
	// is not a descendant of the previously fetched commit.
	const newJSON = `{"secret_engines":["kv"],"routing":{"kv":["http://new"]}}`
	if err := os.WriteFile(filepath.Join(dir, routingPath), []byte(newJSON), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	gitRun(t, dir, "add", routingPath)
	gitRun(t, dir, "commit", "--amend", "-m", "rewritten")

	cfg2, err := src.Load(context.Background())
	if err != nil {
		t.Fatalf("second Load after force-push: %v", err)
	}
	if got := cfg2.Routing["kv"]; len(got) != 1 || got[0] != "http://new" {
		t.Errorf("expected hard reset to new tip, got %v", got)
	}
	if !strings.Contains(buf.String(), `"routing.force_reset"`) {
		t.Errorf("expected WARN log routing.force_reset, got: %s", buf.String())
	}
}

// TestGitSourceLoadRespectsCancelledContext is the RED test for cycle F5:
// Load must return an error promptly when its context is already cancelled.
func TestGitSourceLoadRespectsCancelledContext(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git binary not on PATH")
	}

	url := initGitRepo(t, "main", "routing.json",
		`{"secret_engines":["kv"],"routing":{"kv":["http://x"]}}`)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	src := NewGitSource(GitSourceConfig{URL: url, Branch: "main", Path: "routing.json"})
	done := make(chan error, 1)
	go func() {
		_, err := src.Load(ctx)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error from cancelled-context Load, got nil")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Load did not return within 5s of cancelled context")
	}
}
