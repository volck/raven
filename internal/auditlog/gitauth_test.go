package auditlog

import (
	"path/filepath"
	"testing"
)

// TestLoadGitAuthMissingKey is the RED test for cycle F6:
// LoadGitAuth must return a non-nil error when SSHKeyPath points to a
// path that does not exist on disk — startup must fail loudly rather
// than silently fall back to unauthenticated cloning.
func TestLoadGitAuthMissingKey(t *testing.T) {
	t.Parallel()
	cfg := GitSourceConfig{
		URL:        "git@example.com:org/repo.git",
		Branch:     "main",
		Path:       "routing.json",
		SSHKeyPath: filepath.Join(t.TempDir(), "does-not-exist"),
	}
	if _, err := LoadGitAuth(cfg); err == nil {
		t.Fatal("expected error for missing SSH key, got nil")
	}
}

// TestLoadGitAuthNoKeyReturnsNil documents that an empty SSHKeyPath means
// "no auth" (e.g., file://, https with no creds) and must succeed.
func TestLoadGitAuthNoKeyReturnsNil(t *testing.T) {
	t.Parallel()
	cfg := GitSourceConfig{URL: "file:///tmp/repo", Branch: "main", Path: "x.json"}
	auth, err := LoadGitAuth(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if auth != nil {
		t.Errorf("expected nil auth, got %v", auth)
	}
}
