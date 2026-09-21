package provision

import (
	"context"
	"testing"

	"github.com/go-git/go-git/v5"
)

// newEmptyRemote creates a bare repository with no commits, which is what
// Bitbucket hands back from a freshly created repository.
func newEmptyRemote(t *testing.T) string {
	t.Helper()

	bare := t.TempDir()
	if _, err := git.PlainInit(bare, true); err != nil {
		t.Fatalf("init bare: %v", err)
	}
	return bare
}

func TestSeedRepo_EmptyRemote(t *testing.T) {
	t.Parallel()

	remote := newEmptyRemote(t)

	seeded, err := SeedRepo(context.Background(), remote, "master", "declarative/dev/sealedsecrets/.gitkeep", nil)
	if err != nil {
		t.Fatalf("SeedRepo: %v", err)
	}
	if !seeded {
		t.Fatal("seeded = false, want true")
	}

	commit := headCommit(t, remote, "master")
	if _, err := commit.File("declarative/dev/sealedsecrets/.gitkeep"); err != nil {
		t.Fatalf("file missing from seed commit: %v", err)
	}
}

// A retry must never rewrite a repository that already holds sealed secrets.
func TestSeedRepo_SkipsPopulatedRemote(t *testing.T) {
	t.Parallel()

	remote := newBareRemote(t)
	before := headCommit(t, remote, "master")

	seeded, err := SeedRepo(context.Background(), remote, "master", "declarative/dev/sealedsecrets/.gitkeep", nil)
	if err != nil {
		t.Fatalf("SeedRepo: %v", err)
	}
	if seeded {
		t.Fatal("seeded a repository that already had commits")
	}

	if after := headCommit(t, remote, "master"); after.Hash != before.Hash {
		t.Fatalf("master moved from %s to %s", before.Hash, after.Hash)
	}
}

func TestSeedRepo_RejectsPathOutsideRepo(t *testing.T) {
	t.Parallel()

	for _, seedPath := range []string{"../escape/.gitkeep", "/etc/passwd", ""} {
		if _, err := SeedRepo(context.Background(), newEmptyRemote(t), "master", seedPath, nil); err == nil {
			t.Errorf("path %q: want error, got nil", seedPath)
		}
	}
}
