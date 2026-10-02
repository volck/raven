package provision

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

var fixedTime = time.Date(2024, 5, 17, 12, 0, 0, 0, time.UTC)

// newBareRemote creates a bare repository seeded with one commit on master
// and returns its path, usable as a file:// remote.
func newBareRemote(t *testing.T) string {
	t.Helper()

	bare := t.TempDir()
	if _, err := git.PlainInit(bare, true); err != nil {
		t.Fatalf("init bare: %v", err)
	}

	seed := t.TempDir()
	repo, err := git.PlainInit(seed, false)
	if err != nil {
		t.Fatalf("init seed: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("worktree: %v", err)
	}
	if err := os.WriteFile(filepath.Join(seed, "README.md"), []byte("seed\n"), 0o600); err != nil {
		t.Fatalf("write seed file: %v", err)
	}
	if _, err := wt.Add("README.md"); err != nil {
		t.Fatalf("add: %v", err)
	}
	if _, err := wt.Commit("seed", &git.CommitOptions{
		Author: &object.Signature{Name: "seed", Email: "seed@example.com", When: fixedTime},
	}); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if _, err := repo.CreateRemote(&config.RemoteConfig{Name: "origin", URLs: []string{bare}}); err != nil {
		t.Fatalf("create remote: %v", err)
	}
	if err := repo.Push(&git.PushOptions{RemoteName: "origin"}); err != nil {
		t.Fatalf("push seed: %v", err)
	}
	return bare
}

func testPublisher(t *testing.T, remote, workDir string) *Publisher {
	t.Helper()
	return NewPublisher(remote, "master", nil,
		WithClock(func() time.Time { return fixedTime }),
		WithAuthor("flock-wrangler", "wrangler@example.com"),
		WithWorkDir(workDir),
	)
}

func TestPublisher_DirectPushRejectsConcurrentUpdate(t *testing.T) {
	t.Parallel()
	remote := newBareRemote(t)
	pub := testPublisher(t, remote, t.TempDir())
	pub.Option(WithDirectPush(true))
	other := testPublisher(t, remote, t.TempDir())
	other.Option(WithDirectPush(true))
	spec := validSpec()
	pub.Option(WithClock(func() time.Time {
		if _, err := other.Publish(context.Background(), spec, []File{{Name: "routes/other.json", Data: []byte("other\n")}}); err != nil {
			t.Fatal(err)
		}
		return fixedTime
	}))
	files := []File{{Name: "routes/demo.json", Data: []byte("demo\n")}}
	if _, err := pub.Publish(context.Background(), spec, files); err == nil {
		t.Fatal("concurrent remote update should reject the push")
	}
	remoteHead := headCommit(t, remote, "master")
	if _, err := remoteHead.File("routes/other.json"); err != nil {
		t.Fatal("concurrent update was lost:", err)
	}
	if _, err := remoteHead.File("routes/demo.json"); err == nil {
		t.Fatal("rejected push changed the remote")
	}
	pub.Option(WithClock(func() time.Time { return fixedTime }))
	if _, err := pub.Publish(context.Background(), spec, files); err != nil {
		t.Fatal("retry:", err)
	}
	retried := headCommit(t, remote, "master")
	for _, name := range []string{"routes/other.json", "routes/demo.json"} {
		if _, err := retried.File(name); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPublisher_DirectPush(t *testing.T) {
	t.Parallel()
	remote := newBareRemote(t)
	work := t.TempDir()
	pub := testPublisher(t, remote, work)
	pub.Option(WithDirectPush(true))
	spec := validSpec()
	files := []File{{Name: "routes/demo.json", Data: []byte("routing\n")}}
	branch, err := pub.Publish(context.Background(), spec, files)
	if err != nil || branch != "master" {
		t.Fatalf("branch=%q err=%v", branch, err)
	}
	first := headCommit(t, remote, "master")
	if _, err := first.File("routes/demo.json"); err != nil {
		t.Fatal(err)
	}
	if _, err := first.File("README.md"); err != nil {
		t.Fatal("existing files were lost:", err)
	}
	if _, err := pub.Publish(context.Background(), spec, files); err != nil {
		t.Fatal(err)
	}
	if headCommit(t, remote, "master").Hash != first.Hash {
		t.Fatal("unchanged retry created another commit")
	}
	files[0].Data = []byte("updated routing\n")
	if _, err := pub.Publish(context.Background(), spec, files); err != nil {
		t.Fatal(err)
	}
	updated := headCommit(t, remote, "master")
	if updated.Hash == first.Hash {
		t.Fatal("changed routing was not published")
	}
	if updated.ParentHashes[0] != first.Hash {
		t.Fatal("push did not preserve history")
	}
	bare, err := git.PlainOpen(remote)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bare.Reference(plumbing.NewBranchReferenceName(BranchName(spec)), true); !errors.Is(err, plumbing.ErrReferenceNotFound) {
		t.Fatalf("unexpected review branch: %v", err)
	}
	assertEmptyDir(t, work)
}

// C1: the branch carries the rendered files, committed with the configured
// author and clock.
func TestPublisher_Publish_Commit(t *testing.T) {
	t.Parallel()

	remote := newBareRemote(t)
	pub := testPublisher(t, remote, t.TempDir())

	spec := validSpec()
	files, err := Render(spec, appConfig())
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	branch, err := pub.Publish(context.Background(), spec, files)
	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	if want := "raven/create-ssg-dev"; branch != want {
		t.Fatalf("branch = %q, want %q", branch, want)
	}

	commit := headCommit(t, remote, branch)
	if got, want := commit.Author.Name, "flock-wrangler"; got != want {
		t.Errorf("author name = %q, want %q", got, want)
	}
	if got, want := commit.Author.Email, "wrangler@example.com"; got != want {
		t.Errorf("author email = %q, want %q", got, want)
	}
	if !commit.Author.When.Equal(fixedTime) {
		t.Errorf("author time = %v, want %v", commit.Author.When, fixedTime)
	}

	f, err := commit.File(files[0].Name)
	if err != nil {
		t.Fatalf("file %s missing from commit: %v", files[0].Name, err)
	}
	contents, err := f.Contents()
	if err != nil {
		t.Fatalf("contents: %v", err)
	}
	if contents != string(files[0].Data) {
		t.Errorf("committed contents = %q, want %q", contents, files[0].Data)
	}
}

// C2: the branch actually lands on the remote.
func TestPublisher_Publish_PushesBranch(t *testing.T) {
	t.Parallel()

	remote := newBareRemote(t)
	pub := testPublisher(t, remote, t.TempDir())

	spec := validSpec()
	files, err := Render(spec, appConfig())
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	branch, err := pub.Publish(context.Background(), spec, files)
	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}

	bare, err := git.PlainOpen(remote)
	if err != nil {
		t.Fatalf("open remote: %v", err)
	}
	ref := plumbing.NewBranchReferenceName(branch)
	if _, err := bare.Reference(ref, true); err != nil {
		t.Fatalf("remote missing %s: %v", ref, err)
	}
}

// C3: the temporary clone is removed on success and on failure.
func TestPublisher_Publish_CleansUpClone(t *testing.T) {
	t.Parallel()

	spec := validSpec()
	files, err := Render(spec, appConfig())
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	t.Run("on success", func(t *testing.T) {
		t.Parallel()
		work := t.TempDir()
		pub := testPublisher(t, newBareRemote(t), work)
		if _, err := pub.Publish(context.Background(), spec, files); err != nil {
			t.Fatalf("Publish() error = %v", err)
		}
		assertEmptyDir(t, work)
	})

	t.Run("on failure", func(t *testing.T) {
		t.Parallel()
		work := t.TempDir()
		pub := testPublisher(t, filepath.Join(t.TempDir(), "no-such-repo"), work)
		if _, err := pub.Publish(context.Background(), spec, files); err == nil {
			t.Fatal("Publish() = nil error, want clone failure")
		}
		assertEmptyDir(t, work)
	})
}

// C4: the branch name is deterministic, so a second publish must refuse
// rather than silently push again.
func TestPublisher_Publish_BranchExists(t *testing.T) {
	t.Parallel()

	remote := newBareRemote(t)
	spec := validSpec()
	files, err := Render(spec, appConfig())
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	first := testPublisher(t, remote, t.TempDir())
	branch, err := first.Publish(context.Background(), spec, files)
	if err != nil {
		t.Fatalf("first Publish() error = %v", err)
	}
	before := headCommit(t, remote, branch).Hash

	second := testPublisher(t, remote, t.TempDir())
	if _, err := second.Publish(context.Background(), spec, files); !errors.Is(err, ErrBranchExists) {
		t.Fatalf("second Publish() error = %v, want ErrBranchExists", err)
	}
	if after := headCommit(t, remote, branch).Hash; after != before {
		t.Errorf("remote branch moved from %s to %s, want untouched", before, after)
	}
}

func headCommit(t *testing.T, remote, branch string) *object.Commit {
	t.Helper()

	dir := t.TempDir()
	repo, err := git.PlainClone(dir, false, &git.CloneOptions{
		URL:           remote,
		ReferenceName: plumbing.NewBranchReferenceName(branch),
		SingleBranch:  true,
	})
	if err != nil {
		t.Fatalf("clone %s at %s: %v", remote, branch, err)
	}
	head, err := repo.Head()
	if err != nil {
		t.Fatalf("head: %v", err)
	}
	commit, err := repo.CommitObject(head.Hash())
	if err != nil {
		t.Fatalf("commit object: %v", err)
	}
	return commit
}

func assertEmptyDir(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	if len(entries) != 0 {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Fatalf("work dir %s still holds %v, want empty", dir, names)
	}
}
