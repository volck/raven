package provision

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/storage/memory"
)

// SeedRepo pushes an initial commit creating filePath, and reports whether it
// wrote anything. A freshly created repository has no commits, which makes
// raven's clone fail and leaves ArgoCD no path to sync. A repository that
// already has branches is left untouched, so a retry cannot rewrite history
// over live sealed secrets.
func SeedRepo(ctx context.Context, repoURL, branch, filePath string, auth transport.AuthMethod) (bool, error) {
	clean := path.Clean(filePath)
	if clean == "." || path.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, "../") {
		return false, fmt.Errorf("seed path %q must stay inside the repository", filePath)
	}

	empty, err := remoteIsEmpty(ctx, repoURL, auth)
	if err != nil {
		return false, err
	}
	if !empty {
		return false, nil
	}

	dir, err := os.MkdirTemp("", "raven-seed-")
	if err != nil {
		return false, fmt.Errorf("create work dir: %w", err)
	}
	defer os.RemoveAll(dir)

	repo, err := git.PlainInit(dir, false)
	if err != nil {
		return false, fmt.Errorf("init seed repo: %w", err)
	}

	full := filepath.Join(dir, filepath.FromSlash(clean))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return false, fmt.Errorf("create seed path: %w", err)
	}
	if err := os.WriteFile(full, nil, 0o644); err != nil {
		return false, fmt.Errorf("write seed file: %w", err)
	}

	worktree, err := repo.Worktree()
	if err != nil {
		return false, fmt.Errorf("worktree: %w", err)
	}
	if _, err := worktree.Add(clean); err != nil {
		return false, fmt.Errorf("stage %s: %w", clean, err)
	}
	if _, err := worktree.Commit("Initialise sealed secrets path", &git.CommitOptions{
		Author: &object.Signature{Name: "flock-wrangler", Email: "flock-wrangler@localhost", When: time.Now()},
	}); err != nil {
		return false, fmt.Errorf("commit seed: %w", err)
	}

	if _, err := repo.CreateRemote(&gitconfig.RemoteConfig{Name: "origin", URLs: []string{repoURL}}); err != nil {
		return false, fmt.Errorf("add remote: %w", err)
	}
	// Push the resolved local ref rather than HEAD, which go-git does not
	// accept as a refspec source, onto the branch the caller asked for.
	head, err := repo.Head()
	if err != nil {
		return false, fmt.Errorf("resolve head: %w", err)
	}
	refspec := gitconfig.RefSpec(fmt.Sprintf("+%s:refs/heads/%s", head.Name(), branch))
	if err := repo.PushContext(ctx, &git.PushOptions{
		RemoteName: "origin",
		Auth:       auth,
		RefSpecs:   []gitconfig.RefSpec{refspec},
	}); err != nil {
		return false, fmt.Errorf("push seed commit to %s: %w", repoURL, err)
	}

	return true, nil
}

// remoteIsEmpty reports whether the remote holds no branches. Asking the
// remote avoids cloning a repository that may be empty.
func remoteIsEmpty(ctx context.Context, repoURL string, auth transport.AuthMethod) (bool, error) {
	remote := git.NewRemote(memory.NewStorage(), &gitconfig.RemoteConfig{
		Name: "origin",
		URLs: []string{repoURL},
	})

	refs, err := remote.ListContext(ctx, &git.ListOptions{Auth: auth})
	if errors.Is(err, transport.ErrEmptyRemoteRepository) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("list remote refs on %s: %w", repoURL, err)
	}

	for _, ref := range refs {
		if ref.Name().IsBranch() {
			return false, nil
		}
	}
	return true, nil
}
