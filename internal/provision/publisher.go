package provision

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport"
)

// ErrBranchExists reports that the deterministic branch for a spec is already
// present on the remote, so a previous publish already happened.
var ErrBranchExists = errors.New("branch already exists on remote")

// Publisher commits rendered files to a branch on the GitOps repository and
// pushes it for human review.
type Publisher struct {
	repoURL    string
	baseBranch string
	auth       transport.AuthMethod

	workDir     string
	now         func() time.Time
	authorName  string
	authorEmail string
}

// Option configures a Publisher and returns an Option that restores the
// previous value, so callers can defer the undo.
type Option func(*Publisher) Option

// WithClock sets the source of commit timestamps.
func WithClock(now func() time.Time) Option {
	return func(p *Publisher) Option {
		previous := p.now
		p.now = now
		return WithClock(previous)
	}
}

// WithAuthor sets the commit author.
func WithAuthor(name, email string) Option {
	return func(p *Publisher) Option {
		prevName, prevEmail := p.authorName, p.authorEmail
		p.authorName, p.authorEmail = name, email
		return WithAuthor(prevName, prevEmail)
	}
}

// WithWorkDir sets the parent directory for the throwaway clone. Empty means
// the system temp directory.
func WithWorkDir(dir string) Option {
	return func(p *Publisher) Option {
		previous := p.workDir
		p.workDir = dir
		return WithWorkDir(previous)
	}
}

// Option applies opts and returns an Option that restores the last one.
func (p *Publisher) Option(opts ...Option) (previous Option) {
	for _, opt := range opts {
		previous = opt(p)
	}
	return previous
}

// NewPublisher returns a Publisher for repoURL. auth may be nil for local or
// unauthenticated remotes.
func NewPublisher(repoURL, baseBranch string, auth transport.AuthMethod, opts ...Option) *Publisher {
	p := &Publisher{
		repoURL:     repoURL,
		baseBranch:  baseBranch,
		auth:        auth,
		now:         time.Now,
		authorName:  "flock-wrangler",
		authorEmail: "flock-wrangler@localhost",
	}
	p.Option(opts...)
	return p
}

// BranchName is the deterministic branch a spec publishes to. Deterministic
// so a retry collides with the first attempt instead of opening a second
// pull request.
func BranchName(spec RavenSpec) string {
	return "raven/create-" + spec.Name
}

// Publish clones the repository, commits files on a fresh branch and pushes
// it. The working clone is always removed. It returns the branch name.
func (p *Publisher) Publish(ctx context.Context, spec RavenSpec, files []File) (string, error) {
	branch := BranchName(spec)

	dir, err := os.MkdirTemp(p.workDir, "raven-publish-")
	if err != nil {
		return "", fmt.Errorf("create work dir: %w", err)
	}
	defer os.RemoveAll(dir)

	repo, err := git.PlainCloneContext(ctx, dir, false, &git.CloneOptions{
		URL:           p.repoURL,
		Auth:          p.auth,
		ReferenceName: plumbing.NewBranchReferenceName(p.baseBranch),
		SingleBranch:  true,
	})
	if err != nil {
		return "", fmt.Errorf("clone %s: %w", p.repoURL, err)
	}

	// Ask the remote rather than the clone: a single-branch clone never
	// fetches the target branch, so a local ref lookup would always miss.
	origin, err := repo.Remote("origin")
	if err != nil {
		return "", fmt.Errorf("remote origin: %w", err)
	}
	refs, err := origin.ListContext(ctx, &git.ListOptions{Auth: p.auth})
	if err != nil {
		return "", fmt.Errorf("list remote refs: %w", err)
	}
	branchRef := plumbing.NewBranchReferenceName(branch)
	for _, ref := range refs {
		if ref.Name() == branchRef {
			return "", fmt.Errorf("%s: %w", branch, ErrBranchExists)
		}
	}

	wt, err := repo.Worktree()
	if err != nil {
		return "", fmt.Errorf("worktree: %w", err)
	}
	if err := wt.Checkout(&git.CheckoutOptions{
		Branch: plumbing.NewBranchReferenceName(branch),
		Create: true,
	}); err != nil {
		return "", fmt.Errorf("checkout %s: %w", branch, err)
	}

	for _, f := range files {
		path := filepath.Join(dir, filepath.FromSlash(f.Name))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return "", fmt.Errorf("mkdir for %s: %w", f.Name, err)
		}
		if err := os.WriteFile(path, f.Data, 0o600); err != nil {
			return "", fmt.Errorf("write %s: %w", f.Name, err)
		}
		if _, err := wt.Add(f.Name); err != nil {
			return "", fmt.Errorf("stage %s: %w", f.Name, err)
		}
	}

	msg := fmt.Sprintf("Add ArgoCD Application for raven %s", spec.Name)
	if _, err := wt.Commit(msg, &git.CommitOptions{
		Author: &object.Signature{
			Name:  p.authorName,
			Email: p.authorEmail,
			When:  p.now(),
		},
	}); err != nil {
		return "", fmt.Errorf("commit: %w", err)
	}

	if err := repo.PushContext(ctx, &git.PushOptions{
		RemoteName: "origin",
		Auth:       p.auth,
	}); err != nil {
		return "", fmt.Errorf("push %s: %w", branch, err)
	}
	return branch, nil
}
