package auditlog

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport"
	yaml "gopkg.in/yaml.v3"
)

// GitSource implements Source by cloning a git repository on first Load and
// fetching incrementally on subsequent Loads. The clone lives on disk for
// the lifetime of the GitSource so each Load only transfers what changed.
type GitSource struct {
	cfg  GitSourceConfig
	auth transport.AuthMethod

	mu      sync.Mutex
	repo    *git.Repository
	workdir string
	logger  *slog.Logger
}

// NewGitSource constructs a GitSource. The clone directory is created on
// first Load.
func NewGitSource(cfg GitSourceConfig) *GitSource {
	return &GitSource{cfg: cfg}
}

// SetAuth replaces the authentication method used by subsequent operations.
func (g *GitSource) SetAuth(auth transport.AuthMethod) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.auth = auth
}

// SetLogger installs the logger used for warnings such as force-resets.
// A nil logger silences output.
func (g *GitSource) SetLogger(l *slog.Logger) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.logger = l
}

func (g *GitSource) log() *slog.Logger {
	if g.logger == nil {
		return slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return g.logger
}

// WorkDir returns the on-disk path of the persistent clone, or "" if Load
// has never succeeded.
func (g *GitSource) WorkDir() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.workdir
}

// Load returns the RoutingConfig parsed from cfg.Path on the configured
// branch. The first Load clones the repository; subsequent Loads fetch
// from origin and fast-forward the local working copy.
func (g *GitSource) Load(ctx context.Context) (RoutingConfig, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.repo == nil {
		if err := g.cloneLocked(ctx); err != nil {
			return RoutingConfig{}, err
		}
	} else {
		if err := g.fetchAndCheckoutLocked(ctx); err != nil {
			return RoutingConfig{}, err
		}
	}

	return g.readRoutingLocked()
}

func (g *GitSource) cloneLocked(ctx context.Context) error {
	dir, err := os.MkdirTemp("", "raven-logparser-git-*")
	if err != nil {
		return fmt.Errorf("create workdir: %w", err)
	}
	repo, err := git.PlainCloneContext(ctx, dir, false, &git.CloneOptions{
		URL:           g.cfg.URL,
		ReferenceName: plumbing.NewBranchReferenceName(g.cfg.Branch),
		SingleBranch:  true,
		Auth:          g.auth,
	})
	if err != nil {
		_ = os.RemoveAll(dir)
		return fmt.Errorf("clone %s branch=%s: %w", g.cfg.URL, g.cfg.Branch, err)
	}
	g.repo = repo
	g.workdir = dir
	return nil
}

func (g *GitSource) fetchAndCheckoutLocked(ctx context.Context) error {
	refName := plumbing.NewRemoteReferenceName("origin", g.cfg.Branch)

	var oldHash plumbing.Hash
	if ref, err := g.repo.Reference(refName, true); err == nil {
		oldHash = ref.Hash()
	}

	err := g.repo.FetchContext(ctx, &git.FetchOptions{
		Auth:  g.auth,
		Force: true,
	})
	if err != nil && err != git.NoErrAlreadyUpToDate {
		return fmt.Errorf("fetch %s: %w", g.cfg.URL, err)
	}
	remoteRef, err := g.repo.Reference(refName, true)
	if err != nil {
		return fmt.Errorf("resolve origin/%s: %w", g.cfg.Branch, err)
	}
	newHash := remoteRef.Hash()

	if !oldHash.IsZero() && oldHash != newHash {
		isFF, ffErr := g.isFastForward(oldHash, newHash)
		if ffErr == nil && !isFF {
			g.log().Warn("routing.force_reset",
				"old", oldHash.String(),
				"new", newHash.String(),
				"branch", g.cfg.Branch,
			)
		}
	}

	wt, err := g.repo.Worktree()
	if err != nil {
		return fmt.Errorf("worktree: %w", err)
	}
	if err := wt.Checkout(&git.CheckoutOptions{
		Hash:  newHash,
		Force: true,
	}); err != nil {
		return fmt.Errorf("checkout %s: %w", newHash, err)
	}
	return nil
}

// isFastForward reports whether newHash is a descendant of oldHash (i.e.
// the update preserves history). Returns false on history rewrites.
func (g *GitSource) isFastForward(oldHash, newHash plumbing.Hash) (bool, error) {
	oldCommit, err := g.repo.CommitObject(oldHash)
	if err != nil {
		// old commit no longer reachable in object DB → history rewrite.
		return false, nil
	}
	newCommit, err := g.repo.CommitObject(newHash)
	if err != nil {
		return false, err
	}
	isAnc, err := oldCommit.IsAncestor(newCommit)
	if err != nil {
		return false, err
	}
	return isAnc, nil
}

func (g *GitSource) readRoutingLocked() (RoutingConfig, error) {
	full := filepath.Join(g.workdir, g.cfg.Path)
	f, err := os.Open(full)
	if err != nil {
		return RoutingConfig{}, fmt.Errorf("open %s: %w", g.cfg.Path, err)
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return RoutingConfig{}, fmt.Errorf("read %s: %w", g.cfg.Path, err)
	}

	var cfg RoutingConfig
	if isYAMLPath(g.cfg.Path) {
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return RoutingConfig{}, fmt.Errorf("parse %s: %w", g.cfg.Path, err)
		}
	} else {
		if err := json.Unmarshal(data, &cfg); err != nil {
			return RoutingConfig{}, fmt.Errorf("parse %s: %w", g.cfg.Path, err)
		}
	}
	return cfg, nil
}

func isYAMLPath(p string) bool {
	lower := strings.ToLower(p)
	return strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml")
}
