package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path"

	"github.com/go-git/go-git/v5/plumbing/transport"

	"github.com/volck/raven/internal/bitbucket"
	"github.com/volck/raven/internal/provision"
)

// seedBranch matches Bitbucket's default branch for new repositories. Seeding
// onto any other branch would leave HEAD dangling and ArgoCD with nothing to
// resolve.
const seedBranch = "master"

// newRepos returns nil when Bitbucket is unconfigured, which skips the stage
// and leaves repository creation a manual step.
func newRepos(cfg config, auth transport.AuthMethod, logger *slog.Logger) (repoProvisioner, error) {
	if cfg.bitbucketURL == "" {
		logger.Info("bitbucket not configured: sealed secrets repositories must already exist")
		return nil, nil
	}

	client, err := bitbucket.New(cfg.bitbucketURL, cfg.bitbucketToken, bitbucket.WithLogger(logger))
	if err != nil {
		return nil, fmt.Errorf("bitbucket client: %w", err)
	}

	return newRepoEnsurer(client, cfg.bitbucketUser, cfg.argocdReaderKey, seedBranch, auth, logger), nil
}

// repoEnsurer makes the repository raven pushes sealed secrets to exist, and
// grants raven write access and ArgoCD read access to it.
type repoEnsurer struct {
	client *bitbucket.Client
	// user is the Bitbucket account granted write access on every repository.
	user string
	// readerKey is ArgoCD's public key, registered read-only so it can sync
	// what raven pushes.
	readerKey string
	branch    string
	// seed is injected so tests can exercise the Bitbucket calls without git.
	seed   func(ctx context.Context, repoURL, branch, filePath string) (bool, error)
	logger *slog.Logger
}

func newRepoEnsurer(client *bitbucket.Client, user, readerKey, branch string, auth transport.AuthMethod, logger *slog.Logger) *repoEnsurer {
	return &repoEnsurer{
		client:    client,
		user:      user,
		readerKey: readerKey,
		branch:    branch,
		seed: func(ctx context.Context, repoURL, branch, filePath string) (bool, error) {
			return provision.SeedRepo(ctx, repoURL, branch, filePath, auth)
		},
		logger: logger,
	}
}

// EnsureRepo creates the repository when it is absent and adopts it when it is
// not. Every step tolerates the "already done" outcome, so a retried provision
// converges instead of failing. It never deletes anything: a retry that lands
// on a populated repository must not destroy the secrets already in it.
func (e *repoEnsurer) EnsureRepo(ctx context.Context, spec provision.RavenSpec) error {
	repo, err := bitbucket.ParseRepoURL(spec.RepoURL)
	if err != nil {
		return err
	}

	existing, err := e.client.GetRepo(ctx, repo)
	switch {
	case errors.Is(err, bitbucket.ErrNotFound):
		if _, err := e.client.CreateRepo(ctx, repo); err != nil && !errors.Is(err, bitbucket.ErrAlreadyExists) {
			return err
		}
	case err != nil:
		return err
	case existing.Archived:
		return fmt.Errorf("repository %s is archived and accepts no pushes", spec.RepoURL)
	}

	if err := e.client.AddUserPermission(ctx, repo, e.user, "REPO_WRITE"); err != nil {
		return err
	}

	if err := e.client.AddAccessKey(ctx, repo, e.readerKey, "REPO_READ"); err != nil {
		return err
	}

	seeded, err := e.seed(ctx, spec.RepoURL, e.branch, path.Join(spec.SealedSecretsPath(), ".gitkeep"))
	if err != nil {
		return err
	}
	if seeded && e.logger != nil {
		e.logger.InfoContext(ctx, "seeded sealed secrets repository", "repo", spec.RepoURL, "branch", e.branch)
	}
	return nil
}
