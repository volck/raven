package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/volck/raven/internal/bitbucket"
	"github.com/volck/raven/internal/provision"
)

type argoPublisher struct {
	publisher  ravenPublisher
	client     *bitbucket.Client
	repo       bitbucket.Repo
	baseBranch string
	logger     *slog.Logger
}

func newArgoPublisher(cfg config, gitAuth transport.AuthMethod, logger *slog.Logger) (ravenPublisher, error) {
	publisher := provision.NewPublisher(cfg.argoRepoURL, cfg.argoBaseBranch, gitAuth)
	if cfg.bitbucketURL == "" {
		logger.Info("bitbucket not configured: ArgoCD pull requests must be opened manually")
		return publisher, nil
	}
	repo, err := bitbucket.ParseRepoURL(cfg.argoRepoURL)
	if err != nil {
		return nil, fmt.Errorf("ArgoCD repository: %w", err)
	}
	client, err := bitbucket.New(cfg.bitbucketURL, valueOr(cfg.argoBitbucketToken, cfg.bitbucketToken), bitbucket.WithLogger(logger))
	if err != nil {
		return nil, err
	}
	return &argoPublisher{publisher: publisher, client: client, repo: repo, baseBranch: cfg.argoBaseBranch, logger: logger}, nil
}

func (p *argoPublisher) Publish(ctx context.Context, spec provision.RavenSpec, files []provision.File) (string, error) {
	branch, err := p.publisher.Publish(ctx, spec, files)
	if err != nil {
		if !errors.Is(err, provision.ErrBranchExists) {
			return "", err
		}
		branch = provision.BranchName(spec)
	}
	link, err := p.client.EnsurePullRequest(ctx, p.repo, branch, p.baseBranch, "Add ArgoCD Application for raven "+spec.Name)
	if err != nil {
		return "", fmt.Errorf("ArgoCD pull request: %w", err)
	}
	p.logger.InfoContext(ctx, "ArgoCD pull request ready", "raven", spec.Name, "branch", branch, "url", link)
	return branch, nil
}
