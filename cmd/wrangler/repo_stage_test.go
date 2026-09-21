package main

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/volck/raven/internal/provision"
)

type fakeRepos struct {
	calls int
	err   error
}

func (f *fakeRepos) EnsureRepo(_ context.Context, _ provision.RavenSpec) error {
	f.calls++
	return f.err
}

func stageStatus(t *testing.T, results []stageResult, stage string) string {
	t.Helper()

	for _, r := range results {
		if r.Stage == stage {
			return r.Status
		}
	}
	t.Fatalf("stage %q missing from report", stage)
	return ""
}

// The repository must exist before the cluster is told to use it, and before a
// token is minted, so a repository failure cannot orphan a credential.
func TestProvisionRaven_RepoFailureMintsNoToken(t *testing.T) {
	t.Parallel()

	deps, vault, applier, publisher := newTestDeps()
	repos := &fakeRepos{err: errors.New("bitbucket unavailable")}
	deps.repos = repos

	rec := post(t, deps, validBody())

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	if vault.tokens != 0 {
		t.Errorf("minted %d tokens, want 0", vault.tokens)
	}
	if applier.applied != 0 {
		t.Errorf("applied %d times, want 0", applier.applied)
	}
	if publisher.callCount() != 0 {
		t.Errorf("published %d times, want 0", publisher.callCount())
	}
}

func TestProvisionRaven_EnsuresRepo(t *testing.T) {
	t.Parallel()

	deps, _, _, _ := newTestDeps()
	repos := &fakeRepos{}
	deps.repos = repos

	rec := post(t, deps, validBody())

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusAccepted, rec.Body.String())
	}
	if repos.calls != 1 {
		t.Errorf("EnsureRepo calls = %d, want 1", repos.calls)
	}
}

// Bitbucket is optional: deployments without it must still provision.
func TestProvisionRaven_SkipsRepoStageWhenUnconfigured(t *testing.T) {
	t.Parallel()

	deps, _, _, _ := newTestDeps()

	_, report, err := provisionRaven(context.Background(), deps, provision.RavenSpec{
		Name: "dev", Namespace: "ssg", SecretEngine: "kv", DestEnv: "dev",
		RepoURL: testRepoURL, Image: testImage,
	}, false)
	if err != nil {
		t.Fatalf("provisionRaven: %v", err)
	}
	if got := stageStatus(t, report.results(), stageRepo); got != statusSkipped {
		t.Errorf("repo stage = %q, want %q", got, statusSkipped)
	}
}
