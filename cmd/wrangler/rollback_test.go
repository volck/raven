package main

import (
	"context"
	"errors"
	"testing"
)

func TestProvisionRaven_RevokesTokenStrandedOutsideTheCluster(t *testing.T) {
	t.Parallel()

	deps, vault, applier, _ := newTestDeps()
	applier.applyErr = errors.New("namespace quota exceeded")

	_, report, err := provisionRaven(context.Background(), deps, wranglerSpec(), false)
	if err == nil {
		t.Fatal("expected the cluster stage to fail")
	}

	if got := vault.revokedTokens(); len(got) != 1 || got[0] != testToken {
		t.Errorf("revoked %v, want the minted token revoked exactly once", got)
	}
	if report.orphanedToken() {
		t.Error("still reported as orphaned after the token was revoked")
	}
	if report.statusOf(stageVault) != statusRolledBack {
		t.Errorf("vault stage = %q, want %q", report.statusOf(stageVault), statusRolledBack)
	}
}

// Once the token Secret is in the cluster a retry can finish the job, so
// revoking would strand a raven that is already using the credential.
func TestProvisionRaven_KeepsTokenAlreadyInTheCluster(t *testing.T) {
	t.Parallel()

	deps, vault, applier, _ := newTestDeps()
	applier.applyErr = errors.New("route admission webhook rejected")
	applier.applyCreatesSecret = true

	_, report, err := provisionRaven(context.Background(), deps, wranglerSpec(), false)
	if err == nil {
		t.Fatal("expected the cluster stage to fail")
	}

	if got := vault.revokedTokens(); len(got) != 0 {
		t.Errorf("revoked %v, want the token left for the retry to reuse", got)
	}
	if !report.orphanedToken() {
		t.Error("a half-applied raven should still be flagged for attention")
	}
}

// A retry reuses an existing token; it is not wrangler's to revoke.
func TestProvisionRaven_NeverRevokesAReusedToken(t *testing.T) {
	t.Parallel()

	deps, vault, applier, _ := newTestDeps()
	applier.tokenExists = true
	applier.applyErr = errors.New("cluster unreachable")

	if _, _, err := provisionRaven(context.Background(), deps, wranglerSpec(), false); err == nil {
		t.Fatal("expected the cluster stage to fail")
	}

	if got := vault.revokedTokens(); len(got) != 0 {
		t.Errorf("revoked %v, want a reused token left alone", got)
	}
}

// The raven is running by the time git is attempted; its token must survive.
func TestProvisionRaven_KeepsTokenWhenOnlyGitFails(t *testing.T) {
	t.Parallel()

	deps, vault, _, publisher := newTestDeps()
	publisher.err = errors.New("remote rejected the branch")

	_, report, err := provisionRaven(context.Background(), deps, wranglerSpec(), false)
	if err == nil {
		t.Fatal("expected the git stage to fail")
	}

	if got := vault.revokedTokens(); len(got) != 0 {
		t.Errorf("revoked %v, want the running raven's token kept", got)
	}
	if report.statusOf(stageVault) != statusDone {
		t.Errorf("vault stage = %q, want it left alone", report.statusOf(stageVault))
	}
}

// A failed revoke must not mask the error that triggered it.
func TestProvisionRaven_ReportsFailedRevoke(t *testing.T) {
	t.Parallel()

	deps, vault, applier, _ := newTestDeps()
	applier.applyErr = errors.New("namespace quota exceeded")
	vault.revokeErr = errors.New("vault unreachable")

	_, report, err := provisionRaven(context.Background(), deps, wranglerSpec(), false)
	if err == nil {
		t.Fatal("expected the cluster stage to fail")
	}
	if !errors.Is(err, applier.applyErr) {
		t.Errorf("error = %v, want the original cluster failure preserved", err)
	}
	if !report.orphanedToken() {
		t.Error("a token that could not be revoked must stay flagged")
	}
}
