package main

import (
	"context"
	"errors"
	"testing"
)

func TestProvisionRaven_ForceRecreates(t *testing.T) {
	t.Parallel()

	deps, _, applier, _ := newTestDeps()

	if _, _, err := provisionRaven(context.Background(), deps, wranglerSpec(), true); err != nil {
		t.Fatalf("provisionRaven() error = %v", err)
	}
	if applier.deleted != 1 {
		t.Errorf("deleted %d times, want 1", applier.deleted)
	}
	if applier.applied != 1 {
		t.Errorf("applied %d times, want 1", applier.applied)
	}
	if !applier.forced {
		t.Error("Preflight was not told the request was forced")
	}
}

func TestProvisionRaven_WithoutForceDeletesNothing(t *testing.T) {
	t.Parallel()

	deps, _, applier, _ := newTestDeps()

	if _, _, err := provisionRaven(context.Background(), deps, wranglerSpec(), false); err != nil {
		t.Fatalf("provisionRaven() error = %v", err)
	}
	if applier.deleted != 0 {
		t.Errorf("deleted %d times, want 0", applier.deleted)
	}
}

// A forced request must not tear down a working raven before the stages that
// can still fail have passed.
func TestProvisionRaven_ForceKeepsRavenWhenAnEarlierStageFails(t *testing.T) {
	t.Parallel()

	deps, _, applier, _ := newTestDeps()
	deps.repos = &fakeRepos{err: errors.New("bitbucket unreachable")}

	if _, _, err := provisionRaven(context.Background(), deps, wranglerSpec(), true); err == nil {
		t.Fatal("provisionRaven() = nil, want error")
	}
	if applier.deleted != 0 {
		t.Errorf("deleted %d times after the repo stage failed, want 0", applier.deleted)
	}
}

// force is a caller decision, so it has to survive decoding rather than being
// silently rejected as an unknown field.
func TestHandleCreateRaven_ForceReachesTheApplier(t *testing.T) {
	t.Parallel()

	deps, _, applier, _ := newTestDeps()
	body := `{"name":"ssg-dev","secretEngine":"kv","destEnv":"dev",
		"repoURL":"ssh://git@example.com/r.git","force":true}`

	if rec := post(t, deps, body); rec.Code != 202 {
		t.Fatalf("status = %d, want 202: %s", rec.Code, rec.Body)
	}
	if applier.deleted != 1 {
		t.Errorf("deleted %d times, want 1", applier.deleted)
	}
}
