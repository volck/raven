package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func stagesOf(t *testing.T, rec *httptest.ResponseRecorder) map[string]string {
	t.Helper()

	var body struct {
		Stages []stageResult `json:"stages"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response %q: %v", rec.Body, err)
	}
	if len(body.Stages) == 0 {
		t.Fatalf("response carries no stage report: %s", rec.Body)
	}

	got := map[string]string{}
	for _, stage := range body.Stages {
		got[stage.Stage] = stage.Status
	}
	return got
}

func assertStages(t *testing.T, got map[string]string, want map[string]string) {
	t.Helper()

	for stage, status := range want {
		if got[stage] != status {
			t.Errorf("stage %q = %q, want %q (all: %v)", stage, got[stage], status, got)
		}
	}
}

// A failure part-way through must say how far it got, so an operator knows
// whether a token was minted and whether cluster objects exist.
func TestHandleCreateRaven_ReportsProgressOnClusterFailure(t *testing.T) {
	t.Parallel()

	deps, _, applier, _ := newTestDeps()
	applier.applyErr = errors.New("route admission webhook rejected")

	rec := post(t, deps, validBody())

	assertStages(t, stagesOf(t, rec), map[string]string{
		stagePreflight: statusDone,
		stageVault:     statusRolledBack,
		stageCluster:   statusFailed,
		stageGit:       statusPending,
	})
}

func TestHandleCreateRaven_ReportsProgressOnPreflightFailure(t *testing.T) {
	t.Parallel()

	deps, _, applier, _ := newTestDeps()
	applier.preflightErr = errors.New("secret \"ssc\" not found")

	rec := post(t, deps, validBody())

	assertStages(t, stagesOf(t, rec), map[string]string{
		stagePreflight: statusFailed,
		stageVault:     statusPending,
		stageCluster:   statusPending,
		stageGit:       statusPending,
	})
}

func TestHandleCreateRaven_ReportsProgressOnSuccess(t *testing.T) {
	t.Parallel()

	deps, _, _, _ := newTestDeps()
	rec := post(t, deps, validBody())

	assertStages(t, stagesOf(t, rec), map[string]string{
		stagePreflight: statusDone,
		stageVault:     statusDone,
		stageCluster:   statusDone,
		stageGit:       statusDone,
	})
}

// A retry reuses the existing token, and the report must show that rather
// than implying a second one was minted.
func TestHandleCreateRaven_ReportsSkippedVaultOnRetry(t *testing.T) {
	t.Parallel()

	deps, _, applier, _ := newTestDeps()
	applier.tokenExists = true

	rec := post(t, deps, validBody())

	assertStages(t, stagesOf(t, rec), map[string]string{stageVault: statusSkipped})
}

// A token that reached the cluster cannot be revoked without stranding a
// half-built raven, so it stays live and must be alerted on.
func TestHandleCreateRaven_AlertsOnOrphanedToken(t *testing.T) {
	t.Parallel()

	deps, _, applier, _ := newTestDeps()
	applier.applyErr = errors.New("route admission webhook rejected")
	applier.applyCreatesSecret = true

	var logs strings.Builder
	deps.logger = testLogger(&logs)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ravens", strings.NewReader(validBody()))
	req = req.WithContext(context.WithValue(req.Context(), claimsKey, testClaims()))
	rec := httptest.NewRecorder()
	handleCreateRaven(deps).ServeHTTP(rec, req)

	logged := logs.String()
	if !strings.Contains(logged, "orphaned") {
		t.Errorf("no orphaned-token alert in logs: %s", logged)
	}
	for _, want := range []string{"ssg-dev", "raven-ssg-dev", testClaims().Subject} {
		if !strings.Contains(logged, want) {
			t.Errorf("alert missing %q: %s", want, logged)
		}
	}
	if strings.Contains(logged, testToken) {
		t.Error("alert leaks the token value")
	}
}

// Nothing was minted, so there is nothing to alert about.
func TestHandleCreateRaven_NoOrphanAlertWhenVaultNeverRan(t *testing.T) {
	t.Parallel()

	deps, _, applier, _ := newTestDeps()
	applier.preflightErr = errors.New("namespace missing")

	var logs strings.Builder
	deps.logger = testLogger(&logs)

	post(t, deps, validBody())

	if strings.Contains(logs.String(), "orphaned") {
		t.Errorf("alerted about an orphan that was never created: %s", logs.String())
	}
}

// A reused token belongs to the earlier attempt and is not newly orphaned.
func TestHandleCreateRaven_NoOrphanAlertOnRetry(t *testing.T) {
	t.Parallel()

	deps, _, applier, _ := newTestDeps()
	applier.tokenExists = true
	applier.applyErr = errors.New("still broken")

	var logs strings.Builder
	deps.logger = testLogger(&logs)

	post(t, deps, validBody())

	if strings.Contains(logs.String(), "orphaned") {
		t.Errorf("alerted about a pre-existing token: %s", logs.String())
	}
}

func TestHandleCreateRaven_ErrorBodyIsJSON(t *testing.T) {
	t.Parallel()

	deps, _, applier, _ := newTestDeps()
	applier.applyErr = errors.New("boom")

	rec := post(t, deps, validBody())

	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Errorf("Content-Type = %q, want JSON", got)
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Error == "" {
		t.Error("error body has no message")
	}
}
