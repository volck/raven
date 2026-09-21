package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func fixedClock(start time.Time) func() time.Time {
	var mu sync.Mutex
	current := start
	return func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		current = current.Add(time.Second)
		return current
	}
}

func testJournal(t *testing.T, size int) *journal {
	t.Helper()
	return newJournal(size, withJournalClock(fixedClock(time.Unix(0, 0).UTC())))
}

func TestJournal_RecordsOutcome(t *testing.T) {
	t.Parallel()

	j := testJournal(t, 10)
	report := newProgress(stagePreflight, stageVault, stageCluster, stageGit)
	report.set(stagePreflight, statusDone, "")
	report.set(stageVault, statusDone, "")
	report.set(stageCluster, statusFailed, "route rejected")

	j.record(rollout{
		Raven:     "ssg-dev",
		Namespace: "ssg",
		Engine:    "kv",
		Actor:     "system:serviceaccount:ci:provisioner",
		Succeeded: false,
		Stages:    report.results(),
	})

	entries := j.recent()
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	got := entries[0]
	if got.Raven != "ssg-dev" || got.Namespace != "ssg" || got.Engine != "kv" {
		t.Errorf("identity not recorded: %+v", got)
	}
	if got.Succeeded {
		t.Error("failed rollout recorded as succeeded")
	}
	if got.Time.IsZero() {
		t.Error("rollout has no timestamp")
	}
	if len(got.Stages) != 4 {
		t.Errorf("got %d stages, want all 4 reported", len(got.Stages))
	}
}

// Newest first, so a dashboard shows the latest rollout without sorting.
func TestJournal_NewestFirst(t *testing.T) {
	t.Parallel()

	j := testJournal(t, 10)
	for _, name := range []string{"first", "second", "third"} {
		j.record(rollout{Raven: name})
	}

	entries := j.recent()
	want := []string{"third", "second", "first"}
	for i, name := range want {
		if entries[i].Raven != name {
			t.Errorf("entry[%d] = %q, want %q", i, entries[i].Raven, name)
		}
	}
}

func TestJournal_EvictsOldest(t *testing.T) {
	t.Parallel()

	j := testJournal(t, 2)
	for _, name := range []string{"first", "second", "third"} {
		j.record(rollout{Raven: name})
	}

	entries := j.recent()
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want the journal capped at 2", len(entries))
	}
	for _, entry := range entries {
		if entry.Raven == "first" {
			t.Error("oldest entry was not evicted")
		}
	}
}

// recent() is read while requests are still writing.
func TestJournal_ConcurrentUse(t *testing.T) {
	t.Parallel()

	j := testJournal(t, 50)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			j.record(rollout{Raven: "ssg-dev"})
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = j.recent()
		}()
	}
	wg.Wait()
}

// A snapshot must not alias the journal's own storage.
func TestJournal_RecentIsACopy(t *testing.T) {
	t.Parallel()

	j := testJournal(t, 10)
	j.record(rollout{Raven: "ssg-dev"})

	entries := j.recent()
	entries[0].Raven = "tampered"

	if j.recent()[0].Raven != "ssg-dev" {
		t.Error("mutating the snapshot changed the journal")
	}
}

func TestHandleListRollouts(t *testing.T) {
	t.Parallel()

	j := testJournal(t, 10)
	report := newProgress(stagePreflight, stageVault, stageCluster, stageGit)
	report.set(stagePreflight, statusDone, "")
	j.record(rollout{Raven: "ssg-dev", Namespace: "ssg", Engine: "kv", Succeeded: true, Stages: report.results()})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/rollouts", nil)
	rec := httptest.NewRecorder()
	handleListRollouts(j).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Errorf("content-type = %q", got)
	}

	var body struct {
		Rollouts []rollout `json:"rollouts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Rollouts) != 1 {
		t.Fatalf("got %d rollouts, want 1", len(body.Rollouts))
	}
	if body.Rollouts[0].Stages[0].Stage != stagePreflight {
		t.Errorf("stages not serialised: %+v", body.Rollouts[0])
	}
}

// An empty journal must serialise as [] so clients can iterate it.
func TestHandleListRollouts_EmptyIsAnArray(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/rollouts", nil)
	rec := httptest.NewRecorder()
	handleListRollouts(testJournal(t, 10)).ServeHTTP(rec, req)

	if !strings.Contains(rec.Body.String(), `"rollouts":[]`) {
		t.Errorf("empty journal did not serialise as an array: %s", rec.Body)
	}
}

// A rollout that dies midway is exactly the one worth seeing afterwards.
func TestHandleCreateRaven_JournalsFailedRollout(t *testing.T) {
	t.Parallel()

	deps, _, applier, _ := newTestDeps()
	applier.applyErr = errors.New("route admission webhook rejected")
	deps.journal = testJournal(t, 10)
	deps.logger = testLogger(io.Discard)

	if rec := post(t, deps, validBody()); rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}

	entries := deps.journal.recent()
	if len(entries) != 1 {
		t.Fatalf("got %d journal entries, want 1", len(entries))
	}
	entry := entries[0]
	if entry.Succeeded {
		t.Error("failed rollout journalled as succeeded")
	}
	if entry.Branch != "" {
		t.Errorf("branch %q recorded for a rollout that never published", entry.Branch)
	}

	want := map[string]string{
		stagePreflight: statusDone,
		stageRepo:      statusSkipped,
		stageVault:     statusRolledBack,
		stageCluster:   statusFailed,
		stageGit:       statusPending,
	}
	for _, stage := range entry.Stages {
		if got := want[stage.Stage]; got != stage.Status {
			t.Errorf("%s = %q, want %q", stage.Stage, stage.Status, got)
		}
	}
}

func TestHandleCreateRaven_JournalsSuccess(t *testing.T) {
	t.Parallel()

	deps, _, _, _ := newTestDeps()
	deps.journal = testJournal(t, 10)
	deps.logger = testLogger(io.Discard)

	if rec := post(t, deps, validBody()); rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", rec.Code, rec.Body)
	}

	entries := deps.journal.recent()
	if len(entries) != 1 {
		t.Fatalf("got %d journal entries, want 1", len(entries))
	}
	if !entries[0].Succeeded {
		t.Error("successful rollout journalled as failed")
	}
	if entries[0].Branch != "raven/create-ssg-dev" {
		t.Errorf("branch = %q", entries[0].Branch)
	}
}

// The journal is served to flock, so a Vault token must not reach it even
// when a downstream error quotes one back at us.
func TestProvisionRaven_RedactsTokenFromStageDetail(t *testing.T) {
	t.Parallel()

	deps, _, applier, _ := newTestDeps()
	applier.applyErr = errors.New("secret rejected: token " + testToken + " is malformed")

	_, report, err := provisionRaven(context.Background(), deps, wranglerSpec(), false)
	if err == nil {
		t.Fatal("expected the cluster stage to fail")
	}

	encoded, marshalErr := json.Marshal(report.results())
	if marshalErr != nil {
		t.Fatalf("marshal: %v", marshalErr)
	}
	if strings.Contains(string(encoded), testToken) {
		t.Errorf("stage detail leaked the vault token: %s", encoded)
	}
	if !strings.Contains(string(encoded), redacted) {
		t.Errorf("token was dropped rather than redacted: %s", encoded)
	}
}
