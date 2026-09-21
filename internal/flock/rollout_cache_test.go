package flock

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	wrclient "github.com/volck/raven/internal/flock/wrangler"
)

type fakeRolloutSource struct {
	mu      sync.Mutex
	calls   atomic.Int32
	batches [][]wrclient.Rollout
	errs    []error
}

func (f *fakeRolloutSource) Rollouts(context.Context) ([]wrclient.Rollout, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	i := int(f.calls.Add(1)) - 1
	if i < len(f.errs) && f.errs[i] != nil {
		return nil, f.errs[i]
	}
	if i < len(f.batches) {
		return f.batches[i], nil
	}
	return nil, nil
}

func rolloutFor(engine, raven string, ok bool) wrclient.Rollout {
	return wrclient.Rollout{
		Time:      time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC),
		Raven:     raven,
		Engine:    engine,
		Namespace: "ssg",
		Succeeded: ok,
	}
}

func TestRolloutCache_RunOnceStores(t *testing.T) {
	t.Parallel()

	src := &fakeRolloutSource{batches: [][]wrclient.Rollout{{
		rolloutFor("kv", "ssg-dev", true),
		rolloutFor("prod01", "ssg-prod01", false),
	}}}
	cache := NewRolloutCache(src)

	cache.RunOnce(context.Background())

	if got := cache.Rollouts(); len(got) != 2 {
		t.Fatalf("got %d rollouts, want 2", len(got))
	}
}

// A wrangler that is down must not blank the last known state.
func TestRolloutCache_KeepsLastGoodOnError(t *testing.T) {
	t.Parallel()

	src := &fakeRolloutSource{
		batches: [][]wrclient.Rollout{{rolloutFor("kv", "ssg-dev", true)}},
		errs:    []error{nil, errors.New("wrangler unreachable")},
	}
	cache := NewRolloutCache(src)

	cache.RunOnce(context.Background())
	cache.RunOnce(context.Background())

	got := cache.Rollouts()
	if len(got) != 1 || got[0].Raven != "ssg-dev" {
		t.Errorf("cache lost its last good value: %+v", got)
	}
}

func TestRolloutCache_ForEngine(t *testing.T) {
	t.Parallel()

	src := &fakeRolloutSource{batches: [][]wrclient.Rollout{{
		rolloutFor("kv", "ssg-dev", true),
		rolloutFor("prod01", "ssg-prod01", false),
		rolloutFor("kv", "ssg-int", true),
	}}}
	cache := NewRolloutCache(src)
	cache.RunOnce(context.Background())

	got := cache.RolloutsForEngine("kv")
	if len(got) != 2 {
		t.Fatalf("got %d rollouts for kv, want 2", len(got))
	}
	for _, r := range got {
		if r.Engine != "kv" {
			t.Errorf("engine = %q leaked into the kv view", r.Engine)
		}
	}

	if got := cache.RolloutsForEngine("nope"); len(got) != 0 {
		t.Errorf("unknown engine returned %d rollouts", len(got))
	}
}

// Callers must not be able to reach into the cache's storage.
func TestRolloutCache_RollutsIsACopy(t *testing.T) {
	t.Parallel()

	src := &fakeRolloutSource{batches: [][]wrclient.Rollout{{rolloutFor("kv", "ssg-dev", true)}}}
	cache := NewRolloutCache(src)
	cache.RunOnce(context.Background())

	got := cache.Rollouts()
	got[0].Raven = "tampered"

	if cache.Rollouts()[0].Raven != "ssg-dev" {
		t.Error("mutating the result changed the cache")
	}
}

func TestRolloutCache_RunPollsOnTick(t *testing.T) {
	t.Parallel()

	src := &fakeRolloutSource{batches: [][]wrclient.Rollout{
		{rolloutFor("kv", "first", true)},
		{rolloutFor("kv", "second", true)},
	}}

	tick := make(chan time.Time)
	cache := NewRolloutCache(src, WithRolloutTicker(func(time.Duration) (<-chan time.Time, func()) {
		return tick, func() {}
	}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- cache.Run(ctx) }()

	tick <- time.Now()
	waitFor(t, func() bool { return src.calls.Load() >= 1 })

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not return after the context was cancelled")
	}
}

func TestRolloutCache_TriggerPolls(t *testing.T) {
	t.Parallel()

	src := &fakeRolloutSource{batches: [][]wrclient.Rollout{{rolloutFor("kv", "ssg-dev", true)}}}
	cache := NewRolloutCache(src, WithRolloutTicker(func(time.Duration) (<-chan time.Time, func()) {
		return make(chan time.Time), func() {}
	}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = cache.Run(ctx) }()

	cache.Trigger()
	waitFor(t, func() bool { return src.calls.Load() >= 1 })
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met in time")
}
