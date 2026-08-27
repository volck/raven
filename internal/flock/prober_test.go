package flock_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/volck/raven/internal/flock"
)

type fakeProbe struct {
	mu      sync.Mutex
	results map[string]struct {
		ok  bool
		err error
	}
	calls int32
}

func (f *fakeProbe) Probe(ctx context.Context, baseURL string) (bool, error) {
	atomic.AddInt32(&f.calls, 1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if r, ok := f.results[baseURL]; ok {
		return r.ok, r.err
	}
	return true, nil
}

// D”1
func TestProber_ProbesAllTargetsAndCaches(t *testing.T) {
	t.Parallel()
	probe := &fakeProbe{results: map[string]struct {
		ok  bool
		err error
	}{
		"https://r1.example": {ok: true},
		"https://r2.example": {ok: false},
		"https://r3.example": {err: errors.New("conn refused")},
	}}
	snap := flock.Snapshot{
		Engines: []string{"dev", "prod01"},
		Routing: map[string][]string{
			"dev":    {"https://r1.example", "https://r3.example"},
			"prod01": {"https://r2.example"},
		},
	}
	pr := flock.NewProber(probe, flock.WithProberConcurrency(2))
	pr.RunOnce(context.Background(), snap)

	got := pr.Health()
	if got["https://r1.example"].Healthy != true {
		t.Errorf("r1 should be healthy")
	}
	if got["https://r2.example"].Healthy != false {
		t.Errorf("r2 should be unhealthy")
	}
	if got["https://r3.example"].Healthy != false || got["https://r3.example"].Error == "" {
		t.Errorf("r3 should be unhealthy with error: %+v", got["https://r3.example"])
	}
	if atomic.LoadInt32(&probe.calls) != 3 {
		t.Errorf("calls = %d, want 3", probe.calls)
	}
}

// D”2 — RunOnce on empty snapshot is a no-op
func TestProber_EmptySnapshot(t *testing.T) {
	t.Parallel()
	probe := &fakeProbe{}
	pr := flock.NewProber(probe)
	pr.RunOnce(context.Background(), flock.Snapshot{})
	if len(pr.Health()) != 0 {
		t.Fatalf("Health non-empty: %+v", pr.Health())
	}
	if atomic.LoadInt32(&probe.calls) != 0 {
		t.Errorf("called probe for empty snapshot")
	}
}

// D”2b — Run loops on tick and on Trigger
func TestProber_RunDrivesProbes(t *testing.T) {
	t.Parallel()
	probe := &fakeProbe{}
	tickC := make(chan time.Time, 4)
	pr := flock.NewProber(probe,
		flock.WithProberTicker(func(d time.Duration) (<-chan time.Time, func()) {
			return tickC, func() {}
		}),
	)
	snapFn := func() flock.Snapshot {
		return flock.Snapshot{Routing: map[string][]string{
			"dev": {"https://r1.example"},
		}}
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- pr.Run(ctx, snapFn) }()

	tickC <- time.Now()
	deadline := time.After(2 * time.Second)
	for atomic.LoadInt32(&probe.calls) == 0 {
		select {
		case <-deadline:
			t.Fatal("Run did not probe on tick")
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	<-done
}
