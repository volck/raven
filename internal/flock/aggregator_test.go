package flock_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/volck/raven/internal/flock"
	rvclient "github.com/volck/raven/internal/flock/raven"
)

type fakeFetcher struct {
	mu   sync.Mutex
	byT  map[string][]rvclient.Event
	errs map[string]error
	hits map[string]int
}

func (f *fakeFetcher) Events(_ context.Context, baseURL string) ([]rvclient.Event, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hits[baseURL]++
	if err, ok := f.errs[baseURL]; ok {
		return nil, err
	}
	return f.byT[baseURL], nil
}

func TestAggregator_RunOnce_FetchesEveryTargetAndCaches(t *testing.T) {
	t.Parallel()
	now := time.Now()
	f := &fakeFetcher{
		byT: map[string][]rvclient.Event{
			"https://r1": {{Time: now, Path: "kv/a", Engine: "dev"}},
			"https://r2": {{Time: now.Add(-time.Minute), Path: "kv/b", Engine: "dev"}},
		},
		errs: map[string]error{},
		hits: map[string]int{},
	}
	agg := flock.NewAggregator(f, flock.WithAggregatorConcurrency(2))
	agg.RunOnce(context.Background(), flock.Snapshot{
		Engines: []string{"dev"},
		Routing: map[string][]string{"dev": {"https://r1", "https://r2"}},
	})

	if got := agg.EventsForTarget("https://r1"); len(got) != 1 || got[0].Path != "kv/a" {
		t.Fatalf("r1 cached = %+v", got)
	}
	if f.hits["https://r1"] != 1 || f.hits["https://r2"] != 1 {
		t.Fatalf("hits = %v want both 1", f.hits)
	}
}

func TestAggregator_All_SortedNewestFirst(t *testing.T) {
	t.Parallel()
	now := time.Now()
	f := &fakeFetcher{
		byT: map[string][]rvclient.Event{
			"https://r1": {{Time: now.Add(-time.Hour), Path: "old"}},
			"https://r2": {{Time: now, Path: "new"}},
		},
		errs: map[string]error{}, hits: map[string]int{},
	}
	agg := flock.NewAggregator(f)
	agg.RunOnce(context.Background(), flock.Snapshot{
		Routing: map[string][]string{"dev": {"https://r1", "https://r2"}},
	})
	all := agg.All()
	if len(all) != 2 || all[0].Event.Path != "new" || all[1].Event.Path != "old" {
		t.Fatalf("got = %+v", all)
	}
}

func TestAggregator_ForEngine_FiltersByRouting(t *testing.T) {
	t.Parallel()
	now := time.Now()
	f := &fakeFetcher{
		byT: map[string][]rvclient.Event{
			"https://r-dev":  {{Time: now, Path: "dev/x"}},
			"https://r-prod": {{Time: now, Path: "prod/y"}},
		},
		errs: map[string]error{}, hits: map[string]int{},
	}
	agg := flock.NewAggregator(f)
	snap := flock.Snapshot{
		Engines: []string{"dev", "prod"},
		Routing: map[string][]string{
			"dev":  {"https://r-dev"},
			"prod": {"https://r-prod"},
		},
	}
	agg.RunOnce(context.Background(), snap)

	devEvs := agg.ForEngine("dev", snap)
	if len(devEvs) != 1 || devEvs[0].Event.Path != "dev/x" {
		t.Fatalf("dev = %+v", devEvs)
	}
	if got := agg.ForEngine("unknown", snap); got != nil {
		t.Fatalf("unknown engine should be nil, got %+v", got)
	}
}

func TestAggregator_RunOnce_KeepsPreviousOnFetchError(t *testing.T) {
	t.Parallel()
	now := time.Now()
	f := &fakeFetcher{
		byT:  map[string][]rvclient.Event{"https://r1": {{Time: now, Path: "ok"}}},
		errs: map[string]error{}, hits: map[string]int{},
	}
	snap := flock.Snapshot{Routing: map[string][]string{"dev": {"https://r1"}}}
	agg := flock.NewAggregator(f)
	agg.RunOnce(context.Background(), snap)

	// Now make r1 fail; cached value should remain.
	f.errs["https://r1"] = errors.New("boom")
	agg.RunOnce(context.Background(), snap)

	got := agg.EventsForTarget("https://r1")
	if len(got) != 1 || got[0].Path != "ok" {
		t.Fatalf("expected cached value preserved, got %+v", got)
	}
}

func TestAggregator_RunOnce_DropsRemovedTargets(t *testing.T) {
	t.Parallel()
	now := time.Now()
	f := &fakeFetcher{
		byT: map[string][]rvclient.Event{
			"https://r1": {{Time: now, Path: "a"}},
			"https://r2": {{Time: now, Path: "b"}},
		},
		errs: map[string]error{}, hits: map[string]int{},
	}
	agg := flock.NewAggregator(f)
	agg.RunOnce(context.Background(), flock.Snapshot{
		Routing: map[string][]string{"dev": {"https://r1", "https://r2"}},
	})
	if len(agg.All()) != 2 {
		t.Fatalf("setup: want 2 events")
	}
	// r2 removed from snapshot.
	agg.RunOnce(context.Background(), flock.Snapshot{
		Routing: map[string][]string{"dev": {"https://r1"}},
	})
	if got := agg.EventsForTarget("https://r2"); got != nil {
		t.Fatalf("r2 should be dropped, got %+v", got)
	}
}

func TestAggregator_PerTargetCap(t *testing.T) {
	t.Parallel()
	now := time.Now()
	events := make([]rvclient.Event, 10)
	for i := range events {
		events[i] = rvclient.Event{Time: now.Add(-time.Duration(i) * time.Second), Path: "p"}
	}
	f := &fakeFetcher{
		byT:  map[string][]rvclient.Event{"https://r1": events},
		errs: map[string]error{}, hits: map[string]int{},
	}
	agg := flock.NewAggregator(f, flock.WithAggregatorPerTargetCap(3))
	agg.RunOnce(context.Background(), flock.Snapshot{
		Routing: map[string][]string{"dev": {"https://r1"}},
	})
	if got := agg.EventsForTarget("https://r1"); len(got) != 3 {
		t.Fatalf("cap=3, got %d", len(got))
	}
}
