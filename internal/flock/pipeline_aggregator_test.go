package flock_test

import (
	"context"
	"errors"
	"testing"

	"github.com/volck/raven/internal/flock"
	rvclient "github.com/volck/raven/internal/flock/raven"
)

type fakePipelineFetcher struct {
	resp map[string][]rvclient.PipelineEntry
	err  map[string]error
}

func (f *fakePipelineFetcher) Pipeline(_ context.Context, baseURL string) ([]rvclient.PipelineEntry, error) {
	if e, ok := f.err[baseURL]; ok && e != nil {
		return nil, e
	}
	return f.resp[baseURL], nil
}

func TestPipelineAggregator_PerTargetAndSecretLookup(t *testing.T) {
	t.Parallel()
	snap := flock.Snapshot{Routing: map[string][]string{"dev": {"http://a", "http://b"}}}
	fetch := &fakePipelineFetcher{
		resp: map[string][]rvclient.PipelineEntry{
			"http://a": {{Secret: "foo", Engine: "dev"}, {Secret: "bar", Engine: "dev"}},
			"http://b": {{Secret: "foo", Engine: "dev"}},
		},
	}
	agg := flock.NewPipelineAggregator(fetch)
	agg.RunOnce(context.Background(), snap)

	got := agg.PipelineForEngine("dev", snap)
	if len(got) != 2 {
		t.Fatalf("ForEngine = %d", len(got))
	}
	foo := agg.PipelineForSecret("dev", "foo", snap)
	if len(foo) != 2 {
		t.Fatalf("PipelineForSecret(foo) = %d, want 2", len(foo))
	}
	bar := agg.PipelineForSecret("dev", "bar", snap)
	if len(bar) != 1 || bar[0].Target != "http://a" {
		t.Fatalf("PipelineForSecret(bar) = %+v", bar)
	}
}

func TestPipelineAggregator_PreservesPrevOnError(t *testing.T) {
	t.Parallel()
	snap := flock.Snapshot{Routing: map[string][]string{"dev": {"http://a"}}}
	fetch := &fakePipelineFetcher{
		resp: map[string][]rvclient.PipelineEntry{
			"http://a": {{Secret: "foo"}},
		},
	}
	agg := flock.NewPipelineAggregator(fetch)
	agg.RunOnce(context.Background(), snap)

	fetch.err = map[string]error{"http://a": errors.New("boom")}
	agg.RunOnce(context.Background(), snap)
	p, ok := agg.PipelineForTarget("http://a")
	if !ok || len(p.Entries) != 1 || p.Entries[0].Secret != "foo" {
		t.Fatalf("prev not retained: %+v ok=%v", p, ok)
	}
}
