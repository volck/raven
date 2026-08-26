package flock_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/volck/raven/internal/flock"
	rvclient "github.com/volck/raven/internal/flock/raven"
)

type fakeStatusFetcher struct {
	resp map[string]rvclient.Status
	err  map[string]error
}

func (f *fakeStatusFetcher) Status(_ context.Context, baseURL string) (rvclient.Status, error) {
	if e, ok := f.err[baseURL]; ok && e != nil {
		return rvclient.Status{}, e
	}
	return f.resp[baseURL], nil
}

func TestStatusAggregator_RunOnceCachesPerTarget(t *testing.T) {
	t.Parallel()
	snap := flock.Snapshot{
		Engines: []string{"dev"},
		Routing: map[string][]string{"dev": {"http://a", "http://b"}},
	}
	fetch := &fakeStatusFetcher{
		resp: map[string]rvclient.Status{
			"http://a": {Engine: "dev", SecretCount: 1, Secrets: []rvclient.SecretFile{{Name: "x.yaml", SecretName: "x"}}},
			"http://b": {Engine: "dev", SecretCount: 2, Secrets: []rvclient.SecretFile{{Name: "y.yaml", SecretName: "y"}, {Name: "z.yaml", SecretName: "z"}}},
		},
	}
	agg := flock.NewStatusAggregator(fetch,
		flock.WithStatusAggregatorClock(func() time.Time { return time.Unix(1700000000, 0).UTC() }),
	)
	agg.RunOnce(context.Background(), snap)

	all := agg.All()
	if len(all) != 2 {
		t.Fatalf("All() = %+v", all)
	}
	if all[0].Target != "http://a" || all[1].Target != "http://b" {
		t.Fatalf("targets = %s %s", all[0].Target, all[1].Target)
	}
	gotA, ok := agg.StatusForTarget("http://a")
	if !ok || gotA.Status.SecretCount != 1 {
		t.Fatalf("StatusForTarget a = %+v ok=%v", gotA, ok)
	}

	inv := agg.Inventory()
	if len(inv) != 3 {
		t.Fatalf("inventory len = %d", len(inv))
	}

	dev := agg.InventoryForEngine("dev", snap)
	if len(dev) != 3 {
		t.Fatalf("dev inv len = %d", len(dev))
	}

	xs := agg.SecretDetail("dev", "x", snap)
	if len(xs) != 1 || xs[0].Target != "http://a" {
		t.Fatalf("SecretDetail x = %+v", xs)
	}

	ts := agg.ForEngine("dev", snap)
	if len(ts) != 2 {
		t.Fatalf("ForEngine = %+v", ts)
	}
}

func TestStatusAggregator_PreservesPrevOnError(t *testing.T) {
	t.Parallel()
	snap := flock.Snapshot{
		Routing: map[string][]string{"dev": {"http://a"}},
	}
	fetch := &fakeStatusFetcher{
		resp: map[string]rvclient.Status{"http://a": {Engine: "dev", SecretCount: 5}},
	}
	agg := flock.NewStatusAggregator(fetch)
	agg.RunOnce(context.Background(), snap)

	fetch.err = map[string]error{"http://a": errors.New("boom")}
	agg.RunOnce(context.Background(), snap)

	got, ok := agg.StatusForTarget("http://a")
	if !ok || got.Status.SecretCount != 5 {
		t.Fatalf("expected prev value retained, got %+v ok=%v", got, ok)
	}
}

func TestStatusAggregator_DropsRemovedTargets(t *testing.T) {
	t.Parallel()
	snap := flock.Snapshot{
		Routing: map[string][]string{"dev": {"http://a", "http://b"}},
	}
	fetch := &fakeStatusFetcher{
		resp: map[string]rvclient.Status{
			"http://a": {Engine: "dev"},
			"http://b": {Engine: "dev"},
		},
	}
	agg := flock.NewStatusAggregator(fetch)
	agg.RunOnce(context.Background(), snap)
	if len(agg.All()) != 2 {
		t.Fatalf("expected 2 cached")
	}
	snap2 := flock.Snapshot{
		Routing: map[string][]string{"dev": {"http://a"}},
	}
	agg.RunOnce(context.Background(), snap2)
	if got := agg.All(); len(got) != 1 || got[0].Target != "http://a" {
		t.Fatalf("expected only a retained, got %+v", got)
	}
}
