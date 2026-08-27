package flock

import (
	"context"
	"sort"
	"sync"
	"time"

	rvclient "github.com/volck/raven/internal/flock/raven"
)

// PipelineFetcher is the minimal interface flock needs to pull pipeline
// data from a raven instance.
type PipelineFetcher interface {
	Pipeline(ctx context.Context, baseURL string) ([]rvclient.PipelineEntry, error)
}

// TargetPipeline is a pipeline payload tagged with its source target.
type TargetPipeline struct {
	Target     string                   `json:"target"`
	ObservedAt time.Time                `json:"observed_at"`
	Entries    []rvclient.PipelineEntry `json:"entries"`
}

// PipelineAggregator polls every raven target on an interval, fetches its
// /api/v1/pipeline payload, and caches the result in memory.
type PipelineAggregator struct {
	fetch       PipelineFetcher
	interval    time.Duration
	concurrency int
	timeout     time.Duration
	clock       func() time.Time
	newTick     TickerFunc

	mu        sync.RWMutex
	pipelines map[string]TargetPipeline

	triggerCh chan struct{}
}

// PipelineAggregatorOption configures a PipelineAggregator.
type PipelineAggregatorOption func(*PipelineAggregator)

// WithPipelineAggregatorInterval sets the polling interval. Defaults to 30s
// because /api/v1/pipeline is the heaviest raven endpoint.
func WithPipelineAggregatorInterval(d time.Duration) PipelineAggregatorOption {
	return func(a *PipelineAggregator) { a.interval = d }
}

// WithPipelineAggregatorConcurrency caps parallel fetches. Defaults to 4.
func WithPipelineAggregatorConcurrency(n int) PipelineAggregatorOption {
	return func(a *PipelineAggregator) {
		if n > 0 {
			a.concurrency = n
		}
	}
}

// WithPipelineAggregatorTimeout bounds a single fetch. Defaults to 30s.
func WithPipelineAggregatorTimeout(d time.Duration) PipelineAggregatorOption {
	return func(a *PipelineAggregator) { a.timeout = d }
}

// WithPipelineAggregatorClock overrides the clock (tests).
func WithPipelineAggregatorClock(c func() time.Time) PipelineAggregatorOption {
	return func(a *PipelineAggregator) { a.clock = c }
}

// WithPipelineAggregatorTicker overrides the ticker (tests).
func WithPipelineAggregatorTicker(fn TickerFunc) PipelineAggregatorOption {
	return func(a *PipelineAggregator) { a.newTick = fn }
}

// NewPipelineAggregator constructs a PipelineAggregator.
func NewPipelineAggregator(fetch PipelineFetcher, opts ...PipelineAggregatorOption) *PipelineAggregator {
	a := &PipelineAggregator{
		fetch:       fetch,
		interval:    30 * time.Second,
		concurrency: 4,
		timeout:     30 * time.Second,
		clock:       time.Now,
		newTick: func(d time.Duration) (<-chan time.Time, func()) {
			t := time.NewTicker(d)
			return t.C, t.Stop
		},
		pipelines: map[string]TargetPipeline{},
		triggerCh: make(chan struct{}, 1),
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// PipelineForTarget returns the cached pipeline for one target.
func (a *PipelineAggregator) PipelineForTarget(target string) (TargetPipeline, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	p, ok := a.pipelines[target]
	return p, ok
}

// PipelineForEngine returns the pipelines for every target serving the
// named engine.
func (a *PipelineAggregator) PipelineForEngine(name string, snap Snapshot) []TargetPipeline {
	targets, ok := snap.Routing[name]
	if !ok {
		return nil
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]TargetPipeline, 0, len(targets))
	for _, t := range targets {
		if p, ok := a.pipelines[t]; ok {
			out = append(out, p)
		}
	}
	return out
}

// PipelineForSecret returns the pipeline entries for one secret across
// every target serving the engine, tagged with target.
func (a *PipelineAggregator) PipelineForSecret(engine, secret string, snap Snapshot) []PipelineSecretRow {
	targets, ok := snap.Routing[engine]
	if !ok {
		return nil
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]PipelineSecretRow, 0)
	for _, t := range targets {
		p, ok := a.pipelines[t]
		if !ok {
			continue
		}
		for _, e := range p.Entries {
			if e.Secret == secret {
				out = append(out, PipelineSecretRow{
					Target:     t,
					ObservedAt: p.ObservedAt,
					Entry:      e,
				})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Target < out[j].Target })
	return out
}

// PipelineSecretRow is one (target, secret) pipeline observation.
type PipelineSecretRow struct {
	Target     string                 `json:"target"`
	ObservedAt time.Time              `json:"observed_at"`
	Entry      rvclient.PipelineEntry `json:"entry"`
}

// RunOnce fetches pipeline data from every target in snap. Per-target
// failures keep the previous cached value.
func (a *PipelineAggregator) RunOnce(ctx context.Context, snap Snapshot) {
	targets := uniqueTargets(snap)
	if len(targets) == 0 {
		return
	}
	type result struct {
		target  string
		entries []rvclient.PipelineEntry
		err     error
	}
	sem := make(chan struct{}, a.concurrency)
	var wg sync.WaitGroup
	results := make([]result, len(targets))

	for i, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, target string) {
			defer wg.Done()
			defer func() { <-sem }()
			fctx := ctx
			if a.timeout > 0 {
				var cancel context.CancelFunc
				fctx, cancel = context.WithTimeout(ctx, a.timeout)
				defer cancel()
			}
			es, err := a.fetch.Pipeline(fctx, target)
			results[i] = result{target: target, entries: es, err: err}
		}(i, t)
	}
	wg.Wait()

	now := a.clock()
	a.mu.Lock()
	for _, r := range results {
		if r.err != nil {
			continue
		}
		a.pipelines[r.target] = TargetPipeline{
			Target:     r.target,
			ObservedAt: now,
			Entries:    r.entries,
		}
	}
	keep := map[string]struct{}{}
	for _, t := range targets {
		keep[t] = struct{}{}
	}
	for t := range a.pipelines {
		if _, ok := keep[t]; !ok {
			delete(a.pipelines, t)
		}
	}
	a.mu.Unlock()
}

// Run drives RunOnce on every ticker tick and Trigger signal.
func (a *PipelineAggregator) Run(ctx context.Context, snapFn func() Snapshot) error {
	tickC, stop := a.newTick(a.interval)
	defer stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tickC:
			a.RunOnce(ctx, snapFn())
		case <-a.triggerCh:
			a.RunOnce(ctx, snapFn())
		}
	}
}

// Trigger schedules an out-of-band fetch.
func (a *PipelineAggregator) Trigger() {
	select {
	case a.triggerCh <- struct{}{}:
	default:
	}
}
