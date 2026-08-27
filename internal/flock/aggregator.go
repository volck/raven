package flock

import (
	"context"
	"sort"
	"sync"
	"time"

	rvclient "github.com/volck/raven/internal/flock/raven"
)

// EventFetcher is the minimal interface flock needs to pull events from a
// raven instance. internal/flock/raven.Client satisfies this.
type EventFetcher interface {
	Events(ctx context.Context, baseURL string) ([]rvclient.Event, error)
}

// TargetEvent is an Event tagged with the raven target it came from.
type TargetEvent struct {
	Target string         `json:"target"`
	Event  rvclient.Event `json:"event"`
}

// Aggregator polls every known raven target on an interval, fetches its
// recent events, and caches them in memory keyed by target. Reads are
// served from the cache so callers never block on upstream ravens.
type Aggregator struct {
	fetch       EventFetcher
	interval    time.Duration
	concurrency int
	timeout     time.Duration
	perTarget   int
	clock       func() time.Time
	newTick     TickerFunc

	mu     sync.RWMutex
	events map[string][]rvclient.Event

	triggerCh chan struct{}
}

// AggregatorOption configures an Aggregator.
type AggregatorOption func(*Aggregator)

// WithAggregatorInterval sets the polling interval. Defaults to 30s.
func WithAggregatorInterval(d time.Duration) AggregatorOption {
	return func(a *Aggregator) { a.interval = d }
}

// WithAggregatorConcurrency caps parallel fetches. Defaults to 8.
func WithAggregatorConcurrency(n int) AggregatorOption {
	return func(a *Aggregator) {
		if n > 0 {
			a.concurrency = n
		}
	}
}

// WithAggregatorTimeout bounds a single fetch call. Defaults to 5s.
func WithAggregatorTimeout(d time.Duration) AggregatorOption {
	return func(a *Aggregator) { a.timeout = d }
}

// WithAggregatorPerTargetCap limits the events cached per target. Defaults
// to 200. Set <= 0 to keep whatever the upstream returns.
func WithAggregatorPerTargetCap(n int) AggregatorOption {
	return func(a *Aggregator) { a.perTarget = n }
}

// WithAggregatorClock overrides the clock (tests).
func WithAggregatorClock(c func() time.Time) AggregatorOption {
	return func(a *Aggregator) { a.clock = c }
}

// WithAggregatorTicker overrides the ticker (tests).
func WithAggregatorTicker(fn TickerFunc) AggregatorOption {
	return func(a *Aggregator) { a.newTick = fn }
}

// NewAggregator constructs an Aggregator.
func NewAggregator(fetch EventFetcher, opts ...AggregatorOption) *Aggregator {
	a := &Aggregator{
		fetch:       fetch,
		interval:    30 * time.Second,
		concurrency: 8,
		timeout:     5 * time.Second,
		perTarget:   200,
		clock:       time.Now,
		newTick: func(d time.Duration) (<-chan time.Time, func()) {
			t := time.NewTicker(d)
			return t.C, t.Stop
		},
		events:    map[string][]rvclient.Event{},
		triggerCh: make(chan struct{}, 1),
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// EventsForTarget returns a copy of the cached events for a single target,
// newest first. Returns nil if the target has never been fetched.
func (a *Aggregator) EventsForTarget(target string) []rvclient.Event {
	a.mu.RLock()
	defer a.mu.RUnlock()
	evs, ok := a.events[target]
	if !ok {
		return nil
	}
	out := make([]rvclient.Event, len(evs))
	copy(out, evs)
	return out
}

// All returns every cached event tagged by target, sorted newest first.
func (a *Aggregator) All() []TargetEvent {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]TargetEvent, 0)
	for t, evs := range a.events {
		for _, e := range evs {
			out = append(out, TargetEvent{Target: t, Event: e})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Event.Time.After(out[j].Event.Time)
	})
	return out
}

// ForEngine returns events for all raven targets serving the named engine,
// sorted newest first. Returns nil if the engine is unknown.
func (a *Aggregator) ForEngine(name string, snap Snapshot) []TargetEvent {
	targets, ok := snap.Routing[name]
	if !ok {
		return nil
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]TargetEvent, 0)
	for _, t := range targets {
		for _, e := range a.events[t] {
			out = append(out, TargetEvent{Target: t, Event: e})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Event.Time.After(out[j].Event.Time)
	})
	return out
}

// RunOnce fetches events from every target in snap concurrently (bounded by
// the configured concurrency) and replaces each target's cached slice on
// success. Per-target failures are silently kept as the previous value.
func (a *Aggregator) RunOnce(ctx context.Context, snap Snapshot) {
	targets := uniqueTargets(snap)
	if len(targets) == 0 {
		return
	}
	type result struct {
		target string
		events []rvclient.Event
		err    error
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
			evs, err := a.fetch.Events(fctx, target)
			results[i] = result{target: target, events: evs, err: err}
		}(i, t)
	}
	wg.Wait()

	a.mu.Lock()
	for _, r := range results {
		if r.err != nil {
			continue
		}
		evs := r.events
		if a.perTarget > 0 && len(evs) > a.perTarget {
			evs = evs[:a.perTarget]
		}
		a.events[r.target] = evs
	}
	// Drop any targets no longer in the snapshot.
	keep := map[string]struct{}{}
	for _, t := range targets {
		keep[t] = struct{}{}
	}
	for t := range a.events {
		if _, ok := keep[t]; !ok {
			delete(a.events, t)
		}
	}
	a.mu.Unlock()
}

// Run drives RunOnce on every ticker tick and Trigger signal until ctx is
// cancelled. snapFn returns the current Snapshot to fan out across.
func (a *Aggregator) Run(ctx context.Context, snapFn func() Snapshot) error {
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

// Trigger schedules an out-of-band fetch pass. Bursts coalesce.
func (a *Aggregator) Trigger() {
	select {
	case a.triggerCh <- struct{}{}:
	default:
	}
}
