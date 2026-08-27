package flock

import (
	"context"
	"sort"
	"sync"
	"time"

	rvclient "github.com/volck/raven/internal/flock/raven"
)

// StatusFetcher is the minimal interface flock needs to pull status from a
// raven instance.
type StatusFetcher interface {
	Status(ctx context.Context, baseURL string) (rvclient.Status, error)
}

// TargetStatus is a raven status tagged with the target it came from and
// the time flock observed it. The latter is distinct from Status.GeneratedAt
// which is the raven's own clock.
type TargetStatus struct {
	Target     string          `json:"target"`
	ObservedAt time.Time       `json:"observed_at"`
	Status     rvclient.Status `json:"status"`
}

// InventoryEntry flattens a single secret across the fleet — one row per
// (target, secret) pairing, with the secret's K8s state if available.
type InventoryEntry struct {
	Engine     string                   `json:"engine"`
	Target     string                   `json:"target"`
	Name       string                   `json:"name"`
	SecretName string                   `json:"secret_name"`
	Modified   time.Time                `json:"modified"`
	K8s        *rvclient.SecretK8sState `json:"k8s,omitempty"`
}

// StatusAggregator polls every raven target on an interval, fetches its
// bundled /api/v1/status payload, and caches the result in memory.
type StatusAggregator struct {
	fetch       StatusFetcher
	interval    time.Duration
	concurrency int
	timeout     time.Duration
	clock       func() time.Time
	newTick     TickerFunc

	mu       sync.RWMutex
	statuses map[string]TargetStatus

	triggerCh chan struct{}
}

// StatusAggregatorOption configures a StatusAggregator.
type StatusAggregatorOption func(*StatusAggregator)

// WithStatusAggregatorInterval sets the polling interval. Defaults to 30s.
func WithStatusAggregatorInterval(d time.Duration) StatusAggregatorOption {
	return func(a *StatusAggregator) { a.interval = d }
}

// WithStatusAggregatorConcurrency caps parallel fetches. Defaults to 8.
func WithStatusAggregatorConcurrency(n int) StatusAggregatorOption {
	return func(a *StatusAggregator) {
		if n > 0 {
			a.concurrency = n
		}
	}
}

// WithStatusAggregatorTimeout bounds a single fetch. Defaults to 10s.
func WithStatusAggregatorTimeout(d time.Duration) StatusAggregatorOption {
	return func(a *StatusAggregator) { a.timeout = d }
}

// WithStatusAggregatorClock overrides the clock (tests).
func WithStatusAggregatorClock(c func() time.Time) StatusAggregatorOption {
	return func(a *StatusAggregator) { a.clock = c }
}

// WithStatusAggregatorTicker overrides the ticker (tests).
func WithStatusAggregatorTicker(fn TickerFunc) StatusAggregatorOption {
	return func(a *StatusAggregator) { a.newTick = fn }
}

// NewStatusAggregator constructs a StatusAggregator.
func NewStatusAggregator(fetch StatusFetcher, opts ...StatusAggregatorOption) *StatusAggregator {
	a := &StatusAggregator{
		fetch:       fetch,
		interval:    30 * time.Second,
		concurrency: 8,
		timeout:     10 * time.Second,
		clock:       time.Now,
		newTick: func(d time.Duration) (<-chan time.Time, func()) {
			t := time.NewTicker(d)
			return t.C, t.Stop
		},
		statuses:  map[string]TargetStatus{},
		triggerCh: make(chan struct{}, 1),
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// StatusForTarget returns the cached status for one target, or false if
// it has never been fetched.
func (a *StatusAggregator) StatusForTarget(target string) (TargetStatus, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	s, ok := a.statuses[target]
	return s, ok
}

// All returns every cached status, sorted by target.
func (a *StatusAggregator) All() []TargetStatus {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]TargetStatus, 0, len(a.statuses))
	for _, s := range a.statuses {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Target < out[j].Target
	})
	return out
}

// ForEngine returns the statuses of every raven target serving the named
// engine.
func (a *StatusAggregator) ForEngine(name string, snap Snapshot) []TargetStatus {
	targets, ok := snap.Routing[name]
	if !ok {
		return nil
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]TargetStatus, 0, len(targets))
	for _, t := range targets {
		if s, ok := a.statuses[t]; ok {
			out = append(out, s)
		}
	}
	return out
}

// Inventory returns one InventoryEntry per (target, secret) pair across the
// fleet, sorted by engine then secret_name.
func (a *StatusAggregator) Inventory() []InventoryEntry {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]InventoryEntry, 0)
	for target, ts := range a.statuses {
		for _, sec := range ts.Status.Secrets {
			out = append(out, InventoryEntry{
				Engine:     ts.Status.Engine,
				Target:     target,
				Name:       sec.Name,
				SecretName: sec.SecretName,
				Modified:   sec.Modified,
				K8s:        sec.K8s,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Engine != out[j].Engine {
			return out[i].Engine < out[j].Engine
		}
		if out[i].SecretName != out[j].SecretName {
			return out[i].SecretName < out[j].SecretName
		}
		return out[i].Target < out[j].Target
	})
	return out
}

// InventoryForEngine returns inventory rows only for the given engine.
func (a *StatusAggregator) InventoryForEngine(name string, snap Snapshot) []InventoryEntry {
	targets, ok := snap.Routing[name]
	if !ok {
		return nil
	}
	set := map[string]struct{}{}
	for _, t := range targets {
		set[t] = struct{}{}
	}
	all := a.Inventory()
	out := make([]InventoryEntry, 0)
	for _, row := range all {
		if _, ok := set[row.Target]; ok {
			out = append(out, row)
		}
	}
	return out
}

// SecretDetail returns inventory entries for a specific secret_name within
// an engine (one row per target that serves that engine), plus nil if the
// engine is unknown.
func (a *StatusAggregator) SecretDetail(engine, secretName string, snap Snapshot) []InventoryEntry {
	rows := a.InventoryForEngine(engine, snap)
	if rows == nil {
		return nil
	}
	out := make([]InventoryEntry, 0)
	for _, r := range rows {
		if r.SecretName == secretName {
			out = append(out, r)
		}
	}
	return out
}

// RunOnce fetches status from every target in snap concurrently. Per-target
// failures keep the previous cached value.
func (a *StatusAggregator) RunOnce(ctx context.Context, snap Snapshot) {
	targets := uniqueTargets(snap)
	if len(targets) == 0 {
		return
	}
	type result struct {
		target string
		status rvclient.Status
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
			s, err := a.fetch.Status(fctx, target)
			results[i] = result{target: target, status: s, err: err}
		}(i, t)
	}
	wg.Wait()

	now := a.clock()
	a.mu.Lock()
	for _, r := range results {
		if r.err != nil {
			continue
		}
		a.statuses[r.target] = TargetStatus{
			Target:     r.target,
			ObservedAt: now,
			Status:     r.status,
		}
	}
	keep := map[string]struct{}{}
	for _, t := range targets {
		keep[t] = struct{}{}
	}
	for t := range a.statuses {
		if _, ok := keep[t]; !ok {
			delete(a.statuses, t)
		}
	}
	a.mu.Unlock()
}

// Run drives RunOnce on every ticker tick and Trigger signal until ctx is
// cancelled.
func (a *StatusAggregator) Run(ctx context.Context, snapFn func() Snapshot) error {
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

// Trigger schedules an out-of-band fetch. Bursts coalesce.
func (a *StatusAggregator) Trigger() {
	select {
	case a.triggerCh <- struct{}{}:
	default:
	}
}
