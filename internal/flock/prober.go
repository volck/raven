package flock

import (
	"context"
	"sort"
	"sync"
	"time"
)

// Probe is the minimal interface flock needs from a raven probe client.
// internal/flock/raven.Client satisfies this.
type Probe interface {
	Probe(ctx context.Context, baseURL string) (bool, error)
}

// Health is the cached per-target probe result.
type Health struct {
	Healthy   bool
	Error     string
	CheckedAt time.Time
}

// Prober probes all targets in a Snapshot in parallel and caches results.
type Prober struct {
	probe       Probe
	interval    time.Duration
	concurrency int
	timeout     time.Duration
	clock       func() time.Time
	newTick     TickerFunc

	mu     sync.RWMutex
	health map[string]Health

	triggerCh chan struct{}
}

// ProberOption configures a Prober.
type ProberOption func(*Prober)

// WithProberInterval sets the polling interval. Defaults to 30s.
func WithProberInterval(d time.Duration) ProberOption {
	return func(p *Prober) { p.interval = d }
}

// WithProberConcurrency caps parallel probes. Defaults to 8.
func WithProberConcurrency(n int) ProberOption {
	return func(p *Prober) {
		if n > 0 {
			p.concurrency = n
		}
	}
}

// WithProberTimeout bounds a single probe call. Defaults to 5s.
func WithProberTimeout(d time.Duration) ProberOption {
	return func(p *Prober) { p.timeout = d }
}

// WithProberClock overrides the clock.
func WithProberClock(c func() time.Time) ProberOption {
	return func(p *Prober) { p.clock = c }
}

// WithProberTicker overrides the ticker for tests.
func WithProberTicker(fn TickerFunc) ProberOption {
	return func(p *Prober) { p.newTick = fn }
}

// NewProber constructs a Prober.
func NewProber(probe Probe, opts ...ProberOption) *Prober {
	p := &Prober{
		probe:       probe,
		interval:    30 * time.Second,
		concurrency: 8,
		timeout:     5 * time.Second,
		clock:       time.Now,
		newTick: func(d time.Duration) (<-chan time.Time, func()) {
			t := time.NewTicker(d)
			return t.C, t.Stop
		},
		health:    map[string]Health{},
		triggerCh: make(chan struct{}, 1),
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Health returns a copy of the cached per-target results.
func (p *Prober) Health() map[string]Health {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make(map[string]Health, len(p.health))
	for k, v := range p.health {
		out[k] = v
	}
	return out
}

// HealthFor returns the cached result for a single target, with the zero
// value if it hasn't been probed yet.
func (p *Prober) HealthFor(target string) (Health, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	h, ok := p.health[target]
	return h, ok
}

// uniqueTargets returns the deduplicated, sorted target list in snap.
func uniqueTargets(snap Snapshot) []string {
	set := map[string]struct{}{}
	for _, targets := range snap.Routing {
		for _, t := range targets {
			set[t] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// RunOnce probes every target in snap concurrently (bounded by the
// configured concurrency) and caches results.
func (p *Prober) RunOnce(ctx context.Context, snap Snapshot) {
	targets := uniqueTargets(snap)
	if len(targets) == 0 {
		return
	}
	sem := make(chan struct{}, p.concurrency)
	var wg sync.WaitGroup
	results := make([]Health, len(targets))

	for i, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, target string) {
			defer wg.Done()
			defer func() { <-sem }()

			pctx := ctx
			if p.timeout > 0 {
				var cancel context.CancelFunc
				pctx, cancel = context.WithTimeout(ctx, p.timeout)
				defer cancel()
			}
			ok, err := p.probe.Probe(pctx, target)
			h := Health{Healthy: ok, CheckedAt: p.clock()}
			if err != nil {
				h.Error = err.Error()
			}
			results[i] = h
		}(i, t)
	}
	wg.Wait()

	p.mu.Lock()
	for i, t := range targets {
		p.health[t] = results[i]
	}
	p.mu.Unlock()
}

// Run drives RunOnce on every ticker tick and Trigger signal until ctx is
// cancelled. snapFn is called on every iteration to fetch the current
// Snapshot to probe.
func (p *Prober) Run(ctx context.Context, snapFn func() Snapshot) error {
	tickC, stop := p.newTick(p.interval)
	defer stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tickC:
			p.RunOnce(ctx, snapFn())
		case <-p.triggerCh:
			p.RunOnce(ctx, snapFn())
		}
	}
}

// Trigger schedules an out-of-band probe pass. Bursts coalesce.
func (p *Prober) Trigger() {
	select {
	case p.triggerCh <- struct{}{}:
	default:
	}
}
