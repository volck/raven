// Package flock provides the read-only aggregator for raven instances.
//
// Provider polls a Source for the current Snapshot (engines + routing) and
// exposes it to handlers via Snapshot(). Ready() latches true on the first
// successful Refresh and never clears, so transient upstream failures do
// not flap readiness.
package flock

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"
)

// Snapshot is the cached view of upstream logparser state.
type Snapshot struct {
	Engines []string
	Routing map[string][]string
}

// Source loads the current Snapshot. Implementations must be safe for
// concurrent use.
type Source interface {
	Load(ctx context.Context) (Snapshot, error)
}

// TickerFunc creates a tick channel and a stop function. Tests inject a
// controlled channel via WithTicker.
type TickerFunc func(d time.Duration) (<-chan time.Time, func())

// Provider holds the live Snapshot and refreshes it from a Source.
type Provider struct {
	src      Source
	logger   *slog.Logger
	clock    func() time.Time
	interval time.Duration
	timeout  time.Duration
	newTick  TickerFunc

	mu      sync.RWMutex
	current Snapshot
	loaded  bool

	triggerCh chan struct{}
}

// Option configures a Provider.
type Option func(*Provider)

// WithLogger sets the slog.Logger.
func WithLogger(l *slog.Logger) Option { return func(p *Provider) { p.logger = l } }

// WithClock overrides the time source.
func WithClock(c func() time.Time) Option { return func(p *Provider) { p.clock = c } }

// WithPollInterval sets the Run polling interval. Defaults to 30s.
func WithPollInterval(d time.Duration) Option { return func(p *Provider) { p.interval = d } }

// WithRefreshTimeout bounds a single Refresh call. Defaults to 30s. Zero disables.
func WithRefreshTimeout(d time.Duration) Option { return func(p *Provider) { p.timeout = d } }

// WithTicker overrides the ticker used by Run.
func WithTicker(fn TickerFunc) Option { return func(p *Provider) { p.newTick = fn } }

// NewProvider constructs a Provider that loads Snapshots from src.
func NewProvider(src Source, opts ...Option) *Provider {
	p := &Provider{
		src:      src,
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		clock:    time.Now,
		interval: 30 * time.Second,
		timeout:  30 * time.Second,
		newTick: func(d time.Duration) (<-chan time.Time, func()) {
			t := time.NewTicker(d)
			return t.C, t.Stop
		},
		triggerCh: make(chan struct{}, 1),
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Snapshot returns the most recently loaded Snapshot.
func (p *Provider) Snapshot() Snapshot {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.current
}

// Ready reports whether at least one Refresh has succeeded. The flag latches
// true on first success and is never cleared by later errors.
func (p *Provider) Ready() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.loaded
}

// Refresh synchronously loads a Snapshot from the Source and swaps it in.
func (p *Provider) Refresh(ctx context.Context) error {
	if p.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.timeout)
		defer cancel()
	}
	snap, err := p.src.Load(ctx)
	if err != nil {
		p.logger.Warn("flock.refresh.source_error", "err", err.Error())
		return fmt.Errorf("source load: %w", err)
	}

	p.mu.Lock()
	wasLoaded := p.loaded
	p.current = snap
	p.loaded = true
	p.mu.Unlock()

	if !wasLoaded {
		p.logger.Info("flock.loaded.initial",
			"engine_count", len(snap.Engines),
			"target_count", countTargets(snap),
		)
	}
	return nil
}

func countTargets(s Snapshot) int {
	n := 0
	for _, t := range s.Routing {
		n += len(t)
	}
	return n
}

// Run drives Refresh on every ticker tick and Trigger signal until ctx is
// cancelled. Refresh errors are logged by Refresh and not propagated.
func (p *Provider) Run(ctx context.Context) error {
	tickC, stop := p.newTick(p.interval)
	defer stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tickC:
			_ = p.Refresh(ctx)
		case <-p.triggerCh:
			_ = p.Refresh(ctx)
		}
	}
}

// Trigger schedules an out-of-band Refresh. Bursts coalesce through a size-1
// buffered channel — repeated calls before Run consumes the signal are
// dropped without blocking.
func (p *Provider) Trigger() {
	select {
	case p.triggerCh <- struct{}{}:
	default:
	}
}
