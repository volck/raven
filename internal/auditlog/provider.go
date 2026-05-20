package auditlog

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Source loads the current desired RoutingConfig from somewhere (typically
// a git repository). Implementations must be safe for concurrent use.
type Source interface {
	Load(ctx context.Context) (RoutingConfig, error)
}

// Provider holds the live RoutingConfig and refreshes it from a Source.
// Snapshot is safe for concurrent readers; updates happen on Refresh and
// on each tick of the Run loop.
type Provider struct {
	src      Source
	logger   *slog.Logger
	clock    func() time.Time
	interval time.Duration
	timeout  time.Duration
	newTick  TickerFunc

	mu      sync.RWMutex
	current RoutingConfig
	loaded  bool

	triggerCh chan struct{}
}

// TickerFunc creates a tick channel and a stop function. The default uses
// time.NewTicker; tests inject a controlled channel via WithTicker.
type TickerFunc func(d time.Duration) (<-chan time.Time, func())

// Option configures a Provider. Use the With* constructors below to build
// option values for NewProvider.
type Option func(*Provider)

// WithLogger sets the slog.Logger used for transition and error logs.
// If unset, a discard logger is used.
func WithLogger(l *slog.Logger) Option {
	return func(p *Provider) { p.logger = l }
}

// WithClock overrides the time source used for log timestamps and ticker
// scheduling. Defaults to time.Now.
func WithClock(c func() time.Time) Option {
	return func(p *Provider) { p.clock = c }
}

// WithPollInterval sets how often Run polls the Source. Defaults to 30s.
func WithPollInterval(d time.Duration) Option {
	return func(p *Provider) { p.interval = d }
}

// WithRefreshTimeout bounds the duration of a single Refresh call. Defaults
// to 60s. A value of zero disables the timeout.
func WithRefreshTimeout(d time.Duration) Option {
	return func(p *Provider) { p.timeout = d }
}

// WithTicker overrides the ticker used by Run. Defaults to time.NewTicker.
// Tests use this to inject a controlled tick channel.
func WithTicker(fn TickerFunc) Option {
	return func(p *Provider) { p.newTick = fn }
}

// NewProvider constructs a Provider that loads RoutingConfig from src.
// All optional dependencies are supplied via functional options.
func NewProvider(src Source, opts ...Option) *Provider {
	p := &Provider{
		src:      src,
		logger:   slog.Default(),
		clock:    time.Now,
		interval: 30 * time.Second,
		timeout:  60 * time.Second,
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

// Snapshot returns the most recently loaded RoutingConfig. Before the first
// successful Refresh it returns a zero-value RoutingConfig.
func (p *Provider) Snapshot() RoutingConfig {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.current
}

// Ready reports whether at least one Refresh has succeeded.
func (p *Provider) Ready() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.loaded
}

// Refresh synchronously loads a RoutingConfig from the Source and, if it
// passes ValidateRouting, swaps it in as the live snapshot. The first
// successful Refresh logs "loaded.initial"; subsequent Refreshes that
// change the config log "transition" with a structured diff. A Refresh
// that produces no change logs nothing.
func (p *Provider) Refresh(ctx context.Context) error {
	if p.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.timeout)
		defer cancel()
	}
	cfg, err := p.src.Load(ctx)
	if err != nil {
		p.logger.Warn("routing.refresh.source_error", "err", err.Error())
		return fmt.Errorf("source load: %w", err)
	}
	if err := ValidateRouting(cfg); err != nil {
		p.logger.Warn("routing.refresh.invalid", "err", err.Error())
		return fmt.Errorf("validate routing: %w", err)
	}

	p.mu.Lock()
	wasLoaded := p.loaded
	prev := p.current
	p.current = cfg
	p.loaded = true
	p.mu.Unlock()

	if !wasLoaded {
		p.logger.Info("loaded.initial",
			"engine_count", len(cfg.SecretEngines),
			"target_count", countTargets(cfg),
		)
		return nil
	}
	diff := DiffRouting(prev, cfg)
	if diff.HasChanges() {
		p.logger.Info("transition",
			"engines_added", diff.EnginesAdded,
			"engines_removed", diff.EnginesRemoved,
			"targets_added", diff.TargetsAdded,
			"targets_removed", diff.TargetsRemoved,
		)
	}
	return nil
}

func countTargets(cfg RoutingConfig) int {
	n := 0
	for _, targets := range cfg.Routing {
		n += len(targets)
	}
	return n
}

// Run drives Refresh on every tick from the configured ticker until ctx is
// cancelled. Errors from individual Refresh calls are already logged by
// Refresh; Run does not propagate them.
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

// Trigger schedules an out-of-band Refresh. Calls coalesce through a size-1
// buffered channel — repeated calls before Run consumes the signal are
// dropped without blocking.
func (p *Provider) Trigger() {
	select {
	case p.triggerCh <- struct{}{}:
	default:
	}
}
