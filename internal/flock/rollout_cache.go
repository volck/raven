package flock

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"time"

	wrclient "github.com/volck/raven/internal/flock/wrangler"
)

// RolloutSource fetches recent provisioning attempts from wrangler.
type RolloutSource interface {
	Rollouts(ctx context.Context) ([]wrclient.Rollout, error)
}

// RolloutCache polls wrangler and serves the last successful response.
type RolloutCache struct {
	src      RolloutSource
	logger   *slog.Logger
	interval time.Duration
	timeout  time.Duration
	newTick  TickerFunc

	mu      sync.RWMutex
	current []wrclient.Rollout

	triggerCh chan struct{}
}

type RolloutCacheOption func(*RolloutCache)

func WithRolloutLogger(l *slog.Logger) RolloutCacheOption {
	return func(c *RolloutCache) { c.logger = l }
}

func WithRolloutInterval(d time.Duration) RolloutCacheOption {
	return func(c *RolloutCache) { c.interval = d }
}

func WithRolloutTimeout(d time.Duration) RolloutCacheOption {
	return func(c *RolloutCache) { c.timeout = d }
}

func WithRolloutTicker(f TickerFunc) RolloutCacheOption {
	return func(c *RolloutCache) { c.newTick = f }
}

func NewRolloutCache(src RolloutSource, opts ...RolloutCacheOption) *RolloutCache {
	c := &RolloutCache{
		src:      src,
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		interval: 30 * time.Second,
		timeout:  10 * time.Second,
		newTick: func(d time.Duration) (<-chan time.Time, func()) {
			t := time.NewTicker(d)
			return t.C, t.Stop
		},
		triggerCh: make(chan struct{}, 1),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// RunOnce refreshes the cache. A failed poll keeps the previous value, so a
// wrangler outage does not erase the rollout history flock is showing.
func (c *RolloutCache) RunOnce(ctx context.Context) {
	if c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}

	rollouts, err := c.src.Rollouts(ctx)
	if err != nil {
		c.logger.WarnContext(ctx, "flock.rollouts.fetch_failed", "err", err.Error())
		return
	}

	c.mu.Lock()
	c.current = rollouts
	c.mu.Unlock()
}

func (c *RolloutCache) Run(ctx context.Context) error {
	tickC, stop := c.newTick(c.interval)
	defer stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tickC:
			c.RunOnce(ctx)
		case <-c.triggerCh:
			c.RunOnce(ctx)
		}
	}
}

func (c *RolloutCache) Trigger() {
	select {
	case c.triggerCh <- struct{}{}:
	default:
	}
}

func (c *RolloutCache) Rollouts() []wrclient.Rollout {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return append([]wrclient.Rollout(nil), c.current...)
}

func (c *RolloutCache) RolloutsForEngine(engine string) []wrclient.Rollout {
	c.mu.RLock()
	defer c.mu.RUnlock()

	out := []wrclient.Rollout{}
	for _, r := range c.current {
		if r.Engine == engine {
			out = append(out, r)
		}
	}
	return out
}
