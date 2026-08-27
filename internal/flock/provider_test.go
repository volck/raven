package flock_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/volck/raven/internal/flock"
)

type fakeSource struct {
	mu    sync.Mutex
	snaps []flock.Snapshot
	errs  []error
	calls int32
}

func (f *fakeSource) Load(ctx context.Context) (flock.Snapshot, error) {
	atomic.AddInt32(&f.calls, 1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.errs) > 0 {
		err := f.errs[0]
		f.errs = f.errs[1:]
		if err != nil {
			return flock.Snapshot{}, err
		}
	}
	if len(f.snaps) == 0 {
		return flock.Snapshot{}, nil
	}
	s := f.snaps[0]
	if len(f.snaps) > 1 {
		f.snaps = f.snaps[1:]
	}
	return s, nil
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// D'1
func TestProvider_ZeroState(t *testing.T) {
	t.Parallel()
	p := flock.NewProvider(&fakeSource{}, flock.WithLogger(discardLogger()))
	if p.Ready() {
		t.Fatal("Ready true before any Refresh")
	}
	s := p.Snapshot()
	if s.Engines != nil || s.Routing != nil {
		t.Fatalf("Snapshot not zero: %+v", s)
	}
}

// D'2
func TestProvider_RefreshLoadsAndMarksReady(t *testing.T) {
	t.Parallel()
	src := &fakeSource{snaps: []flock.Snapshot{
		{Engines: []string{"dev", "prod01"}, Routing: map[string][]string{
			"dev":    {"https://r1.example"},
			"prod01": {"https://r2.example"},
		}},
	}}
	p := flock.NewProvider(src, flock.WithLogger(discardLogger()))
	if err := p.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if !p.Ready() {
		t.Fatal("Ready false after successful Refresh")
	}
	s := p.Snapshot()
	if len(s.Engines) != 2 {
		t.Fatalf("engines = %v", s.Engines)
	}
	if got := s.Routing["dev"]; len(got) != 1 || got[0] != "https://r1.example" {
		t.Fatalf("routing[dev] = %v", got)
	}
}

// D'3
func TestProvider_RefreshSourceError(t *testing.T) {
	t.Parallel()
	src := &fakeSource{errs: []error{errors.New("boom")}}
	p := flock.NewProvider(src, flock.WithLogger(discardLogger()))
	if err := p.Refresh(context.Background()); err == nil {
		t.Fatal("want error")
	}
	if p.Ready() {
		t.Fatal("Ready true after failed Refresh")
	}
}

// D'4 — Ready latches: once true, stays true across later errors.
func TestProvider_ReadyLatches(t *testing.T) {
	t.Parallel()
	src := &fakeSource{
		snaps: []flock.Snapshot{{Engines: []string{"dev"}}, {Engines: []string{"dev"}}},
		errs:  []error{nil, errors.New("transient")},
	}
	p := flock.NewProvider(src, flock.WithLogger(discardLogger()))
	if err := p.Refresh(context.Background()); err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	if err := p.Refresh(context.Background()); err == nil {
		t.Fatal("second refresh should error")
	}
	if !p.Ready() {
		t.Fatal("Ready cleared after later error; should latch")
	}
}

// D'5 — Run drives Refresh from injected ticker.
func TestProvider_RunDrivesRefresh(t *testing.T) {
	t.Parallel()
	src := &fakeSource{snaps: []flock.Snapshot{
		{Engines: []string{"dev"}},
		{Engines: []string{"dev", "prod01"}},
	}}
	tickC := make(chan time.Time, 4)
	p := flock.NewProvider(src,
		flock.WithLogger(discardLogger()),
		flock.WithTicker(func(d time.Duration) (<-chan time.Time, func()) {
			return tickC, func() {}
		}),
	)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()

	tickC <- time.Now()
	deadline := time.After(2 * time.Second)
	for {
		if atomic.LoadInt32(&src.calls) >= 1 && p.Ready() {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("Run did not refresh; calls=%d ready=%v", atomic.LoadInt32(&src.calls), p.Ready())
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run err: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return on ctx cancel")
	}
}

// D'6 — Trigger coalesces and drives Refresh.
func TestProvider_TriggerCoalesces(t *testing.T) {
	t.Parallel()
	src := &fakeSource{snaps: []flock.Snapshot{{Engines: []string{"dev"}}}}
	tickC := make(chan time.Time)
	p := flock.NewProvider(src,
		flock.WithLogger(discardLogger()),
		flock.WithTicker(func(d time.Duration) (<-chan time.Time, func()) {
			return tickC, func() {}
		}),
	)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()

	// Burst of triggers — should not block, should coalesce.
	for i := 0; i < 50; i++ {
		p.Trigger()
	}
	deadline := time.After(2 * time.Second)
	for atomic.LoadInt32(&src.calls) == 0 {
		select {
		case <-deadline:
			t.Fatal("Trigger did not cause a Refresh")
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	<-done
}
