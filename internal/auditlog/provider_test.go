package auditlog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// fakeSource is a minimal in-memory Source for testing the Provider.
type fakeSource struct {
	loads   int
	cfgs    []RoutingConfig // sequence of configs to return on each Load
	errs    []error         // sequence of errors (same length as cfgs)
}

func (f *fakeSource) Load(ctx context.Context) (RoutingConfig, error) {
	i := f.loads
	f.loads++
	if i >= len(f.cfgs) {
		if len(f.cfgs) > 0 {
			return f.cfgs[len(f.cfgs)-1], nil
		}
		return RoutingConfig{}, nil
	}
	if i < len(f.errs) && f.errs[i] != nil {
		return RoutingConfig{}, f.errs[i]
	}
	return f.cfgs[i], nil
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

// TestNewProviderConstructsWithOptions is the RED test for cycle D1:
// the Provider has a functional-options constructor accepting at minimum
// WithLogger, WithClock, and WithPollInterval.
func TestNewProviderConstructsWithOptions(t *testing.T) {
	t.Parallel()

	src := &fakeSource{}
	p := NewProvider(src,
		WithLogger(discardLogger()),
		WithClock(fixedClock(time.Date(2026, 5, 20, 0, 0, 0, 0, time.UTC))),
		WithPollInterval(30*time.Second),
	)
	if p == nil {
		t.Fatal("NewProvider returned nil")
	}

	// Before any load, Snapshot returns the zero-value RoutingConfig.
	got := p.Snapshot()
	if len(got.SecretEngines) != 0 || len(got.Routing) != 0 {
		t.Errorf("expected empty snapshot before load, got: %+v", got)
	}
}

// captureLogger returns a logger that writes JSON to the returned buffer.
func captureLogger() (*slog.Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	return slog.New(slog.NewJSONHandler(buf, nil)), buf
}

// logRecords parses each JSON line in buf into a map.
func logRecords(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("non-JSON log line %q: %v", line, err)
		}
		out = append(out, rec)
	}
	return out
}

// findLog returns the first log record whose "msg" equals msg, or nil.
func findLog(records []map[string]any, msg string) map[string]any {
	for _, r := range records {
		if r["msg"] == msg {
			return r
		}
	}
	return nil
}

// TestProviderRefreshInitialLoad is the RED test for cycle D2:
// the first successful Refresh logs a "loaded.initial" event and makes the
// new config available via Snapshot.
func TestProviderRefreshInitialLoad(t *testing.T) {
	t.Parallel()

	cfg := RoutingConfig{
		SecretEngines: []string{"kv", "ssg"},
		Routing: map[string][]string{
			"kv":  {"http://a", "http://b"},
			"ssg": {"http://c"},
		},
	}
	src := &fakeSource{cfgs: []RoutingConfig{cfg}}
	logger, buf := captureLogger()
	p := NewProvider(src, WithLogger(logger))

	if err := p.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	got := p.Snapshot()
	if len(got.SecretEngines) != 2 {
		t.Errorf("expected 2 engines after refresh, got %+v", got)
	}

	records := logRecords(t, buf)
	rec := findLog(records, "loaded.initial")
	if rec == nil {
		t.Fatalf("expected a 'loaded.initial' log entry, got: %s", buf.String())
	}
	if v := rec["engine_count"]; v != float64(2) {
		t.Errorf("expected engine_count=2, got %v", v)
	}
	if v := rec["target_count"]; v != float64(3) {
		t.Errorf("expected target_count=3, got %v", v)
	}
}

// TestProviderRefreshTransitionLogged is the RED test for cycle D3:
// when a subsequent Refresh delivers a different config, the Provider
// logs a "transition" event containing the diff.
func TestProviderRefreshTransitionLogged(t *testing.T) {
	t.Parallel()

	cfg1 := RoutingConfig{
		SecretEngines: []string{"kv"},
		Routing:       map[string][]string{"kv": {"http://a"}},
	}
	cfg2 := RoutingConfig{
		SecretEngines: []string{"kv", "ssg"},
		Routing: map[string][]string{
			"kv":  {"http://a", "http://b"},
			"ssg": {"http://c"},
		},
	}
	src := &fakeSource{cfgs: []RoutingConfig{cfg1, cfg2}}
	logger, buf := captureLogger()
	p := NewProvider(src, WithLogger(logger))

	if err := p.Refresh(context.Background()); err != nil {
		t.Fatalf("first Refresh: %v", err)
	}
	buf.Reset()
	if err := p.Refresh(context.Background()); err != nil {
		t.Fatalf("second Refresh: %v", err)
	}

	records := logRecords(t, buf)
	rec := findLog(records, "transition")
	if rec == nil {
		t.Fatalf("expected 'transition' log entry, got: %s", buf.String())
	}

	// Must NOT log loaded.initial on subsequent refresh.
	if findLog(records, "loaded.initial") != nil {
		t.Errorf("did not expect 'loaded.initial' on second refresh, got: %s", buf.String())
	}

	// Engines added: ssg
	added, _ := rec["engines_added"].([]any)
	if len(added) != 1 || added[0] != "ssg" {
		t.Errorf("expected engines_added=[ssg], got %v", added)
	}
	// Targets added on kept engine kv: http://b
	ta, _ := rec["targets_added"].(map[string]any)
	if ta == nil {
		t.Fatalf("expected targets_added map, got %v", rec["targets_added"])
	}
	if kv, _ := ta["kv"].([]any); len(kv) != 1 || kv[0] != "http://b" {
		t.Errorf("expected targets_added.kv=[http://b], got %v", ta["kv"])
	}
}

// TestProviderRefreshNoChangeSilent is the RED test for cycle D4:
// a Refresh that returns the same config as the current snapshot must
// not emit any log records.
func TestProviderRefreshNoChangeSilent(t *testing.T) {
	t.Parallel()

	cfg := RoutingConfig{
		SecretEngines: []string{"kv"},
		Routing:       map[string][]string{"kv": {"http://a"}},
	}
	src := &fakeSource{cfgs: []RoutingConfig{cfg, cfg}}
	logger, buf := captureLogger()
	p := NewProvider(src, WithLogger(logger))

	if err := p.Refresh(context.Background()); err != nil {
		t.Fatalf("first Refresh: %v", err)
	}
	buf.Reset()
	if err := p.Refresh(context.Background()); err != nil {
		t.Fatalf("second Refresh: %v", err)
	}

	if buf.Len() != 0 {
		t.Errorf("expected silent no-change refresh, got logs: %s", buf.String())
	}
}

// TestProviderRefreshInvalidConfigSkipped is the RED test for cycle D5:
// when the Source returns a config that fails ValidateRouting, Refresh
// must return an error, log a WARN, and leave the previous snapshot intact.
func TestProviderRefreshInvalidConfigSkipped(t *testing.T) {
	t.Parallel()

	cfg1 := RoutingConfig{
		SecretEngines: []string{"kv"},
		Routing:       map[string][]string{"kv": {"http://a"}},
	}
	cfgBad := RoutingConfig{
		SecretEngines: []string{"kv"},
		Routing:       map[string][]string{}, // no route for kv
	}
	src := &fakeSource{cfgs: []RoutingConfig{cfg1, cfgBad}}
	logger, buf := captureLogger()
	p := NewProvider(src, WithLogger(logger))

	if err := p.Refresh(context.Background()); err != nil {
		t.Fatalf("first Refresh: %v", err)
	}
	buf.Reset()

	err := p.Refresh(context.Background())
	if err == nil {
		t.Fatal("expected Refresh to return error for invalid config")
	}

	// Snapshot must still be cfg1.
	got := p.Snapshot()
	if len(got.SecretEngines) != 1 || got.SecretEngines[0] != "kv" {
		t.Errorf("expected previous snapshot to remain, got %+v", got)
	}

	records := logRecords(t, buf)
	rec := findLog(records, "routing.refresh.invalid")
	if rec == nil {
		t.Fatalf("expected 'routing.refresh.invalid' WARN log, got: %s", buf.String())
	}
	if rec["level"] != "WARN" {
		t.Errorf("expected level=WARN, got %v", rec["level"])
	}
}

// TestProviderRefreshSourceErrorLogged is the RED test for cycle D6:
// when the Source returns an error, Refresh must return the wrapped error,
// log a WARN, and leave the previous snapshot intact.
func TestProviderRefreshSourceErrorLogged(t *testing.T) {
	t.Parallel()

	cfg1 := RoutingConfig{
		SecretEngines: []string{"kv"},
		Routing:       map[string][]string{"kv": {"http://a"}},
	}
	boom := errors.New("git clone failed")
	src := &fakeSource{
		cfgs: []RoutingConfig{cfg1, {}},
		errs: []error{nil, boom},
	}
	logger, buf := captureLogger()
	p := NewProvider(src, WithLogger(logger))

	if err := p.Refresh(context.Background()); err != nil {
		t.Fatalf("first Refresh: %v", err)
	}
	buf.Reset()

	err := p.Refresh(context.Background())
	if err == nil {
		t.Fatal("expected Refresh to return error when source fails")
	}
	if !errors.Is(err, boom) {
		t.Errorf("expected error to wrap source error, got: %v", err)
	}

	got := p.Snapshot()
	if len(got.SecretEngines) != 1 || got.SecretEngines[0] != "kv" {
		t.Errorf("expected previous snapshot to remain, got %+v", got)
	}

	records := logRecords(t, buf)
	rec := findLog(records, "routing.refresh.source_error")
	if rec == nil {
		t.Fatalf("expected 'routing.refresh.source_error' WARN log, got: %s", buf.String())
	}
	if rec["level"] != "WARN" {
		t.Errorf("expected level=WARN, got %v", rec["level"])
	}
}

// blockingSource blocks Load until its ctx is cancelled, then returns ctx.Err().
type blockingSource struct{}

func (blockingSource) Load(ctx context.Context) (RoutingConfig, error) {
	<-ctx.Done()
	return RoutingConfig{}, ctx.Err()
}

// TestProviderRefreshAppliesTimeout is the RED test for cycle D7:
// Refresh applies a per-call timeout (configurable via WithRefreshTimeout)
// so a hung Source does not block the caller forever.
func TestProviderRefreshAppliesTimeout(t *testing.T) {
	t.Parallel()

	logger, _ := captureLogger()
	p := NewProvider(blockingSource{},
		WithLogger(logger),
		WithRefreshTimeout(50*time.Millisecond),
	)

	start := time.Now()
	err := p.Refresh(context.Background())
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error from timed-out Refresh, got nil")
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("expected Refresh to return within ~50ms, took %s", elapsed)
	}
}

// TestProviderRunRefreshesOnTick is the RED test for cycle D8:
// Provider.Run(ctx) calls Refresh on every tick from the injected ticker
// and returns nil when ctx is cancelled.
func TestProviderRunRefreshesOnTick(t *testing.T) {
	t.Parallel()

	cfg1 := RoutingConfig{
		SecretEngines: []string{"kv"},
		Routing:       map[string][]string{"kv": {"http://a"}},
	}
	cfg2 := RoutingConfig{
		SecretEngines: []string{"kv", "ssg"},
		Routing: map[string][]string{
			"kv":  {"http://a"},
			"ssg": {"http://b"},
		},
	}
	src := &fakeSource{cfgs: []RoutingConfig{cfg1, cfg2, cfg2, cfg2}}
	logger, _ := captureLogger()

	tickC := make(chan time.Time, 4)
	p := NewProvider(src,
		WithLogger(logger),
		WithTicker(func(d time.Duration) (<-chan time.Time, func()) {
			return tickC, func() {}
		}),
	)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	runErr := make(chan error, 1)
	go func() { runErr <- p.Run(ctx) }()

	// First tick: cfg1 loaded.
	tickC <- time.Now()
	// Poll until first refresh visible.
	deadline := time.Now().Add(time.Second)
	for {
		if len(p.Snapshot().SecretEngines) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for first tick refresh")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Second tick: cfg2 loaded.
	tickC <- time.Now()
	deadline = time.Now().Add(time.Second)
	for {
		if len(p.Snapshot().SecretEngines) == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for second tick refresh")
		}
		time.Sleep(5 * time.Millisecond)
	}

	cancel()
	select {
	case err := <-runErr:
		if err != nil {
			t.Errorf("Run returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within 2s of ctx cancel")
	}
}

// TestProviderTriggerCoalesces is the RED test for cycle D9:
// Trigger sends a non-blocking refresh signal that is coalesced through a
// size-1 buffered channel. Multiple Trigger calls before Run consumes them
// produce at most one extra Refresh.
func TestProviderTriggerCoalesces(t *testing.T) {
	t.Parallel()

	cfg := RoutingConfig{
		SecretEngines: []string{"kv"},
		Routing:       map[string][]string{"kv": {"http://a"}},
	}
	src := &fakeSource{cfgs: []RoutingConfig{cfg, cfg, cfg, cfg, cfg, cfg}}
	logger, _ := captureLogger()

	tickC := make(chan time.Time)
	p := NewProvider(src,
		WithLogger(logger),
		WithTicker(func(d time.Duration) (<-chan time.Time, func()) {
			return tickC, func() {}
		}),
	)

	// Fire 5 triggers BEFORE Run starts. With size-1 buffer, 4 must be dropped.
	for i := 0; i < 5; i++ {
		p.Trigger()
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	runErr := make(chan error, 1)
	go func() { runErr <- p.Run(ctx) }()

	// Wait until Snapshot reflects the load (load count went from 0 to 1).
	deadline := time.Now().Add(time.Second)
	for {
		if len(p.Snapshot().SecretEngines) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for triggered refresh")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Give it a moment to let any other queued triggers fire.
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-runErr

	if src.loads > 2 {
		t.Errorf("expected at most 2 refreshes (1 triggered + 1 coalesce slack), got %d", src.loads)
	}
	if src.loads < 1 {
		t.Errorf("expected at least 1 refresh from Trigger, got %d", src.loads)
	}
}
