package auditlog

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

// mutableSnapshot is a test double implementing RoutingSnapshotter whose
// returned config can be swapped at runtime.
type mutableSnapshot struct {
	mu  sync.Mutex
	cur RoutingConfig
}

func (m *mutableSnapshot) Snapshot() RoutingConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cur
}

func (m *mutableSnapshot) Set(cfg RoutingConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cur = cfg
}

// TestDispatcherReadsFromSnapshotter is the RED test for cycle E1:
// the Dispatcher must look up routes from a RoutingSnapshotter on every
// Dispatch call, not from a fixed map captured at construction time.
func TestDispatcherReadsFromSnapshotter(t *testing.T) {
	t.Parallel()

	var hitA, hitB atomic.Int32
	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitA.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = io.Copy(io.Discard, r.Body)
	}))
	t.Cleanup(srvA.Close)
	srvB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitB.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = io.Copy(io.Discard, r.Body)
	}))
	t.Cleanup(srvB.Close)

	snap := &mutableSnapshot{
		cur: RoutingConfig{
			SecretEngines: []string{"kv"},
			Routing:       map[string][]string{"kv": {srvA.URL}},
		},
	}

	d := NewDispatcherFromSnapshot(snap, nil)
	d.MaxRetries = 0

	event := DispatchEvent{Operation: "create", SecretEngine: "kv", SecretPath: "x"}
	if err := d.Dispatch(event); err != nil {
		t.Fatalf("first dispatch: %v", err)
	}
	if hitA.Load() != 1 || hitB.Load() != 0 {
		t.Errorf("first dispatch: expected hitA=1 hitB=0, got hitA=%d hitB=%d", hitA.Load(), hitB.Load())
	}

	// Swap routing to point at srvB.
	snap.Set(RoutingConfig{
		SecretEngines: []string{"kv"},
		Routing:       map[string][]string{"kv": {srvB.URL}},
	})

	if err := d.Dispatch(event); err != nil {
		t.Fatalf("second dispatch: %v", err)
	}
	if hitA.Load() != 1 || hitB.Load() != 1 {
		t.Errorf("second dispatch: expected hitA=1 hitB=1, got hitA=%d hitB=%d", hitA.Load(), hitB.Load())
	}
}
