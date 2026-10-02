package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// rollout is one provisioning attempt as flock sees it.
type rollout struct {
	Time      time.Time     `json:"time"`
	Raven     string        `json:"raven"`
	Namespace string        `json:"namespace"`
	Engine    string        `json:"engine"`
	Actor     string        `json:"actor"`
	Branch    string        `json:"branch,omitempty"`
	Succeeded bool          `json:"succeeded"`
	Error     string        `json:"error,omitempty"`
	Stages    []stageResult `json:"stages"`
}

// journal keeps the most recent rollouts in memory for flock to poll.
type journal struct {
	mu      sync.RWMutex
	entries []rollout
	size    int
	now     func() time.Time
}

type journalOption func(*journal) journalOption

func withJournalClock(now func() time.Time) journalOption {
	return func(j *journal) journalOption {
		previous := j.now
		j.now = now
		return withJournalClock(previous)
	}
}

func newJournal(size int, opts ...journalOption) *journal {
	if size < 1 {
		size = 1
	}
	j := &journal{size: size, now: time.Now}
	j.Option(opts...)
	return j
}

func (j *journal) Option(opts ...journalOption) (previous journalOption) {
	for _, opt := range opts {
		previous = opt(j)
	}
	return previous
}

func (j *journal) record(entry rollout) {
	j.mu.Lock()
	defer j.mu.Unlock()

	if entry.Time.IsZero() {
		entry.Time = j.now().UTC()
	}
	j.entries = append(j.entries, entry)
	if len(j.entries) > j.size {
		j.entries = j.entries[len(j.entries)-j.size:]
	}
}

// recent returns a newest-first copy, so callers cannot reach the storage.
// A nil journal reports no history rather than panicking, matching how the
// create handler treats journalling as optional.
func (j *journal) recent() []rollout {
	if j == nil {
		return []rollout{}
	}

	j.mu.RLock()
	defer j.mu.RUnlock()

	out := make([]rollout, 0, len(j.entries))
	for i := len(j.entries) - 1; i >= 0; i-- {
		entry := j.entries[i]
		entry.Stages = append([]stageResult(nil), entry.Stages...)
		out = append(out, entry)
	}
	return out
}

func handleListRollouts(j *journal) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := struct {
			Rollouts []rollout `json:"rollouts"`
		}{Rollouts: j.recent()}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(body); err != nil {
			slog.ErrorContext(r.Context(), "write rollouts", "error", err)
		}
	})
}
