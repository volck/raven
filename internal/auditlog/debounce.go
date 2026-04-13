package auditlog

import (
	"sync"
	"time"
)

// Debouncer deduplicates rapid events for the same secret within a configurable window.
// When multiple events arrive for the same key (engine+path), only the last operation
// is dispatched after the window expires.
type Debouncer struct {
	window  time.Duration
	handler func(DispatchEvent)
	mu      sync.Mutex
	pending map[string]*debounceEntry
	stopped bool
}

type debounceEntry struct {
	event DispatchEvent
	timer *time.Timer
}

// NewDebouncer creates a Debouncer with the given window and callback.
func NewDebouncer(window time.Duration, handler func(DispatchEvent)) *Debouncer {
	return &Debouncer{
		window:  window,
		handler: handler,
		pending: make(map[string]*debounceEntry),
	}
}

// Submit adds or updates an event in the debounce window.
// The key is engine+"/"+path. If an event for this key is already pending,
// the operation is updated (last write wins) and the timer is reset.
func (d *Debouncer) Submit(event DispatchEvent) {
	key := event.SecretEngine + "/" + event.SecretPath

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.stopped {
		return
	}

	if entry, ok := d.pending[key]; ok {
		entry.timer.Stop()
		entry.event = event
		entry.timer = time.AfterFunc(d.window, func() {
			d.fire(key)
		})
		return
	}

	d.pending[key] = &debounceEntry{
		event: event,
		timer: time.AfterFunc(d.window, func() {
			d.fire(key)
		}),
	}
}

func (d *Debouncer) fire(key string) {
	d.mu.Lock()
	entry, ok := d.pending[key]
	if ok {
		delete(d.pending, key)
	}
	d.mu.Unlock()

	if ok {
		d.handler(entry.event)
	}
}

// Stop cancels all pending timers.
func (d *Debouncer) Stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.stopped = true
	for _, entry := range d.pending {
		entry.timer.Stop()
	}
	d.pending = make(map[string]*debounceEntry)
}
