package auditlog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// DispatchEvent is the payload sent to Raven API instances.
type DispatchEvent struct {
	Operation    string `json:"operation"`
	SecretEngine string `json:"secret_engine"`
	SecretPath   string `json:"secret_path"`
}

// Dispatcher routes secret events to the correct Raven API instance(s).
type Dispatcher struct {
	routing        map[string][]string // legacy static routing (used when snapshot is nil)
	snapshot       RoutingSnapshotter
	httpClient     *http.Client
	MaxRetries     int           // Maximum number of retry attempts (0 = no retry)
	RetryBaseDelay time.Duration // Base delay for exponential backoff
}

// RoutingSnapshotter exposes the current RoutingConfig to the Dispatcher.
// The Provider implements this interface.
type RoutingSnapshotter interface {
	Snapshot() RoutingConfig
}

// NewDispatcher creates a Dispatcher with a static routing table. Used by
// existing callers; new callers should prefer NewDispatcherFromSnapshot so
// routes update at runtime without restarting the process.
func NewDispatcher(routing map[string][]string, httpClient *http.Client) *Dispatcher {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Dispatcher{
		routing:        routing,
		httpClient:     httpClient,
		MaxRetries:     3,
		RetryBaseDelay: 1 * time.Second,
	}
}

// NewDispatcherFromSnapshot creates a Dispatcher that looks up routes from
// the given RoutingSnapshotter on every Dispatch call. This is the canonical
// constructor; Provider implements RoutingSnapshotter.
func NewDispatcherFromSnapshot(snap RoutingSnapshotter, httpClient *http.Client) *Dispatcher {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Dispatcher{
		snapshot:       snap,
		httpClient:     httpClient,
		MaxRetries:     3,
		RetryBaseDelay: 1 * time.Second,
	}
}

// routes returns the current routing table — from the live snapshot if
// configured, otherwise from the static map passed to NewDispatcher.
func (d *Dispatcher) routes() map[string][]string {
	if d.snapshot != nil {
		return d.snapshot.Snapshot().Routing
	}
	return d.routing
}

// Dispatch sends a secret event to the appropriate Raven API instance(s).
// If multiple URLs are configured for an engine, dispatches to all of them.
// Retries with exponential backoff on transient failures (5xx or connection errors).
func (d *Dispatcher) Dispatch(event DispatchEvent) error {
	routing := d.routes()
	targetURLs, ok := routing[event.SecretEngine]
	if !ok || len(targetURLs) == 0 {
		return fmt.Errorf("no route configured for engine: %s", event.SecretEngine)
	}

	body, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	var errs []error
	for _, targetURL := range targetURLs {
		if err := d.dispatchToURL(targetURL, body); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", targetURL, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("dispatch errors: %v", errs)
	}
	return nil
}

func (d *Dispatcher) dispatchToURL(targetURL string, body []byte) error {

	var lastErr error
	maxAttempts := 1 + d.MaxRetries
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			delay := d.RetryBaseDelay * time.Duration(1<<(attempt-1))
			time.Sleep(delay)
		}

		req, err := http.NewRequest(http.MethodPost, targetURL+"/api/v1/secret", bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := d.httpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("dispatch request failed: %w", err)
			continue
		}
		resp.Body.Close()

		if resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("dispatch returned status %d", resp.StatusCode)
			continue
		}
		if resp.StatusCode >= 400 {
			return fmt.Errorf("dispatch returned status %d", resp.StatusCode)
		}

		return nil
	}

	return fmt.Errorf("dispatch failed after %d attempts: %w", maxAttempts, lastErr)
}
