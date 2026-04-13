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

// Dispatcher routes secret events to the correct Raven API instance.
type Dispatcher struct {
	routing        map[string]string // secret engine → Raven URL
	httpClient     *http.Client
	MaxRetries     int           // Maximum number of retry attempts (0 = no retry)
	RetryBaseDelay time.Duration // Base delay for exponential backoff
}

// NewDispatcher creates a Dispatcher with the given routing table and optional HTTP client.
// If httpClient is nil, http.DefaultClient is used.
func NewDispatcher(routing map[string]string, httpClient *http.Client) *Dispatcher {
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

// Dispatch sends a secret event to the appropriate Raven API instance.
// Retries with exponential backoff on transient failures (5xx or connection errors).
func (d *Dispatcher) Dispatch(event DispatchEvent) error {
	targetURL, ok := d.routing[event.SecretEngine]
	if !ok {
		return fmt.Errorf("no route configured for engine: %s", event.SecretEngine)
	}

	body, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

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
