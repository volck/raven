// Package raven is a read-only HTTP health-probe client targeting a raven
// instance's /healthz endpoint. It does not call any state-changing endpoints.
package raven

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"
)

// Client probes raven instances by GETing their /healthz endpoint.
type Client struct {
	httpC     *http.Client
	logger    *slog.Logger
	timeout   time.Duration
	tlsConfig *tls.Config
}

// Option configures a Client. Self-referential per Pike's pattern.
type Option func(*Client) Option

// WithHTTPClient overrides the underlying *http.Client.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) Option {
		prev := c.httpC
		c.httpC = h
		return WithHTTPClient(prev)
	}
}

// WithLogger overrides the logger.
func WithLogger(l *slog.Logger) Option {
	return func(c *Client) Option {
		prev := c.logger
		c.logger = l
		return WithLogger(prev)
	}
}

// WithRequestTimeout sets the per-probe timeout.
func WithRequestTimeout(d time.Duration) Option {
	return func(c *Client) Option {
		prev := c.timeout
		c.timeout = d
		return WithRequestTimeout(prev)
	}
}

// WithTLSConfig sets a *tls.Config used for both HTTPS probe requests and
// WebSocket dials. Passing nil restores Go's default TLS behaviour. The
// config is shared by reference; callers must not mutate it after passing it.
func WithTLSConfig(t *tls.Config) Option {
	return func(c *Client) Option {
		prev := c.tlsConfig
		c.tlsConfig = t
		return WithTLSConfig(prev)
	}
}

// New constructs a probe Client.
func New(opts ...Option) (*Client, error) {
	c := &Client{
		httpC:   &http.Client{Timeout: 5 * time.Second},
		logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		timeout: 5 * time.Second,
	}
	for _, opt := range opts {
		opt(c)
	}
	if c.tlsConfig != nil {
		tr, ok := c.httpC.Transport.(*http.Transport)
		if !ok || tr == nil {
			base, ok := http.DefaultTransport.(*http.Transport)
			if !ok {
				return nil, fmt.Errorf("default http transport is not *http.Transport")
			}
			tr = base.Clone()
		} else {
			tr = tr.Clone()
		}
		tr.TLSClientConfig = c.tlsConfig.Clone()
		c.httpC.Transport = tr
	}
	return c, nil
}

// Probe GETs baseURL+"/healthz". Returns (true, nil) on 2xx, (false, nil) on
// 4xx/5xx, and (false, err) on transport/url errors.
func (c *Client) Probe(ctx context.Context, baseURL string) (bool, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return false, fmt.Errorf("parse base url: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return false, fmt.Errorf("base url must include scheme and host: %q", baseURL)
	}
	u.Path = "/healthz"

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return false, fmt.Errorf("new request: %w", err)
	}
	resp, err := c.httpC.Do(req)
	if err != nil {
		return false, fmt.Errorf("probe %s: %w", baseURL, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	return resp.StatusCode >= 200 && resp.StatusCode < 300, nil
}

// Event mirrors raven's internal/api.SyncEvent for read-only consumption.
type Event struct {
	Time      time.Time `json:"time"`
	Operation string    `json:"operation"`
	Engine    string    `json:"engine"`
	Path      string    `json:"path"`
	Status    string    `json:"status"`
	Message   string    `json:"message"`
}

// Status mirrors raven's internal/api.StatusInfo for read-only consumption.
// Field names match the JSON contract exactly.
type Status struct {
	Engine      string       `json:"engine"`
	DestEnv     string       `json:"dest_env"`
	VaultURL    string       `json:"vault_url"`
	Sync        SyncSummary  `json:"sync"`
	Secrets     []SecretFile `json:"secrets"`
	SecretCount int          `json:"secret_count"`
	EventCount  int          `json:"event_count"`
	GeneratedAt time.Time    `json:"generated_at"`
}

// SyncSummary mirrors raven's sync timing block.
type SyncSummary struct {
	LastSync     time.Time `json:"last_sync"`
	NextSync     time.Time `json:"next_sync"`
	SleepSeconds int       `json:"sleep_seconds"`
	Overdue      bool      `json:"overdue"`
}

// SecretFile is one gitops-managed secret entry, optionally with K8s state.
type SecretFile struct {
	Name       string          `json:"name"`
	SecretName string          `json:"secret_name"`
	Modified   time.Time       `json:"modified"`
	K8s        *SecretK8sState `json:"k8s,omitempty"`
}

// SecretK8sState is the K8s-side facts about a secret (deployments using it,
// when the K8s Secret object was last modified, etc.).
type SecretK8sState struct {
	Created      string   `json:"created,omitempty"`
	Modified     string   `json:"modified,omitempty"`
	Source       string   `json:"source,omitempty"`
	Deployments  []string `json:"deployments,omitempty"`
	StatefulSets []string `json:"statefulsets,omitempty"`
}

// Events GETs baseURL+"/api/v1/events" and decodes the JSON array. The
// returned slice is the order raven sent (newest first by raven's contract).
// Non-2xx responses return an error.
func (c *Client) Events(ctx context.Context, baseURL string) ([]Event, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse base url: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("base url must include scheme and host: %q", baseURL)
	}
	u.Path = "/api/v1/events"

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	resp, err := c.httpC.Do(req)
	if err != nil {
		return nil, fmt.Errorf("events %s: %w", baseURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("events %s: status %d", baseURL, resp.StatusCode)
	}
	// Cap the body at 4 MiB to avoid runaway responses.
	body := io.LimitReader(resp.Body, 4<<20)
	var out []Event
	if err := json.NewDecoder(body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode events: %w", err)
	}
	return out, nil
}

// Status GETs baseURL+"/api/v1/status" and decodes the bundled status
// payload. Non-2xx responses return an error.
func (c *Client) Status(ctx context.Context, baseURL string) (Status, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return Status{}, fmt.Errorf("parse base url: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return Status{}, fmt.Errorf("base url must include scheme and host: %q", baseURL)
	}
	u.Path = "/api/v1/status"

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return Status{}, fmt.Errorf("new request: %w", err)
	}
	resp, err := c.httpC.Do(req)
	if err != nil {
		return Status{}, fmt.Errorf("status %s: %w", baseURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		return Status{}, fmt.Errorf("status %s: status %d", baseURL, resp.StatusCode)
	}
	body := io.LimitReader(resp.Body, 4<<20)
	var out Status
	if err := json.NewDecoder(body).Decode(&out); err != nil {
		return Status{}, fmt.Errorf("decode status: %w", err)
	}
	return out, nil
}
