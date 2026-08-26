package logparser

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"
)

// ErrNotFound is returned by GetSSG when the engine name is unknown to the
// upstream logparser.
var ErrNotFound = errors.New("logparser: ssg not found")

// Client is a read-only HTTP client for an upstream raven-logparser instance.
type Client struct {
	base    *url.URL
	httpC   *http.Client
	logger  *slog.Logger
	timeout time.Duration
}

// Option configures a Client. Self-referential per Pike's pattern: each
// Option returns its own inverse so callers can restore the previous state.
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

// WithRequestTimeout sets the per-request timeout applied via context.
func WithRequestTimeout(d time.Duration) Option {
	return func(c *Client) Option {
		prev := c.timeout
		c.timeout = d
		return WithRequestTimeout(prev)
	}
}

// New constructs a Client targeting baseURL.
func New(baseURL string, opts ...Option) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse base url: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("base url must include scheme and host: %q", baseURL)
	}
	c := &Client{
		base:    u,
		httpC:   &http.Client{Timeout: 10 * time.Second},
		logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		timeout: 10 * time.Second,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c, nil
}

// ListSSGs returns the SSG engine names known to the upstream logparser.
func (c *Client) ListSSGs(ctx context.Context) ([]string, error) {
	var out []string
	if err := c.getJSON(ctx, "/api/v1/ssgs", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// GetSSG returns the raven targets for the named engine, or ErrNotFound if
// the engine is unknown.
func (c *Client) GetSSG(ctx context.Context, name string) ([]string, error) {
	var out []string
	if err := c.getJSON(ctx, "/api/v1/ssgs/"+url.PathEscape(name), &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) getJSON(ctx context.Context, path string, dst any) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	u := *c.base
	u.Path = path

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpC.Do(req)
	if err != nil {
		return fmt.Errorf("get %s: %w", path, err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusNotFound:
		return ErrNotFound
	case resp.StatusCode >= 400:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("logparser: unexpected status %d: %s", resp.StatusCode, string(body))
	}

	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}
