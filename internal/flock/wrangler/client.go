// Package wrangler polls flock-wrangler for recent raven rollouts.
package wrangler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"
)

const (
	rolloutsPath = "/api/v1/rollouts"
	maxBody      = 4 << 20
)

// Stage is one step of a provisioning attempt.
type Stage struct {
	Stage  string `json:"stage"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// Rollout is one provisioning attempt as wrangler reported it.
type Rollout struct {
	Time      time.Time `json:"time"`
	Raven     string    `json:"raven"`
	Namespace string    `json:"namespace"`
	Engine    string    `json:"engine"`
	Actor     string    `json:"actor"`
	Branch    string    `json:"branch,omitempty"`
	Succeeded bool      `json:"succeeded"`
	Error     string    `json:"error,omitempty"`
	Stages    []Stage   `json:"stages"`
}

type Client struct {
	base    *url.URL
	httpC   *http.Client
	logger  *slog.Logger
	timeout time.Duration
}

type Option func(*Client) Option

func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) Option {
		previous := c.httpC
		c.httpC = h
		return WithHTTPClient(previous)
	}
}

func WithLogger(l *slog.Logger) Option {
	return func(c *Client) Option {
		previous := c.logger
		c.logger = l
		return WithLogger(previous)
	}
}

func WithRequestTimeout(d time.Duration) Option {
	return func(c *Client) Option {
		previous := c.timeout
		c.timeout = d
		return WithRequestTimeout(previous)
	}
}

func New(baseURL string, opts ...Option) (*Client, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse wrangler url %q: %w", baseURL, err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("wrangler url %q: needs a scheme and host", baseURL)
	}

	c := &Client{
		base:    parsed,
		httpC:   &http.Client{Timeout: 10 * time.Second},
		logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		timeout: 10 * time.Second,
	}
	c.Option(opts...)
	return c, nil
}

func (c *Client) Option(opts ...Option) (previous Option) {
	for _, opt := range opts {
		previous = opt(c)
	}
	return previous
}

func (c *Client) Rollouts(ctx context.Context) ([]Rollout, error) {
	if c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}

	endpoint := *c.base
	endpoint.Path = rolloutsPath

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpC.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get rollouts: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusBadRequest {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
		return nil, fmt.Errorf("get rollouts: %d: %s", resp.StatusCode, snippet)
	}

	var body struct {
		Rollouts []Rollout `json:"rollouts"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode rollouts: %w", err)
	}
	return body.Rollouts, nil
}
