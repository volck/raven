// Package argocd provides a thin HTTP client for triggering ArgoCD
// Application refresh/sync operations from Raven.
//
// Authentication uses an ArgoCD API JWT supplied via env. In Raven's topology
// there is one Deployment per (Vault engine, namespace); each Deployment
// mounts its own K8s Secret into ARGOCD_AUTH_TOKEN, giving us per-engine JWT
// mapping without a central config table.
package argocd

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/volck/raven/internal/helpers"
)

var jsonLogger = helpers.JsonLogger

// Client talks to the ArgoCD REST API.
type Client struct {
	Server string // e.g. https://argocd.example.com
	Token  string // Bearer JWT
	Enable bool   // master on/off switch
	HTTP   *http.Client
}

// NewClient constructs a Client from environment variables:
//
//	ARGOCD_SERVER        base URL (no trailing slash)
//	ARGOCD_AUTH_TOKEN    bearer token (JWT)
//	ARGOCD_SYNC_ENABLED  "true" to enable the feature
func NewClient() *Client {
	return &Client{
		Server: strings.TrimRight(os.Getenv("ARGOCD_SERVER"), "/"),
		Token:  os.Getenv("ARGOCD_AUTH_TOKEN"),
		Enable: strings.EqualFold(os.Getenv("ARGOCD_SYNC_ENABLED"), "true"),
		HTTP:   &http.Client{Timeout: 30 * time.Second},
	}
}

// Enabled reports whether the client is configured and feature-enabled.
func (c *Client) Enabled() bool {
	if c == nil {
		return false
	}
	return c.Enable && c.Server != "" && c.Token != ""
}

// RefreshAndSync performs a hard refresh followed by a sync on the named
// ArgoCD Application. It is a no-op when the client is not Enabled().
func (c *Client) RefreshAndSync(ctx context.Context, appName string) error {
	if !c.Enabled() {
		return nil
	}
	if appName == "" {
		return fmt.Errorf("argocd: empty appName")
	}
	if err := c.doRefresh(ctx, appName); err != nil {
		return err
	}
	return c.doSync(ctx, appName)
}

func (c *Client) doRefresh(ctx context.Context, appName string) error {
	u := fmt.Sprintf("%s/api/v1/applications/%s?refresh=hard", c.Server, url.PathEscape(appName))
	return c.call(ctx, http.MethodGet, u, "refresh", appName)
}

func (c *Client) doSync(ctx context.Context, appName string) error {
	u := fmt.Sprintf("%s/api/v1/applications/%s/sync", c.Server, url.PathEscape(appName))
	return c.call(ctx, http.MethodPost, u, "sync", appName)
}

func (c *Client) call(ctx context.Context, method, u, op, appName string) error {
	body := io.Reader(nil)
	if method == http.MethodPost {
		body = strings.NewReader(`{}`)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return fmt.Errorf("argocd %s %s: build request: %w", op, appName, err)
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}

	httpC := c.HTTP
	if httpC == nil {
		httpC = http.DefaultClient
	}
	resp, err := httpC.Do(req)
	if err != nil {
		return fmt.Errorf("argocd %s %s: %w", op, appName, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		jsonLogger.Error("argocd call failed",
			"op", op, "app", appName, "status", resp.StatusCode, "body", string(b))
		return fmt.Errorf("argocd %s %s: status %d: %s", op, appName, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	jsonLogger.Info("argocd call ok", "op", op, "app", appName, "status", resp.StatusCode)
	return nil
}
