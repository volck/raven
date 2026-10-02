package wrangler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// ErrNotFound reports that wrangler manages no raven by that name.
var ErrNotFound = errors.New("not found")

// DeploymentCondition is one Kubernetes Deployment condition.
type DeploymentCondition struct {
	Type    string `json:"type"`
	Status  string `json:"status"`
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

// PodStatus is why a raven's pod is or is not running.
type PodStatus struct {
	Name     string `json:"name"`
	Phase    string `json:"phase"`
	Ready    bool   `json:"ready"`
	Restarts int32  `json:"restarts"`
	Reason   string `json:"reason,omitempty"`
	Message  string `json:"message,omitempty"`
}

// Deployment is the live workload state wrangler reports for one raven.
type Deployment struct {
	Name       string                `json:"name"`
	Namespace  string                `json:"namespace"`
	Engine     string                `json:"engine,omitempty"`
	Desired    int32                 `json:"desired"`
	Ready      int32                 `json:"ready"`
	Available  int32                 `json:"available"`
	Updated    int32                 `json:"updated"`
	Conditions []DeploymentCondition `json:"conditions"`
	Pods       []PodStatus           `json:"pods"`
}

func (c *Client) Deployment(ctx context.Context, name string) (*Deployment, error) {
	if c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}

	endpoint := *c.base
	endpoint.Path = "/api/v1/ravens/" + name + "/deployment"
	endpoint.RawPath = "/api/v1/ravens/" + url.PathEscape(name) + "/deployment"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpC.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get deployment %s: %w", name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("get deployment %s: %w", name, ErrNotFound)
	}
	if resp.StatusCode >= http.StatusBadRequest {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
		return nil, fmt.Errorf("get deployment %s: %d: %s", name, resp.StatusCode, snippet)
	}

	var out Deployment
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode deployment %s: %w", name, err)
	}
	return &out, nil
}
