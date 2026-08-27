package raven

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// PipelineStage mirrors raven's internal/api.PipelineStage.
type PipelineStage struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Time   string `json:"time,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// PipelineEntry mirrors raven's internal/api.PipelineEntry.
type PipelineEntry struct {
	Secret       string          `json:"secret"`
	Stages       []PipelineStage `json:"stages"`
	K8sCreated   string          `json:"k8s_created,omitempty"`
	K8sModified  string          `json:"k8s_modified,omitempty"`
	Source       string          `json:"source,omitempty"`
	DataKeys     []string        `json:"data_keys,omitempty"`
	Deployments  []string        `json:"deployments,omitempty"`
	StatefulSets []string        `json:"statefulsets,omitempty"`
	Namespace    string          `json:"namespace,omitempty"`
	Engine       string          `json:"engine,omitempty"`
}

// Pipeline GETs baseURL+"/api/v1/pipeline" and decodes the per-secret
// lifecycle payload. Non-2xx responses return an error.
func (c *Client) Pipeline(ctx context.Context, baseURL string) ([]PipelineEntry, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse base url: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("base url must include scheme and host: %q", baseURL)
	}
	u.Path = "/api/v1/pipeline"

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	resp, err := c.httpC.Do(req)
	if err != nil {
		return nil, fmt.Errorf("pipeline %s: %w", baseURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("pipeline %s: status %d", baseURL, resp.StatusCode)
	}
	body := io.LimitReader(resp.Body, 32<<20) // 32 MiB cap; pipelines can be large
	var out []PipelineEntry
	if err := json.NewDecoder(body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode pipeline: %w", err)
	}
	return out, nil
}
