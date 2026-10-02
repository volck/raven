package main

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/volck/raven/internal/auditlog"
	"github.com/volck/raven/internal/provision"
)

type captureRoutingPublisher struct {
	files []provision.File
	err   error
}

func (p *captureRoutingPublisher) Publish(_ context.Context, spec provision.RavenSpec, files []provision.File) (string, error) {
	p.files = files
	if p.err != nil {
		return "", p.err
	}
	return provision.BranchName(spec), nil
}

func TestProvisionRaven_PublishesRoutingFile(t *testing.T) {
	t.Parallel()
	deps, _, _, _ := newTestDeps()
	routing := &captureRoutingPublisher{}
	deps.routingPublisher = routing

	spec := wranglerSpec()
	_, report, err := provisionRaven(context.Background(), deps, spec, false)
	if err != nil {
		t.Fatalf("provisionRaven: %v", err)
	}
	if report.statusOf(stageRouting) != statusDone {
		t.Fatalf("routing stage = %q", report.statusOf(stageRouting))
	}
	if len(routing.files) != 1 || routing.files[0].Name != "routes/ssg-dev.json" {
		t.Fatalf("routing files = %+v", routing.files)
	}
	var cfg auditlog.RoutingConfig
	if err := json.Unmarshal(routing.files[0].Data, &cfg); err != nil {
		t.Fatalf("decode routing file: %v", err)
	}
	if got := cfg.Routing["kv"]; len(got) != 1 || got[0] != "https://ssg-dev-ssg.apps.example.com" {
		t.Fatalf("routing target = %v", got)
	}
}

func TestProvisionRaven_RoutingFailureStopsArgoPublication(t *testing.T) {
	t.Parallel()
	deps, _, _, publisher := newTestDeps()
	deps.routingPublisher = &captureRoutingPublisher{err: fmt.Errorf("routing branch: %w", provision.ErrBranchExists)}

	_, report, err := provisionRaven(context.Background(), deps, wranglerSpec(), false)
	if err == nil {
		t.Fatal("routing publication failure was ignored")
	}
	if report.statusOf(stageRouting) != statusFailed {
		t.Fatalf("routing stage = %q, want failed", report.statusOf(stageRouting))
	}
	if publisher.callCount() != 0 {
		t.Fatalf("Argo publisher calls = %d, want 0", publisher.callCount())
	}
}
