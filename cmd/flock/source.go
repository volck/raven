package main

import (
	"context"

	"github.com/volck/raven/internal/flock"
	lpclient "github.com/volck/raven/internal/flock/logparser"
)

// logparserSource adapts the logparser HTTP client to flock.Source.
//
// On each Load it lists the engines, then fetches the per-engine targets in
// sequence. Failures on individual engines drop the engine from the
// resulting Snapshot rather than failing the whole Load — partial state is
// preferable to a hard outage while one cluster is unreachable.
type logparserSource struct {
	client *lpclient.Client
}

func newLogparserSource(client *lpclient.Client) *logparserSource {
	return &logparserSource{client: client}
}

func (s *logparserSource) Load(ctx context.Context) (flock.Snapshot, error) {
	engines, err := s.client.ListSSGs(ctx)
	if err != nil {
		return flock.Snapshot{}, err
	}
	routing := make(map[string][]string, len(engines))
	for _, eng := range engines {
		targets, err := s.client.GetSSG(ctx, eng)
		if err != nil {
			// Drop this engine from the snapshot, but keep going. The
			// caller still sees an authoritative engine list.
			continue
		}
		routing[eng] = targets
	}
	return flock.Snapshot{Engines: engines, Routing: routing}, nil
}
