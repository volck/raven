package main

import "strings"

const (
	statusPending    = "pending"
	statusDone       = "done"
	statusSkipped    = "skipped"
	statusFailed     = "failed"
	statusRolledBack = "rolled back"
)

const redacted = "[REDACTED]"

type stageResult struct {
	Stage  string `json:"stage"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// progress records how far provisioning got. Every stage is listed from the
// start so a truncated run still reports the ones it never reached.
type progress struct {
	stages  []stageResult
	secrets []string
}

func newProgress(stages ...string) *progress {
	p := &progress{stages: make([]stageResult, 0, len(stages))}
	for _, stage := range stages {
		p.stages = append(p.stages, stageResult{Stage: stage, Status: statusPending})
	}
	return p
}

// redact registers a value that must never appear in a stage detail, which is
// served to flock and returned to the caller.
func (p *progress) redact(secret string) {
	if secret != "" {
		p.secrets = append(p.secrets, secret)
	}
}

func (p *progress) scrub(detail string) string {
	for _, secret := range p.secrets {
		detail = strings.ReplaceAll(detail, secret, redacted)
	}
	return detail
}

func (p *progress) set(stage, status string, detail string) {
	for i := range p.stages {
		if p.stages[i].Stage == stage {
			p.stages[i].Status = status
			p.stages[i].Detail = p.scrub(detail)
			return
		}
	}
}

func (p *progress) statusOf(stage string) string {
	for _, s := range p.stages {
		if s.Stage == stage {
			return s.Status
		}
	}
	return statusPending
}

func (p *progress) results() []stageResult {
	return p.stages
}

// orphanedToken reports a freshly minted credential that no raven is using.
func (p *progress) orphanedToken() bool {
	return p.statusOf(stageVault) == statusDone && p.statusOf(stageCluster) != statusDone
}

// summary renders the report for a log line.
func (p *progress) summary() string {
	out := ""
	for i, s := range p.stages {
		if i > 0 {
			out += ","
		}
		out += s.Stage + "=" + s.Status
	}
	return out
}
