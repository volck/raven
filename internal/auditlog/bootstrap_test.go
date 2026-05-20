package auditlog

import (
	"strings"
	"testing"
)

func TestValidateBootstrap(t *testing.T) {
	t.Parallel()

	valid := BootstrapConfig{
		AuditLogPath: "/var/log/vault/audit.log",
		HTTPAddr:     "127.0.0.1:8080",
		Git: GitSourceConfig{
			URL:          "git@example.com:org/repo.git",
			Branch:       "main",
			Path:         "logparser/routing.yaml",
			PollInterval: "30s",
		},
	}

	tests := []struct {
		name    string
		mutate  func(*BootstrapConfig)
		wantErr string
	}{
		{name: "valid", mutate: func(c *BootstrapConfig) {}},
		{
			name:    "missing audit_log_path",
			mutate:  func(c *BootstrapConfig) { c.AuditLogPath = "" },
			wantErr: "audit_log_path",
		},
		{
			name:    "missing git url",
			mutate:  func(c *BootstrapConfig) { c.Git.URL = "" },
			wantErr: "git.url",
		},
		{
			name:    "missing git branch",
			mutate:  func(c *BootstrapConfig) { c.Git.Branch = "" },
			wantErr: "git.branch",
		},
		{
			name:    "missing git path",
			mutate:  func(c *BootstrapConfig) { c.Git.Path = "" },
			wantErr: "git.path",
		},
		{
			name:    "invalid poll_interval",
			mutate:  func(c *BootstrapConfig) { c.Git.PollInterval = "not-a-duration" },
			wantErr: "git.poll_interval",
		},
		{
			name:    "zero poll_interval rejected",
			mutate:  func(c *BootstrapConfig) { c.Git.PollInterval = "0s" },
			wantErr: "git.poll_interval",
		},
		{
			name:    "negative poll_interval rejected",
			mutate:  func(c *BootstrapConfig) { c.Git.PollInterval = "-1s" },
			wantErr: "git.poll_interval",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := valid
			tt.mutate(&cfg)
			err := ValidateBootstrap(cfg)
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("expected nil error, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got: %v", tt.wantErr, err)
			}
		})
	}
}
